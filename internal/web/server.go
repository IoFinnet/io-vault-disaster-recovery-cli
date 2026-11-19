// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"archive/zip"
	"bytes"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/bittensor"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/fileutils"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/hd"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/solana"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/wif"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/xrpl"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ziputils"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

//go:embed static
var staticFiles embed.FS

const (
	tempDirPrefix   = "vault-recovery-web-"
	exportDirPrefix = "vault-recovery-web-export-"
)

// ServerConfig holds the configuration for the http server
type ServerConfig struct {
	Port int
}

// HDAddressResult represents a derived HD address for the frontend
type HDAddressResult struct {
	Address    string `json:"address"`
	Path       string `json:"path"`
	Algorithm  string `json:"algorithm"`
	Curve      string `json:"curve"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
	WIF        string `json:"wif,omitempty"`
}

// RecoveryResult stores the recovery data to be sent to the frontend
type RecoveryResult struct {
	Success          bool              `json:"success"`
	ErrorMessage     string            `json:"errorMessage,omitempty"`
	Address          string            `json:"address,omitempty"`
	EcdsaPrivateKey  string            `json:"ecdsaPrivateKey,omitempty"`
	TestnetWIF       string            `json:"testnetWIF,omitempty"`
	MainnetWIF       string            `json:"mainnetWIF,omitempty"`
	EddsaPrivateKey  string            `json:"eddsaPrivateKey,omitempty"`
	EddsaPublicKey   string            `json:"eddsaPublicKey,omitempty"`
	XRPLAddress      string            `json:"xrplAddress,omitempty"`
	BittensorAddress string            `json:"bittensorAddress,omitempty"`
	SolanaAddress    string            `json:"solanaAddress,omitempty"`
	ExportedKsFile   string            `json:"exportedKsFile,omitempty"`
	HDAddresses      []HDAddressResult `json:"hdAddresses,omitempty"`
	HDError          string            `json:"hdError,omitempty"`

	// Which reshare and threshold the keys were rebuilt from. Identifiers only. RequestID is the
	// reshare request id, or the reshare nonce for a legacy flat-nonce export.
	// NetworkBlocked is set when recovery was refused because this computer is online.
	NetworkBlocked bool `json:"networkBlocked,omitempty"`

	RequestID  string `json:"requestId,omitempty"`
	Threshold  int    `json:"threshold,omitempty"`
	SharesUsed int    `json:"sharesUsed,omitempty"`
}

// Server represents the http server for the disaster recovery tool
type Server struct {
	config  ServerConfig
	tempDir string
	// exportDir is never cleaned up on server shutdown, because it stores files the users can download and use later.
	exportDir          string
	server             *http.Server
	listener           net.Listener
	actualPort         int // the port the server actually bound to
	zipExtractedDirsMu sync.Mutex
	zipExtractedDirs   map[string]struct{}  // ZIP extraction dirs not yet cleaned up; handlers run concurrently, so guard with zipExtractedDirsMu
	checkNetwork       func() NetworkStatus // nil: read the real adapters; tests supply a fixed status
}

// NewServer creates a new http server instance
func NewServer(config ServerConfig) (*Server, error) {
	// Create a temporary directory to store uploaded files
	tempDir, err := os.MkdirTemp("", tempDirPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %w", err)
	}

	return &Server{
		config:           config,
		tempDir:          tempDir,
		exportDir:        workingDir,
		zipExtractedDirs: make(map[string]struct{}),
	}, nil
}

// Start starts the http server
func (s *Server) Start() (string, error) {
	// Create a new mux for our server
	mux := http.NewServeMux()

	// Define static file handler for embedded files
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFiles.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "Error reading index.html", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write(data)
	})

	// Handle static assets
	mux.HandleFunc("GET /static/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		data, err := staticFiles.ReadFile(path)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		// Set the content type based on file extension
		ext := filepath.Ext(path)
		contentType := "application/octet-stream"
		switch ext {
		case ".css":
			contentType = "text/css"
		case ".js":
			contentType = "application/javascript"
		case ".png":
			contentType = "image/png"
		case ".jpg", ".jpeg":
			contentType = "image/jpeg"
		case ".svg":
			contentType = "image/svg+xml"
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(data)
	})

	// API endpoint for vault recovery
	mux.HandleFunc("POST /api/recover", s.handleRecovery)

	// API endpoint for listing vaults
	mux.HandleFunc("POST /api/list-vaults", s.handleListVaults)

	// API endpoint to list files in a ZIP archive
	mux.HandleFunc("POST /api/list-zip-files", s.handleListZipFiles)

	// API endpoint to verify backup coverage without reconstructing any key
	mux.HandleFunc("POST /api/verify", s.handleVerify)

	// API endpoint for the offline indicator: which local network adapters are active
	mux.HandleFunc("POST /api/network-status", s.handleNetworkStatus)

	// No validation endpoints needed

	// Find an available port
	port := s.config.Port
	if port == 0 {
		port = 8080 // default port
	}

	// Try to listen on the selected port
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		// If the port is in use, try to find an available one
		if port == 8080 {
			// Try ports 8081-8090
			for tryPort := 8081; tryPort <= 8090; tryPort++ {
				listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tryPort))
				if err == nil {
					port = tryPort
					break
				}
			}
		}
		if err != nil {
			return "", fmt.Errorf("failed to start server: %w", err)
		}
	}
	s.listener = listener
	s.actualPort = port

	// Apply security middleware: origin validation wraps the mux,
	// then security headers wrap everything.
	handler := securityHeaders(validateOrigin(mux, port))

	// Create the server
	s.server = &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Start the server in a goroutine
	go func() {
		log.Printf("Starting http server on http://localhost:%d", port)
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
		}
	}()

	return fmt.Sprintf("http://localhost:%d", port), nil
}

// Stop stops the http server and cleans up resources
func (s *Server) Stop() error {
	// Close the server
	if s.server != nil {
		if err := s.server.Close(); err != nil {
			return err
		}
	}

	// Clean up any ZIP extracted directories left over from requests
	s.zipExtractedDirsMu.Lock()
	dirs := make([]string, 0, len(s.zipExtractedDirs))
	for dir := range s.zipExtractedDirs {
		dirs = append(dirs, dir)
	}
	s.zipExtractedDirsMu.Unlock()
	for _, dir := range dirs {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("warning: failed to clean up temporary directory %s: %v", dir, err)
		}
	}

	// Clean up temporary files
	if s.tempDir != "" {
		if err := os.RemoveAll(s.tempDir); err != nil {
			return err
		}
	}

	return nil
}

// handleListVaults handles the request to list vaults from uploaded files
func (s *Server) handleListVaults(w http.ResponseWriter, r *http.Request) {
	// Parse the multipart form data
	err := r.ParseMultipartForm(10 << 20) // 10 MB max size
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	// Process files and mnemonics
	vaultsDataFiles, reqCleanup, err := s.processFilesAndMnemonics(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to process files: %v", err), http.StatusBadRequest)
		return
	}
	defer reqCleanup()
	defer vaultsDataFiles.Zeroize()

	// If no vault data files were processed, return an error
	if len(vaultsDataFiles) == 0 {
		http.Error(w, "No valid vault data files provided", http.StatusBadRequest)
		return
	}

	// Read the ML-KEM-768 private key PEM, if supplied, needed to decrypt any .dr inputs.
	privateKeysPEM, err := readPrivateKeysPEM(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read private key: %v", err), http.StatusBadRequest)
		return
	}
	defer clearKeys(privateKeysPEM)

	// Run the tool to get vault information
	_, _, _, vaultsFormInfo, _, err := runTool(vaultsDataFiles, "", 0, false, "", 0, "", "", privateKeysPEM, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to retrieve vault information: %v", err), http.StatusInternalServerError)
		return
	}

	// Marshal the vault information to JSON and return it
	response, err := json.Marshal(vaultsFormInfo)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to marshal response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// handleRecovery handles the recovery API endpoint
func (s *Server) handleRecovery(w http.ResponseWriter, r *http.Request) {
	// Parse the multipart form data
	err := r.ParseMultipartForm(10 << 20) // 10 MB max size
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	// Get vault ID from form
	vaultID := r.FormValue("vaultId")
	if vaultID == "" {
		http.Error(w, "Vault ID is required", http.StatusBadRequest)
		return
	}

	// Recovery rebuilds a full private key, so it refuses to run while this computer has an active
	// network adapter, unless the user explicitly confirmed it in the UI (for example a disposable
	// VM whose virtual adapter has no internet route). The UI enforces the same rule; this is the
	// server-side backstop. This first check saves the upload work when the computer is already
	// connected; a second one runs just before the key is rebuilt.
	allowConnected := r.FormValue("allowConnected") == "true"
	if s.refuseWhileConnected(w, allowConnected) {
		return
	}

	// Get optional parameters
	nonceOverride := 0
	nonceOverrideProvided := false
	if nonceOverrideStr := r.FormValue("nonceOverride"); nonceOverrideStr != "" {
		nonceOverrideProvided = true
		fmt.Sscanf(nonceOverrideStr, "%d", &nonceOverride)
	}
	nonceOverrideSet := nonceOverrideProvided && nonceOverride > -1

	requestIDOverride := r.FormValue("requestIdOverride")

	quorumOverride := 0
	if quorumOverrideStr := r.FormValue("quorumOverride"); quorumOverrideStr != "" {
		fmt.Sscanf(quorumOverrideStr, "%d", &quorumOverride)
	}

	passwordForKS := r.FormValue("password")

	exportKSFile := r.FormValue("exportFile")
	if exportKSFile != "" && passwordForKS == "" {
		http.Error(w, "Password is required when exporting keystore file", http.StatusBadRequest)
		return
	}
	exportFile := ""
	if exportKSFile != "" {
		scopedPath, err := ui.ScopeExportPathForWeb(exportKSFile, s.exportDir)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid export filename: %v", err), http.StatusBadRequest)
			return
		}
		exportFile = scopedPath
	}

	// Process files and mnemonics
	vaultsDataFiles, reqCleanup, err := s.processFilesAndMnemonics(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to process files: %v", err), http.StatusBadRequest)
		return
	}
	defer reqCleanup()
	defer vaultsDataFiles.Zeroize()

	// Read the ML-KEM-768 private key PEM, if supplied, needed to decrypt any .dr inputs.
	privateKeysPEM, err := readPrivateKeysPEM(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read private key: %v", err), http.StatusBadRequest)
		return
	}
	defer clearKeys(privateKeysPEM)

	// The computer may connect while the uploads are saved and the shares decrypted, so the check
	// runs again inside runTool: after decryption and immediately before the key is rebuilt.
	var connectedBeforeReconstruct *NetworkStatus
	beforeReconstruct := func() error {
		if allowConnected {
			return nil
		}
		if status := s.networkStatus(); status.Connected {
			connectedBeforeReconstruct = &status
			return errConnectedBeforeReconstruct
		}
		return nil
	}

	// Run the recovery tool
	result := RecoveryResult{}
	address, ecSK, edSK, orderedVaults, exportedKsFile, err := runTool(vaultsDataFiles, vaultID, nonceOverride, nonceOverrideSet, requestIDOverride, quorumOverride, exportFile, passwordForKS, privateKeysPEM, beforeReconstruct)
	if connectedBeforeReconstruct != nil {
		writeNetworkBlocked(w, *connectedBeforeReconstruct)
		return
	}
	if err == nil {
		// In recovery mode the pipeline only processes the selected vault, so its entry records the
		// reshare the shares came from and how many were used.
		for _, v := range orderedVaults {
			if v.VaultID != vaultID {
				continue
			}
			result.RequestID = v.LastRequestID
			result.SharesUsed = v.NumberOfShares
			result.Threshold = v.Quorum
			if quorumOverride > 0 {
				result.Threshold = quorumOverride
			}
		}
	}

	if err != nil {
		result.Success = false
		result.ErrorMessage = err.Error()
	} else {
		// Set up the result with all the recovered key information
		result.Success = true
		result.Address = address
		result.EcdsaPrivateKey = hex.EncodeToString(ecSK)
		result.TestnetWIF = wif.ToBitcoinWIF(ecSK, true, true)
		result.MainnetWIF = wif.ToBitcoinWIF(ecSK, false, true)

		if edSK != nil {
			result.EddsaPrivateKey = hex.EncodeToString(edSK)
			log.Printf("EdDSA Private Key present: %d bytes", len(edSK))

			// Get the EdDSA public key
			_, edPK, err := edwards.PrivKeyFromScalar(edSK)
			if err == nil {
				edPKC := edPK.SerializeCompressed()
				result.EddsaPublicKey = hex.EncodeToString(edPKC)
				log.Printf("EdDSA Public Key: %s", result.EddsaPublicKey)

				// Generate XRPL address
				xrplAddress, err := xrpl.DeriveXRPLAddress(edPKC)
				if err == nil {
					result.XRPLAddress = xrplAddress
					log.Printf("XRPL Address: %s", result.XRPLAddress)
				} else {
					log.Printf("Error deriving XRPL address: %v", err)
				}

				// Generate Bittensor address
				bittensorAddress, err := bittensor.GenerateSS58Address(edPKC)
				if err == nil {
					result.BittensorAddress = bittensorAddress
					log.Printf("Bittensor Address: %s", result.BittensorAddress)
				} else {
					log.Printf("Error deriving Bittensor address: %v", err)
				}

				// Generate Solana address
				solanaAddress, err := solana.DeriveSolanaAddress(edPKC)
				if err == nil {
					result.SolanaAddress = solanaAddress
					log.Printf("Solana Address: %s", result.SolanaAddress)
				} else {
					log.Printf("Error deriving Solana address: %v", err)
				}
			} else {
				log.Printf("Error getting EdDSA public key: %v", err)
			}
		} else {
			log.Printf("No EdDSA private key present for vault `%s`", vaultID)
		}

		if exportedKsFile != nil {
			result.ExportedKsFile = *exportedKsFile
			log.Printf("Wallet v3 file exported to: %s", ui.PlainText(*exportedKsFile))
		}

		// Process HD addresses if CSV file was provided (must be done before clearing keys)
		hdAddresses, hdErr := s.processHDAddresses(r, ecSK, edSK)
		if hdErr != nil {
			// Log the error but don't fail the entire recovery
			log.Printf("HD address derivation error: %v", hdErr)
			result.HDError = hdErr.Error()
		} else if len(hdAddresses) > 0 {
			result.HDAddresses = hdAddresses
			log.Printf("Derived %d HD addresses", len(hdAddresses))
		}

		// Clear sensitive data again to be safe
		clear(ecSK)
		clear(edSK)
	}

	// Return the result as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
}

// refuseWhileConnected writes the networkBlocked recovery result and returns true when this
// computer is connected and the request did not confirm recovering anyway. No key is rebuilt for a
// refused request.
func (s *Server) refuseWhileConnected(w http.ResponseWriter, allowConnected bool) bool {
	status := s.networkStatus()
	if !status.Connected || allowConnected {
		return false
	}
	writeNetworkBlocked(w, status)
	return true
}

// errConnectedBeforeReconstruct stops runTool before any key is rebuilt when the computer connected
// to a network after the request's first check.
var errConnectedBeforeReconstruct = errors.New("computer connected to a network before the key was rebuilt")

// writeNetworkBlocked writes the recovery result that refuses to rebuild a key on a connected
// computer, naming the active adapters.
func writeNetworkBlocked(w http.ResponseWriter, status NetworkStatus) {
	names := make([]string, 0, len(status.Adapters))
	for _, a := range status.Adapters {
		names = append(names, a.Name)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(RecoveryResult{
		NetworkBlocked: true,
		ErrorMessage: fmt.Sprintf("This computer is connected to a network (%s). Disconnect it before you recover, "+
			"or confirm that you want to recover anyway.", strings.Join(names, ", ")),
	})
}

// readPrivateKeysPEM extracts the ML-KEM-768 private key PEMs needed to decrypt any Virtual Signer
// .dr inputs from the request: every uploaded "privateKeyFile" part (one per Virtual Signer), plus
// pasted PEM text in the "privateKey" field. The pipeline tries each key against each .dr file.
// Returns nil, nil when none is supplied, which is fine for inputs that are only mobile/legacy JSON.
func readPrivateKeysPEM(r *http.Request) ([][]byte, error) {
	var keys [][]byte
	if r.MultipartForm != nil {
		for _, fileHeader := range r.MultipartForm.File["privateKeyFile"] {
			data, err := readMultipartFile(fileHeader)
			if err != nil {
				clearKeys(keys)
				return nil, fmt.Errorf("failed to read private key file %s: %w", filepath.Base(fileHeader.Filename), err)
			}
			if len(bytes.TrimSpace(data)) == 0 {
				continue
			}
			keys = append(keys, data)
		}
	}
	if pem := r.FormValue("privateKey"); strings.TrimSpace(pem) != "" {
		keys = append(keys, []byte(pem))
	}
	if len(keys) == 0 {
		return nil, nil
	}
	return keys, nil
}

func readMultipartFile(fileHeader *multipart.FileHeader) ([]byte, error) {
	file, err := fileHeader.Open()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

// clearKeys zeroes every private key once the request is done with it. This is best effort for a
// pasted key: FormValue hands back an immutable string, so the copy taken above is what gets
// cleared and the form's own string survives until it is collected.
func clearKeys(keys [][]byte) {
	for _, k := range keys {
		clear(k)
	}
}

// uploadedFile records how a pipeline input reached the server, so a response can name it the way
// the user uploaded it rather than by its temp path.
type uploadedFile struct {
	name    string // base name as uploaded, or the entry name for a file extracted from a ZIP
	fromZip bool   // extracted from a legacy (non-bundle) ZIP archive of exports
}

// uploadFailure is an uploaded file that could not be read at all, such as a damaged ZIP archive.
// Only verification collects these, to report them as that file's error.
type uploadFailure struct {
	name string // base name as uploaded
	err  string // why it could not be read, without temp paths
}

// processFilesAndMnemonics processes the uploaded files and their mnemonics for listing and
// recovery, where every JSON export needs its mnemonic. On success it also returns a cleanup func
// the caller must defer to remove this request's temp files; on error they are already removed and
// the cleanup func is a no-op.
func (s *Server) processFilesAndMnemonics(r *http.Request) (ui.VaultsDataFiles, func(), error) {
	files, _, _, reqCleanup, err := s.processUploadedFiles(r, false)
	return files, reqCleanup, err
}

// processUploadedFiles saves the request's "files" uploads into a per-request temp directory and
// pairs each JSON export with its mnemonic.
//
// A Virtual Signer bundle zip (one with a root manifest.json) is passed through whole, so the
// pipeline expands it with its manifest, as the CLI does. Any other zip is a legacy archive of
// exports and is extracted flat. A JSON file's mnemonic comes from the "mnemonic_<file name without
// extension>" field; for a directly uploaded JSON file the older unkeyed fields are still read, by
// upload position, when that field is absent.
//
// With mnemonicsOptional (verify), a JSON file with no mnemonic is kept with an empty one so it can
// be checked by its header, a supplied mnemonic is passed through unvalidated so a bad one shows up
// as that file's error, and a ZIP archive that cannot be opened is returned as an uploadFailure
// while the other uploads are still processed. Otherwise (list and recover) a JSON file without a
// mnemonic is skipped when it came from a zip and is an error when uploaded directly, and an
// unreadable ZIP fails the request, as before.
//
// On success it also returns how each input path was uploaded, any upload failures, and a cleanup
// func the caller must defer to remove this request's temp files; on error they are already
// removed and the cleanup func is a no-op.
func (s *Server) processUploadedFiles(r *http.Request, mnemonicsOptional bool) (
	ui.VaultsDataFiles, map[string]uploadedFile, []uploadFailure, func(), error) {
	if r.MultipartForm == nil || len(r.MultipartForm.File["files"]) == 0 {
		return nil, nil, nil, noopCleanup, fmt.Errorf("no files uploaded")
	}
	// Only the "files" field carries vault data files; other file fields (e.g. "privateKeyFile",
	// "hdAddressesCSV") carry unrelated data and must not be swept in here.
	fileHeaders := r.MultipartForm.File["files"]

	// Each request gets its own directory, so uploads are removed when the request ends and two
	// requests never overwrite each other's files.
	requestDir, err := os.MkdirTemp(s.tempDir, "request-")
	if err != nil {
		log.Printf("⚠ failed to create a request directory: %v", err)
		return nil, nil, nil, noopCleanup, fmt.Errorf("failed to create a temporary directory: %w", fileutils.StripPathFromError(err))
	}
	requestDirs := []string{requestDir}
	fail := func(err error) (ui.VaultsDataFiles, map[string]uploadedFile, []uploadFailure, func(), error) {
		for _, dir := range requestDirs {
			os.RemoveAll(dir)
		}
		return nil, nil, nil, noopCleanup, err
	}

	vaultsDataFiles := make([]ui.VaultsDataFile, 0, len(fileHeaders))
	uploads := make(map[string]uploadedFile, len(fileHeaders))
	var failures []uploadFailure
	seenNames := make(map[string]bool, len(fileHeaders))
	add := func(path, mnemonic string, upload uploadedFile) {
		vaultsDataFiles = append(vaultsDataFiles, ui.VaultsDataFile{File: path, Mnemonics: mnemonic})
		uploads[path] = upload
	}

	for i, fileHeader := range fileHeaders {
		name := filepath.Base(fileHeader.Filename)
		if name == "" || name == "." || name == string(filepath.Separator) {
			return fail(fmt.Errorf("an uploaded file has no name"))
		}
		// Case-insensitive: on Windows and macOS the second file would overwrite the first.
		if seenNames[strings.ToLower(name)] {
			return fail(fmt.Errorf("two uploaded files are named %s; rename one and try again", name))
		}
		seenNames[strings.ToLower(name)] = true

		filePath := filepath.Join(requestDir, name)
		if err := saveUploadedFile(fileHeader, filePath); err != nil {
			return fail(err)
		}

		switch {
		case ziputils.IsBundleZip(filePath):
			add(filePath, "", uploadedFile{name: name})

		case ziputils.IsZipFile(filePath):
			extractedFiles, err := ziputils.ProcessZipFile(filePath)
			// The uploaded ZIP is no longer needed after extraction, whether or not it succeeded.
			os.Remove(filePath)
			if err != nil {
				if mnemonicsOptional {
					// Verification reports a damaged archive as that file's error and still checks the
					// other uploads; listing and recovery need every file, so they stop here.
					failures = append(failures, uploadFailure{name: name, err: fileutils.StripPathFromError(err).Error()})
					continue
				}
				return fail(err)
			}
			if len(extractedFiles) > 0 {
				requestDirs = append(requestDirs, filepath.Dir(extractedFiles[0]))
			}
			for _, extractedFile := range extractedFiles {
				entryName := filepath.Base(extractedFile)
				upload := uploadedFile{name: entryName, fromZip: true}

				// Virtual Signer .dr files are decrypted with an ML-KEM-768 private key (see
				// readPrivateKeysPEM), not a per-file mnemonic.
				if isDRFileName(entryName) {
					add(extractedFile, "", upload)
					continue
				}

				mnemonic, supplied := keyedMnemonic(r, entryName)
				if mnemonicsOptional {
					add(extractedFile, mnemonic, upload)
					continue
				}
				if !supplied {
					log.Printf("⚠ skipping file %s - no mnemonic provided", entryName)
					fmt.Println(ui.PlainTextf("Skipping file %s - no mnemonic provided", entryName))
					continue
				}
				if err := ui.ValidateMnemonics(mnemonic); err != nil {
					return fail(fmt.Errorf("invalid mnemonic for signer %s: %w", strings.TrimSuffix(entryName, filepath.Ext(entryName)), err))
				}
				add(extractedFile, mnemonic, upload)
			}

		case isDRFileName(name):
			add(filePath, "", uploadedFile{name: name})

		default:
			mnemonic, supplied := keyedMnemonic(r, name)
			if mnemonicsOptional {
				add(filePath, mnemonic, uploadedFile{name: name})
				continue
			}
			if !supplied {
				// Older clients send unkeyed mnemonics in upload order.
				var ok bool
				if mnemonic, ok = positionalMnemonic(r, i); !ok {
					return fail(fmt.Errorf("no mnemonics provided for JSON file %s", name))
				}
			}
			if err := ui.ValidateMnemonics(mnemonic); err != nil {
				return fail(fmt.Errorf("invalid mnemonic for file %s: %w", name, err))
			}
			add(filePath, mnemonic, uploadedFile{name: name})
		}
	}

	// Ensure we have at least one vault data file to process. Verification with only unreadable
	// uploads still answers, so the user sees why each one failed.
	if len(vaultsDataFiles) == 0 && len(failures) == 0 {
		return fail(fmt.Errorf("no valid JSON files were uploaded (directly or in ZIP archives)"))
	}

	// Keep the dirs on the server too, as a fallback for Stop() in case the caller's deferred
	// cleanup below doesn't run (e.g. process killed mid-request).
	s.trackZipExtractedDirs(requestDirs)

	reqCleanup := func() { s.cleanupRequestDirs(requestDirs) }
	return vaultsDataFiles, uploads, failures, reqCleanup, nil
}

// saveUploadedFile writes one upload to dst, readable by the owner only.
func saveUploadedFile(fileHeader *multipart.FileHeader, dst string) error {
	in, err := fileHeader.Open()
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", filepath.Base(dst), err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileutils.PermissionOwnerRW)
	if err != nil {
		log.Printf("⚠ failed to create temporary file %s: %v", dst, err)
		return fmt.Errorf("failed to create temporary file %s: %w", filepath.Base(dst), fileutils.StripPathFromError(err))
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return fmt.Errorf("failed to copy file content: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return fmt.Errorf("failed to save file %s: %w", filepath.Base(dst), fileutils.StripPathFromError(err))
	}
	return nil
}

// keyedMnemonic returns the cleaned mnemonic sent for a JSON file under
// "mnemonic_<file name without extension>", and whether that field was sent at all. A field that
// was sent blank comes back as "" with supplied true.
func keyedMnemonic(r *http.Request, fileName string) (mnemonic string, supplied bool) {
	baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	values, ok := r.MultipartForm.Value["mnemonic_"+baseName]
	if !ok || len(values) == 0 {
		return "", false
	}
	return ui.CleanMnemonicInput(values[0]), true
}

// positionalMnemonic is the fallback for older clients that send unkeyed mnemonic fields: it
// takes the i-th one in upload order, or the first if there are fewer than i.
func positionalMnemonic(r *http.Request, i int) (string, bool) {
	var mnemonicValues []string
	for key, values := range r.MultipartForm.Value {
		if strings.Contains(key, "mnemonic") && !strings.Contains(key, "mnemonic_") {
			mnemonicValues = append(mnemonicValues, values...)
		}
	}

	// If we couldn't find mnemonic fields by name, try using all form values except known ones
	if len(mnemonicValues) == 0 {
		for key, values := range r.MultipartForm.Value {
			if key != "mode" && key != "vaultId" && !strings.HasPrefix(key, "mnemonic_") {
				mnemonicValues = append(mnemonicValues, values...)
			}
		}
	}
	if len(mnemonicValues) == 0 {
		return "", false
	}
	if i >= len(mnemonicValues) {
		i = 0 // Fall back to first mnemonic if not enough
	}
	return ui.CleanMnemonicInput(mnemonicValues[i]), true
}

func isDRFileName(name string) bool {
	return strings.EqualFold(filepath.Ext(name), ".dr")
}

// securityHeaders wraps an http.Handler to add security headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent the site from being loaded in an iframe. Removes clickjacking risks.
		w.Header().Set("X-Frame-Options", "DENY")
		// Prevent MIME type sniffing. Helps stop attacks where files might be served as the wrong content-type.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Restrict what resources this page can load and from where (only self for api, images and scripts. also inlined html styles).
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		// Only send referrer info for same-origin or top-level navigation. Limits leaking info to other sites.
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Forbid browser features like camera, microphone, geolocation on this site unless explicitly allowed.
		// Protects user privacy.
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// validateOrigin wraps an http.Handler to reject cross-origin POST and OPTIONS requests.
// Requests with no Origin header are allowed, because they are treated as same-origin or non-browser (e.g., curl), which are safe.
func validateOrigin(next http.Handler, port int) http.Handler {
	// The server always binds to localhost, so only allow requests from localhost or 127.0.0.1.
	// Making it configurable would risk weakening security through misconfiguration
	allowedOrigins := map[string]bool{
		fmt.Sprintf("http://localhost:%d", port): true,
		fmt.Sprintf("http://127.0.0.1:%d", port): true,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Methods that modify state (POST, PUT, DELETE, PATCH) are vulnerable to CSRF attacks.
		// Methods that don't modify state (GET, HEAD) are not vulnerable. Altough, OPTIONS is a special case.
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			origin := r.Header.Get("Origin")
			if origin != "" && !allowedOrigins[origin] {
				http.Error(w, "Forbidden: invalid origin", http.StatusForbidden)
				return
			}
		}

		// empty origin indicates a non-browser or non-CORS preflight request,
		// which should not be allowed because browsers use OPTIONS with Origin during CORS preflight. Allowing it could let cross-origin preflight requests to bypass origin checks.
		if r.Method == http.MethodOptions {
			origin := r.Header.Get("Origin")
			if origin == "" || !allowedOrigins[origin] {
				http.Error(w, "Forbidden: invalid origin", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// processHDAddresses processes an optional HD addresses CSV file and derives child keys
func (s *Server) processHDAddresses(r *http.Request, ecdsaSK, eddsaSK []byte) ([]HDAddressResult, error) {
	// Check if an HD CSV file was uploaded
	hdFiles := r.MultipartForm.File["hdAddressesCSV"]
	if len(hdFiles) == 0 {
		// No HD CSV file provided - this is not an error
		return nil, nil
	}

	// Process only the first HD CSV file
	fileHeader := hdFiles[0]

	// Open the uploaded file
	file, err := fileHeader.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open HD addresses CSV file: %w", err)
	}
	defer file.Close()

	// Parse the CSV
	records, err := hd.ParseCSVReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HD addresses CSV: %w", err)
	}

	if len(records) == 0 {
		return nil, nil
	}

	// Create the deriver with the master keys
	deriver, err := hd.NewDeriver(ecdsaSK, eddsaSK)
	if err != nil {
		return nil, fmt.Errorf("failed to create HD deriver: %w", err)
	}

	// Derive all keys
	derivedRecords, err := deriver.DeriveAll(records)
	if err != nil {
		return nil, fmt.Errorf("HD key derivation failed: %w", err)
	}

	// Convert to HDAddressResult for the frontend
	results := make([]HDAddressResult, len(derivedRecords))
	for i, rec := range derivedRecords {
		results[i] = HDAddressResult{
			Address:    rec.Address,
			Path:       rec.Path,
			Algorithm:  string(rec.Algorithm),
			Curve:      string(rec.Curve),
			PublicKey:  rec.PublicKey,
			PrivateKey: rec.PrivateKey,
			WIF:        rec.WIF,
		}
	}

	return results, nil
}

// OpenBrowser opens the URL in the default browser
func OpenBrowser(url string) error {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	return err
}

// Helper function to get map keys for debugging
func getMapKeys(m interface{}) []string {
	var keys []string

	switch v := m.(type) {
	case map[string][]string:
		for k := range v {
			keys = append(keys, k)
		}
	case map[string][]*multipart.FileHeader:
		for k := range v {
			keys = append(keys, k)
		}
	}

	return keys
}

// handleListZipFiles extracts JSON files from a ZIP and returns their filenames
func (s *Server) handleListZipFiles(w http.ResponseWriter, r *http.Request) {
	// Parse the multipart form data
	err := r.ParseMultipartForm(10 << 20) // 10 MB max size
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	// Get the ZIP files
	zipFiles := r.MultipartForm.File["zipFile"]
	if len(zipFiles) == 0 {
		http.Error(w, "No ZIP files provided", http.StatusBadRequest)
		return
	}

	// Track all extracted files
	allExtractedFiles := []string{}

	// Extracted dirs from this request; cleaned up on every return path below,
	// with a copy also kept on the server as a Stop() fallback.
	requestExtractedDirs := []string{}
	defer func() { s.cleanupRequestDirs(requestExtractedDirs) }()

	onZipFileProcessingFinished := func(file *multipart.File, outFile *os.File, filePath *string) {
		if file != nil {
			(*file).Close()
		}
		if outFile != nil {
			(*outFile).Close()
		}
		if filePath != nil {
			os.Remove(*filePath)
		}
	}

	// Process each ZIP file
	for _, fileHeader := range zipFiles {
		// Open the uploaded file
		file, err := fileHeader.Open()
		if err != nil {
			onZipFileProcessingFinished(&file, nil, nil)
			http.Error(w, fmt.Sprintf("Failed to open file %s: %v", fileHeader.Filename, err), http.StatusBadRequest)
			return
		}

		// Create a file in the temp directory
		filePath := filepath.Join(s.tempDir, fileHeader.Filename)
		outFile, err := os.Create(filePath)
		if err != nil {
			onZipFileProcessingFinished(&file, outFile, &filePath)
			log.Printf("Failed to create temporary file %s: %v", filePath, err)
			http.Error(w, "Failed to create temporary file", http.StatusInternalServerError)
			return
		}
		log.Printf("created temporary file %s", filePath)

		// Copy the file content
		if _, err := io.Copy(outFile, file); err != nil {
			onZipFileProcessingFinished(&file, outFile, &filePath)
			http.Error(w, fmt.Sprintf("Failed to copy file content: %v", err), http.StatusInternalServerError)
			return
		}

		// A Virtual Signer bundle is listed, not extracted: its manifest.json is not a backup file,
		// and its .dr files need a key, not a mnemonic.
		if ziputils.IsBundleZip(filePath) {
			names, err := bundleDRNames(filePath)
			onZipFileProcessingFinished(&file, outFile, &filePath)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to process ZIP file %s: %v", fileHeader.Filename, err), http.StatusBadRequest)
				return
			}
			allExtractedFiles = append(allExtractedFiles, names...)
			continue
		}

		// Process the ZIP file to extract JSON files
		extractedFiles, err := ziputils.ProcessZipFile(filePath)
		// Delete the uploaded ZIP file — it's no longer needed after extraction, regardless if it succeeded or failed
		onZipFileProcessingFinished(&file, outFile, &filePath)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to process ZIP file %s: %v", fileHeader.Filename, err), http.StatusBadRequest)
			return
		}

		// Track the extracted directory for cleanup
		if len(extractedFiles) > 0 {
			extractDir := filepath.Dir(extractedFiles[0])
			requestExtractedDirs = append(requestExtractedDirs, extractDir)
			s.trackZipExtractedDirs([]string{extractDir})
			allExtractedFiles = append(allExtractedFiles, extractedFiles...)
		}
	}

	// Check if any JSON files were found across all ZIPs
	if len(allExtractedFiles) == 0 {
		http.Error(w, "No JSON files found in any of the ZIP archives", http.StatusBadRequest)
		return
	}

	// Use a map to handle duplicate filenames - last one wins
	uniqueFiles := make(map[string]bool)
	var fileNames []string

	// Process files in reverse order so first ZIP's files appear first in the list
	// but duplicates from later ZIPs still override earlier ones
	for i := len(allExtractedFiles) - 1; i >= 0; i-- {
		baseName := filepath.Base(allExtractedFiles[i])
		if _, exists := uniqueFiles[baseName]; !exists {
			uniqueFiles[baseName] = true
			fileNames = append([]string{baseName}, fileNames...) // Prepend to maintain order
		}
	}

	// Return the filenames as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(fileNames); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
}

// bundleDRNames lists the base names of a Virtual Signer bundle's .dr entries without extracting it.
func bundleDRNames(zipPath string) ([]string, error) {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open bundle %s: %w", filepath.Base(zipPath), fileutils.StripPathFromError(err))
	}
	defer reader.Close()

	var names []string
	for _, f := range reader.File {
		if f.FileInfo().IsDir() || ziputils.IsIgnoredZipEntry(f.Name) {
			continue
		}
		if strings.EqualFold(path.Ext(f.Name), ".dr") {
			names = append(names, path.Base(f.Name))
		}
	}
	return names, nil
}

// noopCleanup is returned by processFilesAndMnemonics on error paths, so callers can
// unconditionally defer the returned cleanup func without a nil check.
func noopCleanup() {}

// trackZipExtractedDirs records dirs on the server for the Stop() fallback cleanup.
// Handlers run concurrently, so the set is guarded by a mutex.
func (s *Server) trackZipExtractedDirs(dirs []string) {
	if len(dirs) == 0 {
		return
	}
	s.zipExtractedDirsMu.Lock()
	for _, dir := range dirs {
		s.zipExtractedDirs[dir] = struct{}{}
	}
	s.zipExtractedDirsMu.Unlock()
}

// cleanupRequestDirs removes a request's ZIP extraction dirs and drops them from the Stop()
// fallback set, so the set doesn't grow with every request on a long-running server.
func (s *Server) cleanupRequestDirs(dirs []string) {
	for _, dir := range dirs {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("warning: failed to clean up request temp directory %s: %v", dir, err)
			continue
		}
		log.Printf("cleaned up request temp directory: %s", dir)
		s.zipExtractedDirsMu.Lock()
		delete(s.zipExtractedDirs, dir)
		s.zipExtractedDirsMu.Unlock()
	}
}

// Validation handlers removed - unused in frontend
