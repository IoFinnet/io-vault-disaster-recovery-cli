// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/bittensor"
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
	tempDirPrefix = "vault-recovery-web-"
)

// ServerConfig holds the configuration for the http server
type ServerConfig struct {
	Port int
}

// RecoveryResult stores the recovery data to be sent to the frontend
type RecoveryResult struct {
	Success          bool   `json:"success"`
	ErrorMessage     string `json:"errorMessage,omitempty"`
	Address          string `json:"address,omitempty"`
	EcdsaPrivateKey  string `json:"ecdsaPrivateKey,omitempty"`
	TestnetWIF       string `json:"testnetWIF,omitempty"`
	MainnetWIF       string `json:"mainnetWIF,omitempty"`
	EddsaPrivateKey  string `json:"eddsaPrivateKey,omitempty"`
	EddsaPublicKey   string `json:"eddsaPublicKey,omitempty"`
	XRPLAddress      string `json:"xrplAddress,omitempty"`
	BittensorAddress string `json:"bittensorAddress,omitempty"`
	SolanaAddress    string `json:"solanaAddress,omitempty"`
}

// Server represents the http server for the disaster recovery tool
type Server struct {
	config           ServerConfig
	tempDir          string
	server           *http.Server
	listener         net.Listener
	zipExtractedDirs []string // Tracks temporary directories created for ZIP extractions
}

// NewServer creates a new http server instance
func NewServer(config ServerConfig) (*Server, error) {
	// Create a temporary directory to store uploaded files
	tempDir, err := os.MkdirTemp("", tempDirPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}

	return &Server{
		config:           config,
		tempDir:          tempDir,
		zipExtractedDirs: make([]string, 0),
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

	// Create the server
	s.server = &http.Server{
		Handler:      mux,
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

	// Clean up any ZIP extracted directories
	for _, dir := range s.zipExtractedDirs {
		os.RemoveAll(dir)
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
	vaultsDataFiles, err := s.processFilesAndMnemonics(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to process files: %v", err), http.StatusBadRequest)
		return
	}

	// If no vault data files were processed, return an error
	if len(vaultsDataFiles) == 0 {
		http.Error(w, "No valid vault data files provided", http.StatusBadRequest)
		return
	}

	// Run the tool to get vault information
	_, _, _, vaultsFormInfo, err := runTool(vaultsDataFiles, nil, nil, nil, nil, nil)
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

	// Get optional parameters
	nonceOverrideStr := r.FormValue("nonceOverride")
	var nonceOverride *int
	if nonceOverrideStr != "" {
		var nonce int
		fmt.Sscanf(nonceOverrideStr, "%d", &nonce)
		nonceOverride = &nonce
	}

	quorumOverrideStr := r.FormValue("quorumOverride")
	var quorumOverride *int
	if quorumOverrideStr != "" {
		var quorum int
		fmt.Sscanf(quorumOverrideStr, "%d", &quorum)
		quorumOverride = &quorum
	}

	passwordForKS := r.FormValue("password")
	var password *string
	if passwordForKS != "" {
		password = &passwordForKS
	}

	exportKSFile := r.FormValue("exportFile")
	if exportKSFile != "" && password == nil {
		http.Error(w, "Password is required when exporting keystore file", http.StatusBadRequest)
		return
	}
	var exportFile *string
	if exportKSFile != "" {
		exportFile = &exportKSFile
	}

	// Process files and mnemonics
	vaultsDataFiles, err := s.processFilesAndMnemonics(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to process files: %v", err), http.StatusBadRequest)
		return
	}

	// Run the recovery tool
	result := RecoveryResult{}
	address, ecSK, edSK, _, err := runTool(vaultsDataFiles, &vaultID, nonceOverride, quorumOverride, exportFile, password)

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

			// Clear sensitive data
			clear(ecSK)
			clear(edSK)
		} else {
			log.Printf("No EdDSA private key present")
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

// processFilesAndMnemonics processes the uploaded files and their mnemonics
func (s *Server) processFilesAndMnemonics(r *http.Request) ([]ui.VaultsDataFile, error) {
	// Debug logging to help diagnose form issues
	// Get file uploads - the frontend might use "files" or file input specific IDs
	var fileHeaders []*multipart.FileHeader
	for _, uploadedFiles := range r.MultipartForm.File {
		fileHeaders = append(fileHeaders, uploadedFiles...)
	}

	if len(fileHeaders) == 0 {
		return nil, fmt.Errorf("no files uploaded")
	}

	// Check if we're in ZIP mode (handle signers differently)
	isZipMode := false
	if mode, ok := r.MultipartForm.Value["mode"]; ok && len(mode) > 0 && mode[0] == "zip" {
		isZipMode = true
	}

	vaultsDataFiles := make([]ui.VaultsDataFile, 0)
	zipExtractedDirs := make([]string, 0)

	// Process all files
	jsonFileCount := 0 // Track actual JSON files (either direct or from ZIP)

	// Save each file to the temp directory
	for i, fileHeader := range fileHeaders {
		// Open the uploaded file
		file, err := fileHeader.Open()
		if err != nil {
			// Clean up any temp directories we've created
			for _, dir := range zipExtractedDirs {
				os.RemoveAll(dir)
			}
			return nil, fmt.Errorf("failed to open file %s: %w", fileHeader.Filename, err)
		}

		// Create a file in the temp directory
		filePath := filepath.Join(s.tempDir, fileHeader.Filename)
		outFile, err := os.Create(filePath)
		if err != nil {
			file.Close() // Close the file before returning on error
			// Clean up any temp directories we've created
			for _, dir := range zipExtractedDirs {
				os.RemoveAll(dir)
			}
			return nil, fmt.Errorf("failed to create temporary file %s: %w", filePath, err)
		}

		// Copy the file content
		if _, err := io.Copy(outFile, file); err != nil {
			file.Close()    // Close the input file
			outFile.Close() // Close the output file
			// Clean up any temp directories we've created
			for _, dir := range zipExtractedDirs {
				os.RemoveAll(dir)
			}
			return nil, fmt.Errorf("failed to copy file content: %w", err)
		}

		// Close both files after successful processing
		file.Close()
		outFile.Close()

		// Process the file based on its type
		if ziputils.IsZipFile(filePath) {
			// Extract JSON files from the ZIP
			extractedFiles, err := ziputils.ProcessZipFile(filePath)
			if err != nil {
				// Clean up any temp directories we've created
				for _, dir := range zipExtractedDirs {
					os.RemoveAll(dir)
				}
				return nil, err
			}

			// Track the extracted directory for cleanup
			if len(extractedFiles) > 0 {
				zipExtractedDirs = append(zipExtractedDirs, filepath.Dir(extractedFiles[0]))
			}

			if isZipMode {
				// ZIP mode: each signer JSON has its own mnemonic
				for _, extractedFile := range extractedFiles {
					// Get complete filename and base name without extension
					fileName := filepath.Base(extractedFile)
					baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))

					// Look for mnemonic specific to this signer type
					// We use baseName for the key as that's what the frontend is sending
					mnemonicKey := fmt.Sprintf("mnemonic_%s", baseName)

					// Check if we have a mnemonic for this signer
					if mnemonicValues, ok := r.MultipartForm.Value[mnemonicKey]; ok && len(mnemonicValues) > 0 {
						mnemonic := ui.CleanMnemonicInput(mnemonicValues[0])
						if err := ui.ValidateMnemonics(mnemonic); err != nil {
							// Clean up any temp directories we've created
							for _, dir := range zipExtractedDirs {
								os.RemoveAll(dir)
							}
							return nil, fmt.Errorf("invalid mnemonic for signer %s: %w", baseName, err)
						}

						// Add the file with its specific mnemonic
						vaultsDataFiles = append(vaultsDataFiles, ui.VaultsDataFile{
							File:      extractedFile,
							Mnemonics: mnemonic,
						})
						jsonFileCount++
					} else {
						// Skip files we don't have mnemonics for
						fmt.Printf("Skipping file %s - no mnemonic provided\n", extractedFile)
					}
				}
			} else {
				// Legacy ZIP handling: use same mnemonic for all files
				// Get mnemonics list for legacy handling
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

				// For ZIP files, we'll use the same mnemonic for all files inside
				mnemonicIndex := i
				if mnemonicIndex >= len(mnemonicValues) {
					mnemonicIndex = 0 // Fall back to first mnemonic if not enough
				}

				if len(mnemonicValues) == 0 {
					// Clean up any temp directories we've created
					for _, dir := range zipExtractedDirs {
						os.RemoveAll(dir)
					}
					return nil, fmt.Errorf("no mnemonics provided for ZIP file %s", fileHeader.Filename)
				}

				mnemonic := ui.CleanMnemonicInput(mnemonicValues[mnemonicIndex])
				if err := ui.ValidateMnemonics(mnemonic); err != nil {
					// Clean up any temp directories we've created
					for _, dir := range zipExtractedDirs {
						os.RemoveAll(dir)
					}
					return nil, fmt.Errorf("invalid mnemonic for ZIP file %s: %w", fileHeader.Filename, err)
				}

				// Add each extracted file to vaultsDataFiles with the same mnemonic
				for _, extractedFile := range extractedFiles {
					vaultsDataFiles = append(vaultsDataFiles, ui.VaultsDataFile{
						File:      extractedFile,
						Mnemonics: mnemonic,
					})
					jsonFileCount++
				}
			}
		} else {
			// Handle regular JSON file
			// Get mnemonics from regular fields
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

			// Clean the mnemonic input
			mnemonicIndex := i
			if mnemonicIndex >= len(mnemonicValues) {
				mnemonicIndex = 0 // Fall back to first mnemonic if not enough
			}

			if len(mnemonicValues) == 0 {
				// Clean up any temp directories we've created
				for _, dir := range zipExtractedDirs {
					os.RemoveAll(dir)
				}
				return nil, fmt.Errorf("no mnemonics provided for JSON file %s", fileHeader.Filename)
			}

			mnemonic := ui.CleanMnemonicInput(mnemonicValues[mnemonicIndex])
			if err := ui.ValidateMnemonics(mnemonic); err != nil {
				// Clean up any temp directories we've created
				for _, dir := range zipExtractedDirs {
					os.RemoveAll(dir)
				}
				return nil, fmt.Errorf("invalid mnemonic for file %s: %w", fileHeader.Filename, err)
			}

			// Add the file to the vaultsDataFiles
			vaultsDataFiles = append(vaultsDataFiles, ui.VaultsDataFile{
				File:      filePath,
				Mnemonics: mnemonic,
			})
			jsonFileCount++
		}
	}

	// Ensure we have at least one JSON file to process
	if jsonFileCount == 0 {
		// Clean up any temp directories we've created
		for _, dir := range zipExtractedDirs {
			os.RemoveAll(dir)
		}
		return nil, fmt.Errorf("no valid JSON files were uploaded (directly or in ZIP archives)")
	}

	// Store the list of extracted directories in the server for later cleanup
	s.zipExtractedDirs = append(s.zipExtractedDirs, zipExtractedDirs...)
	return vaultsDataFiles, nil
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

	// Get the ZIP file
	files := r.MultipartForm.File["zipFile"]
	if len(files) == 0 {
		http.Error(w, "No ZIP file provided", http.StatusBadRequest)
		return
	}

	// Open the uploaded file
	file, err := files[0].Open()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to open file: %v", err), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create a file in the temp directory
	filePath := filepath.Join(s.tempDir, files[0].Filename)
	outFile, err := os.Create(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create temporary file: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy the file content
	if _, err := io.Copy(outFile, file); err != nil {
		outFile.Close()
		http.Error(w, fmt.Sprintf("Failed to copy file content: %v", err), http.StatusInternalServerError)
		return
	}
	outFile.Close()

	// Process the ZIP file to extract JSON files
	extractedFiles, err := ziputils.ProcessZipFile(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to process ZIP file: %v", err), http.StatusBadRequest)
		return
	}

	// Track the extracted directory for cleanup
	if len(extractedFiles) > 0 {
		extractDir := filepath.Dir(extractedFiles[0])
		s.zipExtractedDirs = append(s.zipExtractedDirs, extractDir)
	}

	// Check if any JSON files were found
	if len(extractedFiles) == 0 {
		// Clean up the temporary directory if we created one
		os.RemoveAll(filePath)

		http.Error(w, "No JSON files found in the ZIP archive", http.StatusBadRequest)
		return
	}

	// Create a response with just the filenames
	fileNames := make([]string, len(extractedFiles))
	for i, file := range extractedFiles {
		fileNames[i] = filepath.Base(file)
	}

	// Return the filenames as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(fileNames); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
}

// Validation handlers removed - unused in frontend

// The runTool function implementation is in tool.go
