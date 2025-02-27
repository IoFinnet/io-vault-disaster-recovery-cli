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
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

//go:embed static
var staticFiles embed.FS

const (
	tempDirPrefix = "vault-recovery-web-"
)

// ServerConfig holds the configuration for the web server
type ServerConfig struct {
	Port int
}

// RecoveryResult stores the recovery data to be sent to the frontend
type RecoveryResult struct {
	Success        bool   `json:"success"`
	ErrorMessage   string `json:"errorMessage,omitempty"`
	Address        string `json:"address,omitempty"`
	EcdsaPrivateKey string `json:"ecdsaPrivateKey,omitempty"`
	TestnetWIF     string `json:"testnetWIF,omitempty"`
	MainnetWIF     string `json:"mainnetWIF,omitempty"`
	EddsaPrivateKey string `json:"eddsaPrivateKey,omitempty"`
	EddsaPublicKey  string `json:"eddsaPublicKey,omitempty"`
	XRPLAddress     string `json:"xrplAddress,omitempty"`
	BittensorAddress string `json:"bittensorAddress,omitempty"`
	SolanaAddress   string `json:"solanaAddress,omitempty"`
}

// Server represents the web server for the disaster recovery tool
type Server struct {
	config   ServerConfig
	tempDir  string
	server   *http.Server
	listener net.Listener
}

// NewServer creates a new web server instance
func NewServer(config ServerConfig) (*Server, error) {
	// Create a temporary directory to store uploaded files
	tempDir, err := os.MkdirTemp("", tempDirPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}

	return &Server{
		config:  config,
		tempDir: tempDir,
	}, nil
}

// Start starts the web server
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
		log.Printf("Starting web server on http://localhost:%d", port)
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
		}
	}()

	return fmt.Sprintf("http://localhost:%d", port), nil
}

// Stop stops the web server and cleans up resources
func (s *Server) Stop() error {
	// Close the server
	if s.server != nil {
		if err := s.server.Close(); err != nil {
			return err
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
			
			// Get the EdDSA public key
			_, edPK, err := edwards.PrivKeyFromScalar(edSK)
			if err == nil {
				edPKC := edPK.SerializeCompressed()
				result.EddsaPublicKey = hex.EncodeToString(edPKC)
				
				// Generate XRPL address
				xrplAddress, err := xrpl.DeriveXRPLAddress(edPKC)
				if err == nil {
					result.XRPLAddress = xrplAddress
				}
				
				// Generate Bittensor address
				bittensorAddress, err := bittensor.GenerateSS58Address(edPKC)
				if err == nil {
					result.BittensorAddress = bittensorAddress
				}
				
				// Generate Solana address
				solanaAddress, err := solana.DeriveSolanaAddress(edPKC)
				if err == nil {
					result.SolanaAddress = solanaAddress
				}
			}
		}

		// Clear sensitive data
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
	fmt.Printf("Debug: Processing form data\n")
	fmt.Printf("Debug: Form value keys: %v\n", getMapKeys(r.MultipartForm.Value))
	fmt.Printf("Debug: Form file keys: %v\n", getMapKeys(r.MultipartForm.File))
	
	// Get file uploads - the frontend might use "files" or file input specific IDs
	var fileHeaders []*multipart.FileHeader
	for key, uploadedFiles := range r.MultipartForm.File {
		fmt.Printf("Debug: Found file field: %s with %d files\n", key, len(uploadedFiles))
		fileHeaders = append(fileHeaders, uploadedFiles...)
	}
	
	if len(fileHeaders) == 0 {
		return nil, fmt.Errorf("no files uploaded")
	}
	
	// Get mnemonics - might be "mnemonics" or specific IDs
	var mnemonicValues []string
	for key, values := range r.MultipartForm.Value {
		if strings.Contains(key, "mnemonic") {
			fmt.Printf("Debug: Found mnemonic field: %s\n", key)
			mnemonicValues = append(mnemonicValues, values...)
		}
	}
	
	// If we couldn't find mnemonic fields by name, try using all form values
	if len(mnemonicValues) == 0 {
		for _, values := range r.MultipartForm.Value {
			mnemonicValues = append(mnemonicValues, values...)
		}
	}
	
	// Ensure we have the right number of mnemonics
	if len(mnemonicValues) < len(fileHeaders) {
		return nil, fmt.Errorf("number of mnemonics (%d) does not match number of files (%d)", len(mnemonicValues), len(fileHeaders))
	}

	vaultsDataFiles := make([]ui.VaultsDataFile, 0, len(fileHeaders))

	// Save each file to the temp directory
	for i, fileHeader := range fileHeaders {
		// Open the uploaded file
		file, err := fileHeader.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open file %s: %w", fileHeader.Filename, err)
		}
		defer file.Close()

		// Create a file in the temp directory
		filePath := filepath.Join(s.tempDir, fileHeader.Filename)
		outFile, err := os.Create(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary file %s: %w", filePath, err)
		}
		defer outFile.Close()

		// Copy the file content
		if _, err := io.Copy(outFile, file); err != nil {
			return nil, fmt.Errorf("failed to copy file content: %w", err)
		}
		
		// Make sure to close and sync the file to ensure it's fully written
		outFile.Close()

		// Clean the mnemonic input
		mnemonicIndex := i
		if mnemonicIndex >= len(mnemonicValues) {
			mnemonicIndex = 0 // Fall back to first mnemonic if not enough
		}
		
		mnemonic := ui.CleanMnemonicInput(mnemonicValues[mnemonicIndex])
		if err := ui.ValidateMnemonics(mnemonic); err != nil {
			return nil, fmt.Errorf("invalid mnemonic for file %s: %w", fileHeader.Filename, err)
		}
		
		fmt.Printf("Debug: Processing file %s with mnemonic (%d words)\n", 
			fileHeader.Filename, len(strings.Split(mnemonic, " ")))

		// Add the file to the vaultsDataFiles
		vaultsDataFiles = append(vaultsDataFiles, ui.VaultsDataFile{
			File:      filePath,
			Mnemonics: mnemonic,
		})
	}

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

// The runTool function implementation is in tool.go