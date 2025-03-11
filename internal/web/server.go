// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"bufio"
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
	"sync"
	"time"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/bittensor"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/solana"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/wif"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/xrpl"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/gorilla/websocket"
)

//go:embed static
var staticFiles embed.FS

const (
	tempDirPrefix = "vault-recovery-web-"
	
	// Terminal message types
	msgTypeCommand    = "command"
	msgTypeOutput     = "output"
	msgTypeError      = "error"
	msgTypeExit       = "exit"
	
	// Chain script types
	chainXRPL         = "xrpl"
	chainBittensor    = "bittensor"
	chainSolana       = "solana"
)

// Configure websocket upgrader
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for development purposes
	},
}

// ServerConfig holds the configuration for the web server
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

// TerminalMessage represents messages sent between client and server for terminal communication
type TerminalMessage struct {
	Type      string            `json:"type"`
	Chain     string            `json:"chain,omitempty"`
	Command   string            `json:"command,omitempty"`
	Arguments map[string]string `json:"arguments,omitempty"`
	Data      string            `json:"data,omitempty"`
	ExitCode  int               `json:"exitCode,omitempty"`
}

// ScriptProcess represents a running script process
type ScriptProcess struct {
	Cmd       *exec.Cmd
	StdoutPipe io.ReadCloser
	StdinPipe  io.WriteCloser
	Mutex     sync.Mutex
	Done      chan struct{}
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

	// API endpoints for address validation
	mux.HandleFunc("POST /api/validate/xrpl", s.handleValidateXRPL)
	mux.HandleFunc("POST /api/validate/bittensor", s.handleValidateBittensor)
	mux.HandleFunc("POST /api/validate/solana", s.handleValidateSolana)
	
	// Websocket endpoint for terminal connection
	mux.HandleFunc("GET /api/terminal", s.handleTerminalWebsocket)

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

			// Clear sensitive data
			clear(ecSK)
			clear(edSK)
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
	// Get file uploads - the frontend might use "files" or file input specific IDs
	var fileHeaders []*multipart.FileHeader
	for _, uploadedFiles := range r.MultipartForm.File {
		fileHeaders = append(fileHeaders, uploadedFiles...)
	}

	if len(fileHeaders) == 0 {
		return nil, fmt.Errorf("no files uploaded")
	}

	// Get mnemonics - might be "mnemonics" or specific IDs
	var mnemonicValues []string
	for key, values := range r.MultipartForm.Value {
		if strings.Contains(key, "mnemonic") {
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

// handleValidateXRPL validates an XRPL address
func (s *Server) handleValidateXRPL(w http.ResponseWriter, r *http.Request) {
	// Parse the form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	// Get the address from the form
	address := r.FormValue("address")
	if address == "" {
		http.Error(w, "Address is required", http.StatusBadRequest)
		return
	}

	// Validate the address using our internal package
	isValid := xrpl.ValidateXRPLAddress(address)

	// Return the result as JSON
	response := struct {
		Valid bool `json:"valid"`
	}{
		Valid: isValid,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
}

// handleValidateBittensor validates a Bittensor SS58 address
func (s *Server) handleValidateBittensor(w http.ResponseWriter, r *http.Request) {
	// Parse the form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	// Get the address from the form
	address := r.FormValue("address")
	if address == "" {
		http.Error(w, "Address is required", http.StatusBadRequest)
		return
	}

	// Validate the address using our internal package
	isValid := bittensor.ValidateBittensorAddress(address)

	// Return the result as JSON
	response := struct {
		Valid bool `json:"valid"`
	}{
		Valid: isValid,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
}

// handleValidateSolana validates a Solana address
func (s *Server) handleValidateSolana(w http.ResponseWriter, r *http.Request) {
	// Parse the form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	// Get the address from the form
	address := r.FormValue("address")
	if address == "" {
		http.Error(w, "Address is required", http.StatusBadRequest)
		return
	}

	// Validate the address using our internal package
	isValid := solana.ValidateSolanaAddress(address)

	// Return the result as JSON
	response := struct {
		Valid bool `json:"valid"`
	}{
		Valid: isValid,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
}

// handleTerminalWebsocket manages websocket connections for the terminal
func (s *Server) handleTerminalWebsocket(w http.ResponseWriter, r *http.Request) {
	// Upgrade the HTTP connection to a WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade to websocket: %v", err)
		return
	}
	defer conn.Close()

	// Create a channel for exit notification
	done := make(chan struct{})
	var process *ScriptProcess
	
	// Read messages from the WebSocket
	for {
		// Read message from browser
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Parse the message
		var msg TerminalMessage
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			log.Printf("Error parsing message: %v", err)
			sendTerminalError(conn, "Invalid message format")
			continue
		}

		// Handle message based on type
		switch msg.Type {
		case msgTypeCommand:
			// Start the appropriate script process
			process, err = s.startChainScript(msg.Chain, msg.Arguments)
			if err != nil {
				log.Printf("Error starting process: %v", err)
				sendTerminalError(conn, fmt.Sprintf("Failed to start process: %v", err))
				continue
			}

			// Start goroutines to handle process I/O
			go s.handleProcessOutput(conn, process, done)
			
		case msgTypeExit:
			// Kill the process if it's running
			if process != nil && process.Cmd != nil && process.Cmd.Process != nil {
				process.Mutex.Lock()
				_ = process.Cmd.Process.Kill()
				process.Mutex.Unlock()
				
				// Close pipes
				_ = process.StdoutPipe.Close()
				_ = process.StdinPipe.Close()
				
				// Wait for the process to finish
				select {
				case <-process.Done:
					// Process has ended
				case <-time.After(2 * time.Second):
					// Timeout waiting for process to end
				}
			}
			return
			
		default:
			sendTerminalError(conn, fmt.Sprintf("Unknown message type: %s", msg.Type))
		}
	}
}

// startChainScript starts the appropriate script for the given chain
func (s *Server) startChainScript(chain string, args map[string]string) (*ScriptProcess, error) {
	var scriptPath string
	var cmdArgs []string
	
	// Determine the script directory based on the chain
	switch chain {
	case chainXRPL:
		scriptPath = filepath.Join("scripts", "xrpl-tool")
		
		// Build arguments specific to XRPL
		if args["publicKey"] != "" {
			cmdArgs = append(cmdArgs, "--public-key", args["publicKey"])
		}
		if args["privateKey"] != "" {
			cmdArgs = append(cmdArgs, "--private-key", args["privateKey"])
		}
		if args["destination"] != "" {
			cmdArgs = append(cmdArgs, "--destination", args["destination"])
		}
		if args["amount"] != "" {
			cmdArgs = append(cmdArgs, "--amount", args["amount"])
		}
		if args["network"] != "" {
			cmdArgs = append(cmdArgs, "--network", args["network"])
		}
		if args["checkBalance"] == "true" {
			cmdArgs = append(cmdArgs, "--check-balance")
		}
		if args["broadcast"] == "true" {
			cmdArgs = append(cmdArgs, "--broadcast")
		}
		
	case chainBittensor:
		scriptPath = filepath.Join("scripts", "bittensor-tool")
		
		// Build arguments specific to Bittensor
		if args["privateKey"] != "" {
			cmdArgs = append(cmdArgs, "--private-key", args["privateKey"])
		}
		if args["destination"] != "" {
			cmdArgs = append(cmdArgs, "--destination", args["destination"])
		}
		if args["amount"] != "" {
			cmdArgs = append(cmdArgs, "--amount", args["amount"])
		}
		if args["endpoint"] != "" {
			cmdArgs = append(cmdArgs, "--endpoint", args["endpoint"])
		}
		
	case chainSolana:
		scriptPath = filepath.Join("scripts", "solana-tool")
		
		// Build arguments specific to Solana
		if args["privateKey"] != "" {
			cmdArgs = append(cmdArgs, "--private-key", args["privateKey"])
		}
		if args["destination"] != "" {
			cmdArgs = append(cmdArgs, "--destination", args["destination"])
		}
		if args["amount"] != "" {
			cmdArgs = append(cmdArgs, "--amount", args["amount"])
		}
		if args["network"] != "" {
			cmdArgs = append(cmdArgs, "--network", args["network"])
		}
		if args["checkBalance"] == "true" {
			cmdArgs = append(cmdArgs, "--check-balance")
		}
		if args["broadcast"] == "true" {
			cmdArgs = append(cmdArgs, "--broadcast")
		}
		
	default:
		return nil, fmt.Errorf("unsupported chain: %s", chain)
	}
	
	// Add confirm flag for all chains to automate confirmation
	if args["confirm"] == "true" {
		cmdArgs = append(cmdArgs, "--confirm")
	}
	
	// Get absolute path for script directory
	absScriptPath, err := filepath.Abs(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}
	
	// Create command to run npm start from the script directory
	cmd := exec.Command("npm", append([]string{"start", "--"}, cmdArgs...)...)
	cmd.Dir = absScriptPath
	
	// Create pipes for stdin and stdout
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	
	// Connect stderr to stdout for simplicity
	cmd.Stderr = cmd.Stdout
	
	// Create the process object
	process := &ScriptProcess{
		Cmd:        cmd,
		StdoutPipe: stdout,
		StdinPipe:  stdin,
		Done:       make(chan struct{}),
	}
	
	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}
	
	return process, nil
}

// handleProcessOutput reads from process stdout and sends to websocket
func (s *Server) handleProcessOutput(conn *websocket.Conn, process *ScriptProcess, done chan struct{}) {
	defer close(process.Done)
	
	scanner := bufio.NewScanner(process.StdoutPipe)
	
	// Read output line by line
	for scanner.Scan() {
		line := scanner.Text()
		
		// Send the line to the websocket
		msg := TerminalMessage{
			Type: msgTypeOutput,
			Data: line,
		}
		
		if err := conn.WriteJSON(msg); err != nil {
			log.Printf("Error writing to websocket: %v", err)
			break
		}
	}
	
	if err := scanner.Err(); err != nil {
		log.Printf("Error reading from process: %v", err)
		sendTerminalError(conn, fmt.Sprintf("Error reading from process: %v", err))
	}
	
	// Wait for the process to finish
	exitCode := 0
	if err := process.Cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}
	
	// Send exit message with the exit code
	msg := TerminalMessage{
		Type:     msgTypeExit,
		ExitCode: exitCode,
	}
	
	if err := conn.WriteJSON(msg); err != nil {
		log.Printf("Error sending exit message: %v", err)
	}
}

// sendTerminalError sends an error message to the websocket
func sendTerminalError(conn *websocket.Conn, errMsg string) {
	msg := TerminalMessage{
		Type: msgTypeError,
		Data: errMsg,
	}
	
	if err := conn.WriteJSON(msg); err != nil {
		log.Printf("Error sending error message: %v", err)
	}
}

// The runTool function implementation is in tool.go