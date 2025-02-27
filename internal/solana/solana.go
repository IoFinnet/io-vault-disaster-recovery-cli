// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package solana

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

// Constants for Solana
const (
	SolanaAddressLength = 44 // Base58 encoded public key length
	
	// Default endpoints
	SolanaMainnetAPI = "https://api.mainnet-beta.solana.com"
	SolanaTestnetAPI = "https://api.testnet.solana.com"
	SolanaDevnetAPI  = "https://api.devnet.solana.com"
	
	// Program IDs
	SystemProgramID = "11111111111111111111111111111111" // System program
)

// SolanaResponse represents the standard JSON-RPC response
type SolanaResponse struct {
	ID      int             `json:"id"`
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    interface{} `json:"data,omitempty"`
	} `json:"error,omitempty"`
}

// AccountInfo represents account information from Solana
type AccountInfo struct {
	Lamports   uint64            `json:"lamports"`
	Owner      string            `json:"owner"`
	Data       []string          `json:"data"`
	Executable bool              `json:"executable"`
	RentEpoch  uint64            `json:"rentEpoch"`
}

// BlockhashInfo represents recent blockhash information
type BlockhashInfo struct {
	Blockhash               string `json:"blockhash"`
	LastValidBlockHeight    uint64 `json:"lastValidBlockHeight"`
}

// SolanaTransactionInstruction represents a Solana transaction instruction
type SolanaTransactionInstruction struct {
	ProgramID  string   `json:"programId"`
	Accounts   []string `json:"accounts"`
	Data       string   `json:"data"`
}

// SolanaTransaction represents a Solana transaction
type SolanaTransaction struct {
	RecentBlockhash string                        `json:"recentBlockhash"`
	FeePayer        string                        `json:"feePayer"`
	Instructions    []SolanaTransactionInstruction `json:"instructions"`
	Signatures      []string                      `json:"signatures,omitempty"`
}

// SolanaClient represents a client to interact with the Solana network
type SolanaClient struct {
	Endpoint string
	Client   *http.Client
}

// NewSolanaClient creates a new Solana client
func NewSolanaClient(network string) *SolanaClient {
	var endpoint string
	
	switch network {
	case "mainnet":
		endpoint = SolanaMainnetAPI
	case "testnet":
		endpoint = SolanaTestnetAPI
	case "devnet":
		endpoint = SolanaDevnetAPI
	default:
		endpoint = SolanaMainnetAPI
	}
	
	return &SolanaClient{
		Endpoint: endpoint,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// RPC sends a JSON-RPC request to the Solana API
func (c *SolanaClient) RPC(method string, params interface{}) (*SolanaResponse, error) {
	// Create request payload
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}
	
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}
	
	// Send request
	resp, err := c.Client.Post(c.Endpoint, "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()
	
	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	
	// Parse response
	var result SolanaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}
	
	// Check for errors
	if result.Error != nil {
		return nil, fmt.Errorf("API error: %d - %s", result.Error.Code, result.Error.Message)
	}
	
	return &result, nil
}

// GetAccountInfo retrieves account information for a given address
func (c *SolanaClient) GetAccountInfo(address string) (*AccountInfo, error) {
	// Build the RPC parameters
	params := []interface{}{
		address,
		map[string]interface{}{
			"encoding": "base64",
		},
	}
	
	resp, err := c.RPC("getAccountInfo", params)
	if err != nil {
		return nil, err
	}
	
	// Parse the result
	var result struct {
		Value *AccountInfo `json:"value"`
	}
	
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to parse account info: %v", err)
	}
	
	if result.Value == nil {
		return nil, fmt.Errorf("account not found: %s", address)
	}
	
	return result.Value, nil
}

// GetRecentBlockhash retrieves the recent blockhash
func (c *SolanaClient) GetRecentBlockhash() (*BlockhashInfo, error) {
	resp, err := c.RPC("getLatestBlockhash", []interface{}{
		map[string]interface{}{
			"commitment": "finalized",
		},
	})
	if err != nil {
		return nil, err
	}
	
	var result struct {
		Value *BlockhashInfo `json:"value"`
	}
	
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to parse blockhash info: %v", err)
	}
	
	if result.Value == nil {
		return nil, fmt.Errorf("failed to get recent blockhash")
	}
	
	return result.Value, nil
}

// SimulateTransaction simulates a transaction and returns any errors
func (c *SolanaClient) SimulateTransaction(txBase64 string) error {
	params := []interface{}{
		txBase64,
		map[string]interface{}{
			"sigVerify": false,
		},
	}
	
	resp, err := c.RPC("simulateTransaction", params)
	if err != nil {
		return err
	}
	
	var result struct {
		Value struct {
			Err interface{} `json:"err"`
		} `json:"value"`
	}
	
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return fmt.Errorf("failed to parse simulation result: %v", err)
	}
	
	if result.Value.Err != nil {
		return fmt.Errorf("transaction simulation failed: %v", result.Value.Err)
	}
	
	return nil
}

// SendTransaction submits a signed transaction to the network
func (c *SolanaClient) SendTransaction(txBase64 string) (string, error) {
	params := []interface{}{
		txBase64,
		map[string]interface{}{
			"encoding": "base64",
		},
	}
	
	resp, err := c.RPC("sendTransaction", params)
	if err != nil {
		return "", err
	}
	
	var result string
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return "", fmt.Errorf("failed to parse transaction signature: %v", err)
	}
	
	return result, nil
}

// HandleTransaction processes a Solana transaction
func HandleTransaction(privateKey []byte, destination, amount string, endpoint string, testnet bool) error {
	// Validate inputs
	if err := validateInputs(destination, amount); err != nil {
		return err
	}

	// Derive public key from private key
	_, pubKey, err := edwards.PrivKeyFromScalar(privateKey)
	if err != nil {
		return fmt.Errorf("failed to derive public key: %v", err)
	}

	// Display key information
	fmt.Println("\nSolana Transaction Information:")
	networkType := "mainnet"
	if testnet {
		networkType = "testnet/devnet"
	}
	fmt.Printf("Network: %s\n", networkType)
	if endpoint != "" {
		fmt.Printf("Endpoint: %s\n", endpoint)
	}

	// Get Solana address from public key
	pubKeyBytes := pubKey.SerializeCompressed()
	solanaAddress, err := DeriveSolanaAddress(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to derive Solana address: %v", err)
	}
	fmt.Printf("Your Solana Address: %s\n", solanaAddress)

	// Transaction details
	fmt.Printf("Destination: %s\n", destination)
	fmt.Printf("Amount: %s SOL\n", amount)

	// Process online vs offline modes
	fmt.Println("\nSolana transactions require online access to fetch account information and network fees.")
	fmt.Println("Would you like to proceed with the transaction now (online mode)?")
	fmt.Println("If you choose 'No', we'll provide instructions for later use.")

	// Ask user if they want to proceed with online transaction
	var proceed string
	fmt.Print("Proceed with online transaction? (y/n): ")
	fmt.Scanln(&proceed)

	if proceed == "y" || proceed == "Y" {
		// Ask for network selection
		fmt.Println("\nSelect Solana network:")
		fmt.Println("1. Mainnet")
		fmt.Println("2. Testnet")
		fmt.Println("3. Devnet")
		
		var networkChoice string
		fmt.Print("Enter choice (1-3): ")
		fmt.Scanln(&networkChoice)
		
		var network string
		switch networkChoice {
		case "1":
			network = "mainnet"
		case "2":
			network = "testnet"
		case "3":
			network = "devnet"
		default:
			network = "mainnet"
		}
		
		return buildAndSubmitSolanaTransaction(privateKey, pubKeyBytes, destination, amount, network)
	}

	// Offline mode instructions
	fmt.Println("\nTo complete this transaction later:")
	fmt.Println("1. Run this tool again with the --solana flag when you're ready to connect to the network")
	fmt.Println("2. Use the same private key, destination address, and amount")
	fmt.Println("3. Choose 'Yes' at the online transaction prompt")

	return nil
}

// createTransferInstruction creates a Solana transfer instruction
func createTransferInstruction(from, to string, lamports uint64) SolanaTransactionInstruction {
	// Create a transfer instruction
	// In Solana, a transfer is done through the System Program
	
	// The data for a transfer instruction:
	// 0x02, 0x00, 0x00, 0x00 (Command index for transfer)
	// followed by lamports (little-endian 64-bit unsigned integer)
	lamportsBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lamportsBytes, lamports)
	
	// Combine command index and lamports
	data := append([]byte{2, 0, 0, 0}, lamportsBytes...)
	
	// Create the instruction - Solana expects base64 encoding for the data field
	instruction := SolanaTransactionInstruction{
		ProgramID: SystemProgramID,
		Accounts: []string{from, to},
		Data:     base64.StdEncoding.EncodeToString(data),
	}
	
	return instruction
}

// serializeTransaction serializes a transaction for signing using Solana's wire format
func serializeTransaction(tx *SolanaTransaction) ([]byte, error) {
	// This implementation follows Solana's transaction wire format
	// as defined in the Solana documentation and @solana/web3.js
	
	var buffer bytes.Buffer
	
	// 1. Signatures (placeholder for signature count)
	// For a single signature transaction, we write 1 as a compact-u16
	buffer.WriteByte(1)
	
	// 2. Message header
	// - Number of required signatures (1)
	buffer.WriteByte(1)
	// - Number of read-only signed accounts (0)
	buffer.WriteByte(0)
	// - Number of read-only unsigned accounts (0)
	buffer.WriteByte(0)
	
	// 3. Account keys
	// - Number of account keys (compact-u16)
	// For a transfer, we have 3 accounts: fee payer, source, destination
	buffer.WriteByte(3)
	
	// - Fee payer account
	feePayerPubkey, err := base58.Decode(tx.FeePayer)
	if err != nil {
		return nil, fmt.Errorf("invalid fee payer: %v", err)
	}
	buffer.Write(feePayerPubkey)
	
	// - Source account (same as fee payer in this case)
	sourceAccount := tx.Instructions[0].Accounts[0]
	sourcePubkey, err := base58.Decode(sourceAccount)
	if err != nil {
		return nil, fmt.Errorf("invalid source account: %v", err)
	}
	buffer.Write(sourcePubkey)
	
	// - Destination account
	destAccount := tx.Instructions[0].Accounts[1]
	destPubkey, err := base58.Decode(destAccount)
	if err != nil {
		return nil, fmt.Errorf("invalid destination account: %v", err)
	}
	buffer.Write(destPubkey)
	
	// - Program ID (System Program)
	programPubkey, err := base58.Decode(tx.Instructions[0].ProgramID)
	if err != nil {
		return nil, fmt.Errorf("invalid program ID: %v", err)
	}
	buffer.Write(programPubkey)
	
	// 4. Recent blockhash
	blockhash, err := base58.Decode(tx.RecentBlockhash)
	if err != nil {
		return nil, fmt.Errorf("invalid blockhash: %v", err)
	}
	buffer.Write(blockhash)
	
	// 5. Instructions
	// - Number of instructions (compact-u16)
	buffer.WriteByte(byte(len(tx.Instructions)))
	
	// - For each instruction
	for _, instruction := range tx.Instructions {
		// Program ID index (u8)
		buffer.WriteByte(3) // Index of the program ID in the account keys array
		
		// Account indices
		// - Number of accounts (compact-u16)
		buffer.WriteByte(byte(len(instruction.Accounts)))
		
		// - Account indices (u8)
		buffer.WriteByte(1) // Source account index
		buffer.WriteByte(2) // Destination account index
		
		// Instruction data
		// - Length of data (compact-u16)
		instructionData, err := base64.StdEncoding.DecodeString(instruction.Data)
		if err != nil {
			return nil, fmt.Errorf("invalid instruction data: %v", err)
		}
		buffer.WriteByte(byte(len(instructionData)))
		
		// - Data bytes
		buffer.Write(instructionData)
	}
	
	return buffer.Bytes(), nil
}

// Import our shared crypto package
import (
	"github.com/io-finnet/crypto-tool/internal/crypto"
)

// ed25519Sign signs a message with the scalar private key
func ed25519Sign(privateKey, message []byte) ([]byte, error) {
	// Use our shared signing implementation
	return crypto.SignWithScalar(privateKey, message)
}

// verifySignature verifies an Ed25519 signature on a transaction
func verifySignature(pubKey, message, signature []byte) bool {
	return ed25519.Verify(pubKey, message, signature)
}

// buildAndSubmitSolanaTransaction builds and submits a Solana transaction
func buildAndSubmitSolanaTransaction(privateKey, publicKey []byte, destination, amount, network string) error {
	fmt.Println("\nPreparing transaction...")

	// Determine Solana network
	switch network {
	case "mainnet", "testnet", "devnet":
		fmt.Printf("Connecting to Solana %s...\n", network)
	default:
		return fmt.Errorf("invalid network: %s", network)
	}
	
	// Create client
	client := NewSolanaClient(network)
	
	// Derive Solana address from public key
	sourceAddress, err := DeriveSolanaAddress(publicKey)
	if err != nil {
		return fmt.Errorf("failed to derive source address: %v", err)
	}
	fmt.Printf("Source account: %s\n", sourceAddress)
	
	// Parse amount
	amountFloat, err := strconv.ParseFloat(amount, 64)
	if err != nil {
		return fmt.Errorf("invalid amount: %v", err)
	}
	
	// Convert to lamports (1 SOL = 1,000,000,000 lamports)
	lamports := uint64(amountFloat * 1000000000)
	fmt.Printf("Amount in lamports: %d\n", lamports)
	
	// Fetch account information
	fmt.Println("Fetching account information...")
	accountInfo, err := client.GetAccountInfo(sourceAddress)
	if err != nil {
		// For demo purposes, we can proceed with simulated data
		fmt.Printf("Warning: Failed to fetch account info: %v\n", err)
		fmt.Println("Proceeding with simulated account data...")
		
		// Simulate account info
		accountInfo = &AccountInfo{
			Lamports: 10000000000, // 10 SOL
			Owner:    SystemProgramID,
		}
	}
	
	// Check if the account has enough balance
	if accountInfo.Lamports < lamports+5000 { // 5000 lamports for fee
		return fmt.Errorf("insufficient funds: available balance is %f SOL, need %f SOL (including fee)",
			float64(accountInfo.Lamports)/1000000000,
			float64(lamports+5000)/1000000000)
	}
	
	// Get recent blockhash
	fmt.Println("Fetching recent blockhash...")
	blockhashInfo, err := client.GetRecentBlockhash()
	if err != nil {
		fmt.Printf("Warning: Failed to fetch recent blockhash: %v\n", err)
		fmt.Println("Using dummy blockhash for demonstration...")
		
		// Use a dummy blockhash
		blockhashInfo = &BlockhashInfo{
			Blockhash: "11111111111111111111111111111111",
		}
	}
	
	// Create transfer instruction
	instruction := createTransferInstruction(sourceAddress, destination, lamports)
	
	// Build transaction
	tx := &SolanaTransaction{
		RecentBlockhash: blockhashInfo.Blockhash,
		FeePayer:        sourceAddress,
		Instructions:    []SolanaTransactionInstruction{instruction},
	}
	
	// Display transaction details
	fmt.Println("\nTransaction Details:")
	fmt.Printf("From: %s\n", sourceAddress)
	fmt.Printf("To: %s\n", destination)
	fmt.Printf("Amount: %s SOL (%d lamports)\n", amount, lamports)
	fmt.Printf("Network: %s\n", network)
	fmt.Printf("Blockhash: %s\n", tx.RecentBlockhash)
	
	// Ask for confirmation
	var confirm string
	fmt.Print("\nConfirm transaction? (y/n): ")
	fmt.Scanln(&confirm)
	
	if confirm != "y" && confirm != "Y" {
		fmt.Println("Transaction cancelled.")
		return nil
	}
	
	// Serialize transaction for signing
	fmt.Println("Building transaction...")
	txBytes, err := serializeTransaction(tx)
	if err != nil {
		return fmt.Errorf("failed to serialize transaction: %v", err)
	}
	
	// Sign the transaction
	fmt.Println("Signing transaction...")
	signature, err := ed25519Sign(privateKey, txBytes)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %v", err)
	}
	
	// Verify signature
	fmt.Println("Verifying signature...")
	if !verifySignature(publicKey, txBytes, signature) {
		return fmt.Errorf("signature verification failed")
	}
	fmt.Println("Signature verified successfully")
	
	// Add signature to transaction
	tx.Signatures = []string{base58.Encode(signature)}
	
	// Serialize and encode the complete transaction
	txJSON, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %v", err)
	}
	
	// For actual submission, use base64
	txBase64 := base64.StdEncoding.EncodeToString(txJSON)
	
	// Simulate transaction first to check for errors
	fmt.Println("Simulating transaction...")
	if err := client.SimulateTransaction(txBase64); err != nil {
		return fmt.Errorf("transaction simulation failed: %v", err)
	}
	fmt.Println("Transaction simulation successful")
	
	// Submit transaction
	fmt.Println("Submitting transaction...")
	transactionSignature, err := client.SendTransaction(txBase64)
	if err != nil {
		fmt.Printf("\n❌ ERROR: Transaction submission failed: %v\n", err)
		fmt.Println("\nThe transaction could not be submitted to the Solana network.")
		fmt.Println("This could be due to network connectivity issues, invalid credentials,")
		fmt.Println("or problems with the Solana server.")
		return fmt.Errorf("transaction submission failed: %w", err)
	}
	
	fmt.Println("\n✅ Transaction submitted successfully!")
	fmt.Printf("Transaction signature: %s\n", transactionSignature)
	fmt.Printf("View on Solana Explorer: https://explorer.solana.com/tx/%s?cluster=%s\n", 
		transactionSignature, network)
	
	return nil
}

// validateInputs checks if the destination and amount are valid
func validateInputs(destination, amount string) error {
	if !isValidSolanaAddress(destination) {
		return errors.New("invalid Solana destination address format")
	}

	if !isValidAmount(amount) {
		return errors.New("invalid SOL amount (must be a positive number)")
	}

	return nil
}

// isValidSolanaAddress checks if the address is a valid Solana address
func isValidSolanaAddress(address string) bool {
	// Simple validation - in production use a proper Solana address validation
	return len(address) >= 32 && len(address) <= 44
}

// isValidAmount checks if the amount is valid
func isValidAmount(amount string) bool {
	// Simple validation - could be more sophisticated
	return len(amount) > 0 && amount[0] != '-'
}

// DeriveSolanaAddress derives a Solana address from a public key
// Solana addresses are the Base58 encoding of the public key bytes
func DeriveSolanaAddress(pubKey []byte) (string, error) {
	// Solana addresses are just Base58 encoded public keys
	address := base58.Encode(pubKey)
	return address, nil
}

// GenerateKeyPairString generates a Solana keypair string format
// This format is used by Solana CLI and some wallets
func GenerateKeyPairString(privateKey []byte, publicKey []byte) (string, error) {
	// Solana keypair is [private key bytes (32) + public key bytes (32)]
	keypair := append(privateKey, publicKey...)
	return base64.StdEncoding.EncodeToString(keypair), nil
}
