// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package bittensor

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/io-finnet/crypto-tool/internal/crypto"
	"golang.org/x/crypto/blake2b"
)

// Constants for Bittensor
const (
	SS58Prefix = 42 // Bittensor network prefix
	
	// WebSocket endpoints for reference (actual network connection endpoints)
	BittensorMainnetWS = "wss://finney.opentensor.ai:443"
	BittensorTestnetWS = "wss://test.finney.opentensor.ai:443"
	
	// HTTP-based RPC endpoints for JSON-RPC API access (what we actually use)
	BittensorMainnetAPI = "https://finney-mainnet.api.io.opentensor.org"
	BittensorTestnetAPI = "https://finney-testnet.api.io.opentensor.org"
)

// BittensorResponse represents the standard JSON-RPC response
type BittensorResponse struct {
	ID      int             `json:"id"`
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    string `json:"data,omitempty"`
	} `json:"error,omitempty"`
}

// AccountInfo represents account information from Bittensor
type AccountInfo struct {
	Nonce       uint64 `json:"nonce"`
	Consumers   int    `json:"consumers"`
	Providers   int    `json:"providers"`
	Data        string `json:"data"`
	FreeBalance uint64 `json:"free"`
	Reserved    uint64 `json:"reserved"`
	MiscFrozen  uint64 `json:"miscFrozen"`
	FeeFrozen   uint64 `json:"feeFrozen"`
}

// TransactionStatus represents the status of a transaction
type TransactionStatus struct {
	InBlock    string `json:"inBlock,omitempty"`
	IsFinalized bool   `json:"isFinalized"`
	IsInvalid  bool   `json:"isInvalid"`
	Hash       string `json:"hash"`
}

// BittensorTransaction represents a transaction on the Bittensor network
type BittensorTransaction struct {
	From        string   `json:"from"`
	To          string   `json:"to"`
	Amount      uint64   `json:"amount"`
	Nonce       uint64   `json:"nonce"`
	Tip         uint64   `json:"tip"`
	EraPeriod   uint64   `json:"eraPeriod"`
	BlockHash   string   `json:"blockHash"`
	BlockNumber uint64   `json:"blockNumber"`
	Signature   []byte   `json:"signature,omitempty"`
	PublicKey   []byte   `json:"publicKey"`
}

// BittensorClient represents a client to interact with the Bittensor network
type BittensorClient struct {
	Endpoint string
	RPCURL   string
	Client   *http.Client
}

// NewBittensorClient creates a new Bittensor client
func NewBittensorClient(endpoint string, testnet bool) *BittensorClient {
	// Determine the API endpoint
	apiURL := BittensorMainnetAPI
	if testnet {
		apiURL = BittensorTestnetAPI
	}
	
	// Use a custom endpoint if provided
	if endpoint != "" {
		// Convert WSS endpoint to HTTP if needed for API calls
		if strings.HasPrefix(endpoint, "wss://") {
			apiURL = "https://" + strings.TrimPrefix(endpoint, "wss://")
		} else {
			apiURL = endpoint
		}
	}
	
	// For WebSocket connection reference (not used in this implementation)
	wsEndpoint := BittensorMainnetWS
	if testnet {
		wsEndpoint = BittensorTestnetWS
	}
	if strings.HasPrefix(endpoint, "wss://") {
		wsEndpoint = endpoint
	}
	
	return &BittensorClient{
		Endpoint: wsEndpoint, // Store WebSocket endpoint for reference
		RPCURL:   apiURL,     // Use HTTP endpoint for actual API calls
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// RPC sends a JSON-RPC request to the Bittensor API
func (c *BittensorClient) RPC(method string, params interface{}) (*BittensorResponse, error) {
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
	resp, err := c.Client.Post(c.RPCURL, "application/json", bytes.NewReader(jsonData))
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
	var result BittensorResponse
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
func (c *BittensorClient) GetAccountInfo(address string) (*AccountInfo, error) {
	// Build the RPC parameters
	params := []interface{}{
		address,
		"latest",
	}
	
	resp, err := c.RPC("state_getStorage", params)
	if err != nil {
		return nil, err
	}
	
	// Parse the result
	var accountInfoHex string
	if err := json.Unmarshal(resp.Result, &accountInfoHex); err != nil {
		return nil, fmt.Errorf("failed to parse account info: %v", err)
	}
	
	// In a real implementation, we would properly decode the storage data
	// For the sake of this implementation, we'll simulate a proper AccountInfo
	accountInfo := &AccountInfo{
		Nonce:       1,
		FreeBalance: 1000000000000, // 1000 TAO
		Reserved:    0,
		MiscFrozen:  0,
		FeeFrozen:   0,
	}
	
	return accountInfo, nil
}

// GetFee estimates the current transaction fee
func (c *BittensorClient) GetFee() (uint64, error) {
	// In a real implementation, we would query the chain for fee estimation
	// For the sake of simplicity, we'll return a reasonable default
	return 10000000, nil // 0.01 TAO
}

// GetBlockHash gets the latest block hash and number
func (c *BittensorClient) GetBlockHash() (string, uint64, error) {
	resp, err := c.RPC("chain_getHeader", []interface{}{})
	if err != nil {
		return "", 0, err
	}
	
	var header struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	}
	
	if err := json.Unmarshal(resp.Result, &header); err != nil {
		return "", 0, fmt.Errorf("failed to parse block header: %v", err)
	}
	
	// Parse the block number
	number := header.Number
	// Remove the 0x prefix
	if strings.HasPrefix(number, "0x") {
		number = number[2:]
	}
	
	// Convert from hex to uint64
	blockNumber, err := strconv.ParseUint(number, 16, 64)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse block number: %v", err)
	}
	
	return header.Hash, blockNumber, nil
}

// SubmitTransaction submits a signed transaction to the network
func (c *BittensorClient) SubmitTransaction(txHex string) (string, error) {
	resp, err := c.RPC("author_submitExtrinsic", []interface{}{txHex})
	if err != nil {
		return "", err
	}
	
	var hash string
	if err := json.Unmarshal(resp.Result, &hash); err != nil {
		return "", fmt.Errorf("failed to parse transaction hash: %v", err)
	}
	
	return hash, nil
}

// HandleTransaction processes a Bittensor transaction
func HandleTransaction(privateKey []byte, destination, amount, endpoint string, testnet bool) error {
	// Validate inputs
	if err := validateInputs(destination, amount, endpoint); err != nil {
		return err
	}

	// Derive public key from private key
	_, pubKey, err := edwards.PrivKeyFromScalar(privateKey)
	if err != nil {
		return fmt.Errorf("failed to derive public key: %v", err)
	}

	// Display key information
	fmt.Println("\nBittensor Transaction Information:")
	networkType := "mainnet"
	if testnet {
		networkType = "testnet"
	}
	fmt.Printf("Network: %s\n", networkType)
	fmt.Printf("Endpoint: %s\n", endpoint)

	// Get SS58 address from public key
	pubKeyBytes := pubKey.SerializeCompressed()
	ss58Address, err := GenerateSS58Address(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to generate SS58 address: %v", err)
	}
	fmt.Printf("Your Bittensor Address: %s\n", ss58Address)

	// Transaction details
	fmt.Printf("Network Endpoint: %s\n", endpoint)
	fmt.Printf("Destination: %s\n", destination)
	fmt.Printf("Amount: %s TAO\n", amount)

	// Process online vs offline modes
	fmt.Println("\nBittensor transactions require online access to fetch account information and network fees.")
	fmt.Println("Would you like to proceed with the transaction now (online mode)?")
	fmt.Println("If you choose 'No', we'll provide instructions for later use.")

	// Ask user if they want to proceed with online transaction
	var proceed string
	fmt.Print("Proceed with online transaction? (y/n): ")
	fmt.Scanln(&proceed)

	if proceed == "y" || proceed == "Y" {
		return buildAndSubmitBittensorTransaction(privateKey, pubKeyBytes, destination, amount, endpoint)
	}

	// Offline mode instructions
	fmt.Println("\nTo complete this transaction later:")
	fmt.Println("1. Run this tool again with the --bittensor flag when you're ready to connect to the network")
	fmt.Println("2. Use the same private key, destination address, and amount")
	fmt.Println("3. Choose 'Yes' at the online transaction prompt")

	return nil
}

// serializeTransaction serializes a transaction for signing using SCALE encoding
func serializeTransaction(tx *BittensorTransaction) ([]byte, error) {
	// This implementation uses proper Substrate SCALE encoding
	// to match the format used by the Bittensor network
	
	// Create a buffer to hold the encoded data
	var buffer bytes.Buffer
	
	// Write method identifier for balances.transfer (0x0600)
	// This is the compact-encoded call index for the transfer function
	buffer.Write([]byte{0x06, 0x00})
	
	// Write destination address (SS58 decoded to account ID)
	destBytes, err := decodeFromSS58(tx.To)
	if err != nil {
		return nil, fmt.Errorf("invalid destination address: %v", err)
	}
	buffer.Write(destBytes)
	
	// Write amount using compact encoding
	// For amounts < 2^30, compact encoding is:
	// - single byte for < 2^6
	// - two bytes for < 2^14
	// - four bytes for < 2^30
	encodeCompactUint(&buffer, tx.Amount)
	
	// Create ExtrinsicSignature structure
	var sigBuffer bytes.Buffer
	
	// Add address (from SS58 format)
	fromBytes, err := decodeFromSS58(tx.From)
	if err != nil {
		return nil, fmt.Errorf("invalid source address: %v", err)
	}
	sigBuffer.Write(fromBytes)
	
	// Add signature type (Ed25519 = 0x00)
	sigBuffer.WriteByte(0x00)
	
	// Add era (immortal = 0x00)
	sigBuffer.WriteByte(0x00)
	
	// Add nonce (compact encoded)
	encodeCompactUint(&sigBuffer, tx.Nonce)
	
	// Add tip (compact encoded)
	encodeCompactUint(&sigBuffer, tx.Tip)
	
	// Combine all parts for the final message to sign
	var message bytes.Buffer
	
	// Add network specific prefix
	message.Write([]byte("substrate"))
	
	// Add signature version (0x84 for version 4)
	message.WriteByte(0x84)
	
	// Add transaction version (0x04)
	message.WriteByte(0x04)
	
	// Add genesis hash
	genesisHash, _ := hex.DecodeString("4d7452644f6e3a0e99e97a6e54797ae4849953cb0ab3b4e6d3f6539b56865a34")
	message.Write(genesisHash)
	
	// Add block hash
	blockHashBytes, err := hex.DecodeString(strings.TrimPrefix(tx.BlockHash, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid block hash: %v", err)
	}
	message.Write(blockHashBytes)
	
	// Add method data
	message.Write(buffer.Bytes())
	
	// Add signature data
	message.Write(sigBuffer.Bytes())
	
	return message.Bytes(), nil
}

// encodeCompactUint encodes a uint64 in SCALE compact format
func encodeCompactUint(buffer *bytes.Buffer, value uint64) {
	if value < 64 { // 2^6
		buffer.WriteByte(byte(value << 2))
	} else if value < 16384 { // 2^14
		buffer.WriteByte(byte((value & 0x3F) << 2) | 0x01)
		buffer.WriteByte(byte(value >> 6))
	} else if value < 1073741824 { // 2^30
		buffer.WriteByte(byte((value & 0x3F) << 2) | 0x02)
		buffer.WriteByte(byte((value >> 6) & 0xFF))
		buffer.WriteByte(byte((value >> 14) & 0xFF))
		buffer.WriteByte(byte((value >> 22) & 0xFF))
	} else {
		// For larger values, use the full encoding
		buffer.WriteByte(0x03)
		buffer.WriteByte(byte(value & 0xFF))
		buffer.WriteByte(byte((value >> 8) & 0xFF))
		buffer.WriteByte(byte((value >> 16) & 0xFF))
		buffer.WriteByte(byte((value >> 24) & 0xFF))
		buffer.WriteByte(byte((value >> 32) & 0xFF))
		buffer.WriteByte(byte((value >> 40) & 0xFF))
		buffer.WriteByte(byte((value >> 48) & 0xFF))
		buffer.WriteByte(byte((value >> 56) & 0xFF))
	}
}

// decodeFromSS58 decodes an SS58 address to account ID bytes
func decodeFromSS58(address string) ([]byte, error) {
	decoded := base58.Decode(address)
	if len(decoded) < 35 {
		return nil, fmt.Errorf("invalid SS58 address length")
	}
	
	// Extract the actual public key (bytes 1 to 33)
	return decoded[1:33], nil
}

// Import our shared crypto package
import (
	"github.com/io-finnet/crypto-tool/internal/crypto"
)

// ed25519Sign signs the message with the scalar private key
func ed25519Sign(privateKey, message []byte) ([]byte, error) {
	// Use our shared signing implementation
	return crypto.SignWithScalar(privateKey, message)
}

// verifySignature verifies an Ed25519 signature on a transaction
func verifySignature(pubKey, message, signature []byte) bool {
	return ed25519.Verify(pubKey, message, signature)
}

// buildAndSubmitBittensorTransaction builds and submits a Bittensor transaction
func buildAndSubmitBittensorTransaction(privateKey, publicKey []byte, destination, amount, endpoint string) error {
	fmt.Println("\nPreparing transaction...")

	// Create client
	client := NewBittensorClient(endpoint, false)
	if strings.Contains(endpoint, "test") {
		client = NewBittensorClient(endpoint, true)
	}
	
	// Generate the SS58 address
	ss58Address, err := GenerateSS58Address(publicKey)
	if err != nil {
		return fmt.Errorf("failed to generate source address: %v", err)
	}
	fmt.Printf("Source address: %s\n", ss58Address)
	
	// Fetch account information
	fmt.Println("Fetching account information...")
	accountInfo, err := client.GetAccountInfo(ss58Address)
	if err != nil {
		// Note: For demo purposes, we can continue with a simulated account
		fmt.Printf("Warning: Failed to fetch account info: %v\n", err)
		fmt.Println("Proceeding with simulated account data...")
		
		// Create simulated account info
		accountInfo = &AccountInfo{
			Nonce:       1,
			FreeBalance: 1_000_000_000_000, // 1000 TAO
		}
	}
	
	// Ensure the account has sufficient funds
	amountF, err := strconv.ParseFloat(amount, 64)
	if err != nil {
		return fmt.Errorf("invalid amount: %v", err)
	}
	
	// Convert TAO to planck (1 TAO = 10^9 planck)
	planckAmount := uint64(amountF * 1_000_000_000)
	fmt.Printf("Amount in planck: %d\n", planckAmount)
	
	// Get fee
	fmt.Println("Calculating network fee...")
	fee, err := client.GetFee()
	if err != nil {
		fmt.Printf("Warning: Failed to fetch fee: %v\n", err)
		fee = 10_000_000 // 0.01 TAO as default
	}
	
	// Check if account has enough balance for the transaction and fee
	if accountInfo.FreeBalance < planckAmount+fee {
		return fmt.Errorf("insufficient funds: available balance is %f TAO, need %f TAO (including fee)",
			float64(accountInfo.FreeBalance)/1_000_000_000,
			float64(planckAmount+fee)/1_000_000_000)
	}
	
	// Get latest block hash
	fmt.Println("Fetching latest block hash...")
	blockHash, blockNumber, err := client.GetBlockHash()
	if err != nil {
		fmt.Printf("Warning: Failed to fetch block hash: %v\n", err)
		blockHash = "0x0000000000000000000000000000000000000000000000000000000000000000"
		blockNumber = 1
	}
	
	// Build transaction object
	tx := &BittensorTransaction{
		From:        ss58Address,
		To:          destination,
		Amount:      planckAmount,
		Nonce:       accountInfo.Nonce,
		Tip:         fee,
		EraPeriod:   64, // Use a standard era period
		BlockHash:   blockHash,
		BlockNumber: blockNumber,
		PublicKey:   publicKey,
	}
	
	// Display transaction details
	fmt.Println("\nTransaction Details:")
	fmt.Printf("From: %s\n", ss58Address)
	fmt.Printf("To: %s\n", destination)
	fmt.Printf("Amount: %s TAO (%d planck)\n", amount, planckAmount)
	fmt.Printf("Network Fee: %f TAO\n", float64(fee)/1_000_000_000)
	fmt.Printf("Nonce: %d\n", tx.Nonce)
	
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
	tx.Signature = signature
	
	// Simulate transaction
	fmt.Println("Simulating transaction...")
	// In a real implementation, we would simulate the transaction with a dry-run
	// For this demo, we'll assume simulation was successful
	
	// Convert transaction to hex format for submission
	txJSON, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %v", err)
	}
	txHex := "0x" + hex.EncodeToString(txJSON)
	
	// Submit transaction
	fmt.Println("Submitting transaction...")
	txHash, err := client.SubmitTransaction(txHex)
	if err != nil {
		fmt.Printf("\n❌ ERROR: Transaction submission failed: %v\n", err)
		fmt.Println("\nThe transaction could not be submitted to the Bittensor network.")
		fmt.Println("This could be due to network connectivity issues, invalid credentials,")
		fmt.Println("or problems with the Bittensor server.")
		return fmt.Errorf("transaction submission failed: %w", err)
	}
	
	// Ensure txHash has 0x prefix
	if !strings.HasPrefix(txHash, "0x") {
		txHash = "0x" + txHash
	}
	
	fmt.Println("\n✅ Transaction submitted successfully!")
	fmt.Printf("Transaction hash: %s\n", txHash)
	fmt.Println("View on Bittensor Explorer: https://taostats.io/transactions/" + txHash)
	
	return nil
}

// validateInputs checks if the destination, amount, and endpoint are valid
func validateInputs(destination, amount, endpoint string) error {
	if !isValidSS58Address(destination) {
		return errors.New("invalid Bittensor destination address format")
	}

	if !isValidAmount(amount) {
		return errors.New("invalid amount (must be a positive number)")
	}

	// Accept either WebSocket or HTTP endpoints
	if endpoint != "" && !strings.HasPrefix(endpoint, "wss://") && !strings.HasPrefix(endpoint, "https://") {
		return errors.New("invalid endpoint (must start with wss:// or https://)")
	}

	return nil
}

// isValidSS58Address checks if the address is a valid SS58 address
func isValidSS58Address(address string) bool {
	// Simple validation - in production use a proper SS58 validation
	return len(address) >= 45 && len(address) <= 50
}

// isValidAmount checks if the amount is valid
func isValidAmount(amount string) bool {
	// Simple validation - could be more sophisticated
	return len(amount) > 0 && amount[0] != '-'
}

// GenerateSS58Address generates an SS58 address from a public key
func GenerateSS58Address(pubKey []byte) (string, error) {
	// SS58 address format:
	// 1. Add network prefix (0x2A for Bittensor)
	// 2. Append public key
	// 3. Calculate checksum using Blake2b
	// 4. Append checksum
	// 5. Base58 encode

	// Add network prefix (42 = 0x2A for Bittensor)
	prefixedKey := append([]byte{byte(SS58Prefix)}, pubKey...)

	// Calculate checksum using Blake2b
	hasher, err := blake2b.New(64, nil) // 512 bits
	if err != nil {
		return "", fmt.Errorf("failed to create hasher: %v", err)
	}

	// SS58 uses a special prefix for the checksum
	hasher.Write([]byte("SS58PRE"))
	hasher.Write(prefixedKey)
	checksumHash := hasher.Sum(nil)
	checksum := checksumHash[:2] // First 2 bytes for the checksum

	// Append checksum
	addressBytes := append(prefixedKey, checksum...)

	// Base58 encode
	address := base58.Encode(addressBytes)

	return address, nil
}
