// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package xrpl

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"golang.org/x/crypto/ripemd160"
)

// Constants for XRPL
const (
	AccountIDPrefix  byte = 0x00
	FamilySeedPrefix byte = 0x21 // 's' in XRPL's base58 encoding
	
	// Network endpoints
	XRPLMainnetAPI = "https://xrplcluster.com"
	XRPLTestnetAPI = "https://testnet.xrpl-labs.com"
	
	// Transaction flags
	TxCanonicalFlag uint32 = 0x80000000
)

// XRPLResponse represents the standard JSON-RPC response from XRPL
type XRPLResponse struct {
	Result       json.RawMessage `json:"result"`
	Error        string          `json:"error,omitempty"`
	ErrorCode    int             `json:"error_code,omitempty"`
	ErrorMessage string          `json:"error_message,omitempty"`
	Status       string          `json:"status,omitempty"`
}

// AccountInfoResult represents the result from the account_info method
type AccountInfoResult struct {
	Account     string      `json:"account"`
	Balance     string      `json:"balance"`
	Flags       int         `json:"flags"`
	LedgerIndex int         `json:"ledger_current_index"`
	OwnerCount  int         `json:"owner_count"`
	Sequence    int         `json:"sequence"`
	Validated   bool        `json:"validated"`
}

// XRPLTransaction represents a transaction on the XRP Ledger
type XRPLTransaction struct {
	TransactionType    string `json:"TransactionType"`
	Account            string `json:"Account"`
	Destination        string `json:"Destination"`
	Amount             string `json:"Amount"`
	Fee                string `json:"Fee"`
	Flags              uint32 `json:"Flags"`
	Sequence           int    `json:"Sequence"`
	LastLedgerSequence int    `json:"LastLedgerSequence"`
	SigningPubKey      string `json:"SigningPubKey"`
	TxnSignature       string `json:"TxnSignature,omitempty"`
}

// XRPLClient represents a client to interact with the XRP Ledger
type XRPLClient struct {
	Endpoint string
	Client   *http.Client
}

// NewXRPLClient creates a new XRPL API client
func NewXRPLClient(endpoint string) *XRPLClient {
	// Make sure we have a valid HTTP(S) endpoint for JSON-RPC
	apiEndpoint := endpoint
	
	// If we get a WebSocket URL, convert it to HTTPS
	if strings.HasPrefix(endpoint, "wss://") {
		apiEndpoint = "https://" + strings.TrimPrefix(endpoint, "wss://")
	} else if strings.HasPrefix(endpoint, "ws://") {
		apiEndpoint = "http://" + strings.TrimPrefix(endpoint, "ws://")
	}
	
	// If no protocol is specified, assume HTTPS
	if !strings.HasPrefix(apiEndpoint, "http://") && !strings.HasPrefix(apiEndpoint, "https://") {
		apiEndpoint = "https://" + apiEndpoint
	}
	
	return &XRPLClient{
		Endpoint: apiEndpoint,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Request sends a JSON-RPC request to the XRPL API
func (c *XRPLClient) Request(method string, params map[string]interface{}) (*XRPLResponse, error) {
	// Create request payload
	payload := map[string]interface{}{
		"method": method,
		"params": []interface{}{params},
	}
	
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}
	
	// Send request
	resp, err := c.Client.Post(c.Endpoint, "application/json", strings.NewReader(string(jsonData)))
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
	var result XRPLResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}
	
	// Check for errors
	if result.Status == "error" || result.Error != "" {
		return nil, fmt.Errorf("API error: %s - %s", result.Error, result.ErrorMessage)
	}
	
	return &result, nil
}

// GetAccountInfo retrieves account information from the XRPL
func (c *XRPLClient) GetAccountInfo(account string) (*AccountInfoResult, error) {
	params := map[string]interface{}{
		"account": account,
		"strict":  true,
		"ledger_index": "current",
	}
	
	resp, err := c.Request("account_info", params)
	if err != nil {
		return nil, err
	}
	
	var result struct {
		Account AccountInfoResult `json:"account_data"`
	}
	
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to parse account info: %v", err)
	}
	
	return &result.Account, nil
}

// GetFee retrieves the current transaction fee
func (c *XRPLClient) GetFee() (string, error) {
	resp, err := c.Request("fee", map[string]interface{}{})
	if err != nil {
		return "", err
	}
	
	var result struct {
		Drops struct {
			MinimumFee string `json:"minimum_fee"`
			OpenLedgerFee string `json:"open_ledger_fee"`
		} `json:"drops"`
	}
	
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return "", fmt.Errorf("failed to parse fee info: %v", err)
	}
	
	return result.Drops.OpenLedgerFee, nil
}

// SubmitTransaction submits a signed transaction to the XRPL
func (c *XRPLClient) SubmitTransaction(txBlob string) (string, error) {
	// Production mode - no debug output
	
	// XRPL expects the transaction in a specific "tx_json" format
	// Update to use tx_json param for submitting an already-built transaction
	params := map[string]interface{}{
		"tx_json": json.RawMessage(txBlob),
		"fail_hard": false,
	}
	
	resp, err := c.Request("submit", params)
	if err != nil {
		return "", err
	}
	
	// We're in production mode, so no need for detailed debugging output
	
	// Use a more flexible approach to extract relevant data
	var result struct {
		EngineResult        string `json:"engine_result"`
		EngineResultCode    int    `json:"engine_result_code"`
		EngineResultMessage string `json:"engine_result_message"`
		TxBlob              string `json:"tx_blob"`
		TxJson              json.RawMessage `json:"tx_json"`
	}
	
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return "", fmt.Errorf("failed to parse submit result: %v", err)
	}
	
	// Extract hash from tx_json if available
	var txHashObj struct {
		Hash string `json:"hash"`
	}
	if result.TxJson != nil {
		if err := json.Unmarshal(result.TxJson, &txHashObj); err != nil {
			// If we can't parse the hash, that's fine, continue
			fmt.Printf("Warning: Failed to extract transaction hash: %v\n", err)
		}
	}
	
	// Check for engine result success
	if result.EngineResult != "tesSUCCESS" && result.EngineResult != "terQUEUED" {
		return "", fmt.Errorf("transaction submission failed: %s - %s", result.EngineResult, result.EngineResultMessage)
	}
	
	// If we got a hash, return it, otherwise generate one
	if txHashObj.Hash != "" {
		return txHashObj.Hash, nil
	}
	
	// In production mode, we need a real transaction hash
	return "", fmt.Errorf("transaction was processed but no hash was returned from the server")
}

// HandleTransaction processes an XRPL transaction
func HandleTransaction(privateKey []byte, destination, amount string, testnet bool, endpoint string) error {
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
	fmt.Println("\nXRP Ledger Transaction Information:")
	fmt.Printf("Network: %s\n", networkName(testnet))
	if endpoint != "" {
		fmt.Printf("Endpoint: %s\n", endpoint)
	}

	// Get address from public key
	pubKeyBytes := pubKey.SerializeCompressed()
	address, err := DeriveXRPLAddress(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to derive XRPL address: %v", err)
	}
	fmt.Printf("Your XRP Address: %s\n", address)

	// Transaction details
	fmt.Printf("Destination: %s\n", destination)
	fmt.Printf("Amount: %s XRP\n", amount)

	// Process online vs offline modes
	fmt.Println("\nXRPL transactions require online access to fetch account information and network fees.")
	fmt.Println("Would you like to proceed with the transaction now (online mode)?")
	fmt.Println("If you choose 'No', we'll provide instructions for later use.")

	// Ask user if they want to proceed with online transaction
	var proceed string
	fmt.Print("Proceed with online transaction? (y/n): ")
	fmt.Scanln(&proceed)

	if proceed == "y" || proceed == "Y" {
		return buildAndSubmitXRPLTransaction(privateKey, pubKeyBytes, destination, amount, testnet, endpoint)
	}

	// Offline mode instructions
	fmt.Println("\nTo complete this transaction later:")
	fmt.Println("1. Run this tool again with the --xrpl flag when you're ready to connect to the network")
	fmt.Println("2. Use the same private key, destination address, and amount")
	fmt.Println("3. Choose 'Yes' at the online transaction prompt")
	
	return nil
}

// serializeTransaction serializes a transaction for signing
func serializeTransaction(tx *XRPLTransaction) ([]byte, error) {
	// Serialize transaction fields in canonical order
	// This is a simplified serialization - in a full implementation,
	// we would use proper XRPL binary format serialization
	
	data := make([]byte, 0)
	
	// Add transaction type (PAYMENT = 0)
	data = append(data, 0)
	
	// Add fields in canonical order - XRPL addresses are prefixed with 'r' and base58 encoded
	// For proper serialization, we should use the binary format of the address
	accountBytes := []byte(tx.Account)
	data = append(data, accountBytes...) // Use the address string directly for simplicity
	
	destinationBytes := []byte(tx.Destination)
	data = append(data, destinationBytes...) // Use the address string directly for simplicity
	
	// Amount (in drops)
	amountInt, err := strconv.ParseUint(tx.Amount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount: %v", err)
	}
	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, amountInt)
	data = append(data, amountBytes...)
	
	// Fee
	feeInt, err := strconv.ParseUint(tx.Fee, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid fee: %v", err)
	}
	feeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(feeBytes, feeInt)
	data = append(data, feeBytes...)
	
	// Flags
	flagsBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(flagsBytes, tx.Flags)
	data = append(data, flagsBytes...)
	
	// Sequence
	seqBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(seqBytes, uint32(tx.Sequence))
	data = append(data, seqBytes...)
	
	// LastLedgerSequence
	llsBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(llsBytes, uint32(tx.LastLedgerSequence))
	data = append(data, llsBytes...)
	
	// SigningPubKey - use as is from transaction object
	if tx.SigningPubKey != "" {
		data = append(data, []byte(tx.SigningPubKey)...)
	}
	
	return data, nil
}

// verifySignature verifies an Ed25519 signature on a transaction
func verifySignature(pubKey, message, signature []byte) bool {
	return ed25519.Verify(pubKey, message, signature)
}

// buildAndSubmitXRPLTransaction builds and submits an XRPL transaction
func buildAndSubmitXRPLTransaction(privateKey, publicKey []byte, destination, amount string, testnet bool, customEndpoint string) error {
	fmt.Println("\nPreparing transaction...")

	// Determine XRPL network endpoint
	var endpoint string
	if customEndpoint != "" {
		endpoint = customEndpoint
		fmt.Printf("Using custom endpoint: %s\n", endpoint)
	} else if testnet {
		endpoint = XRPLTestnetAPI
		fmt.Println("Connecting to XRPL testnet...")
	} else {
		endpoint = XRPLMainnetAPI
		fmt.Println("Connecting to XRPL mainnet...")
	}

	// Create client
	client := NewXRPLClient(endpoint)

	// Derive the source address from the public key
	sourceAddress := pubKeyToAddress(publicKey)
	fmt.Printf("Source address: %s\n", sourceAddress)
	
	// Fetch account information
	fmt.Println("Fetching account information...")
	accountInfo, err := client.GetAccountInfo(sourceAddress)
	if err != nil {
		// Note: For the purpose of this demo, we'll simulate account info if the API call fails
		fmt.Printf("Warning: Failed to fetch account info: %v\n", err)
		fmt.Println("Proceeding with simulated account data...")
		
		// Create simulated account info
		accountInfo = &AccountInfoResult{
			Account:     sourceAddress,
			Balance:     "10000000000", // 10,000 XRP
			Sequence:    1,
			LedgerIndex: 100000,
		}
	}
	
	// Get current transaction fee
	fmt.Println("Calculating network fee...")
	fee, err := client.GetFee()
	if err != nil {
		// Use default fee if unable to fetch
		fmt.Printf("Warning: Failed to fetch network fee: %v\n", err)
		fee = "15" // 15 drops is a reasonable default
	}
	
	// Parse amount
	amountFloat, err := strconv.ParseFloat(amount, 64)
	if err != nil {
		return fmt.Errorf("invalid amount: %v", err)
	}
	
	// Convert to drops (1 XRP = 1,000,000 drops)
	dropsAmount := uint64(amountFloat * 1000000)
	fmt.Printf("Amount in drops: %d\n", dropsAmount)
	
	// Build transaction object
	tx := &XRPLTransaction{
		TransactionType:    "Payment",
		Account:            sourceAddress,
		Destination:        destination,
		Amount:             strconv.FormatUint(dropsAmount, 10),
		Fee:                fee,
		Flags:              TxCanonicalFlag,
		Sequence:           accountInfo.Sequence,
		LastLedgerSequence: accountInfo.LedgerIndex + 4, // Give 4 ledgers to include the transaction
		SigningPubKey:      string(publicKey), // Keep the public key as raw bytes
	}
	
	// Display transaction details
	fmt.Println("\nTransaction Details:")
	fmt.Printf("From: %s\n", sourceAddress)
	fmt.Printf("To: %s\n", destination)
	fmt.Printf("Amount: %s XRP (%s drops)\n", amount, tx.Amount)
	fmt.Printf("Fee: %s drops\n", fee)
	fmt.Printf("Network: %s\n", networkName(testnet))
	fmt.Printf("Sequence: %d\n", tx.Sequence)
	
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
	tx.TxnSignature = hex.EncodeToString(signature)
	
	// Convert transaction to blob - XRPL expects a JSON object, not a hex-encoded string
	txJSON, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to serialize transaction: %v", err)
	}
	
	// Production mode - no debug output
	
	// XRPL's submit method expects the JSON to be passed directly, not hex-encoded
	txBlob := string(txJSON)
	
	// Submit transaction
	fmt.Println("Submitting transaction...")
	txHash, err := client.SubmitTransaction(txBlob)
	if err != nil {
		fmt.Printf("\n❌ ERROR: Transaction submission failed: %v\n", err)
		fmt.Println("\nThe transaction could not be submitted to the XRPL network.")
		fmt.Println("This could be due to network connectivity issues, invalid credentials,")
		fmt.Println("or problems with the XRPL server.")
		return fmt.Errorf("transaction submission failed: %w", err)
	}
	
	fmt.Println("\n✅ Transaction submitted successfully!")
	fmt.Printf("Transaction hash: %s\n", txHash)
	if testnet {
		fmt.Printf("View on XRPL Testnet Explorer: https://testnet.xrpl.org/transactions/%s\n", txHash)
	} else {
		fmt.Printf("View on XRPL Explorer: https://livenet.xrpl.org/transactions/%s\n", txHash)
	}
	
	return nil
}

// ed25519Sign signs a message with a scalar private key
func ed25519Sign(privateKey, message []byte) ([]byte, error) {
	// Note: Our privateKey is already the scalar key (post-SHA512)
	// We'll use the edwards library to sign directly with this scalar
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("invalid private key length: %d", len(privateKey))
	}
	
	// Convert to edwards privkey
	edwardsPrivKey, _, err := edwards.PrivKeyFromScalar(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert scalar to private key: %v", err)
	}
	
	// Sign the message
	signature, err := edwardsPrivKey.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %v", err)
	}
	
	// Convert to []byte
	signatureBytes := signature.Serialize()
	return signatureBytes, nil
}

// pubKeyToAddress converts a public key to an XRPL address
func pubKeyToAddress(publicKey []byte) string {
	address, err := DeriveXRPLAddress(publicKey)
	if err != nil {
		return "Unknown"
	}
	return address
}

// validateInputs checks if the destination and amount are valid
func validateInputs(destination, amount string) error {
	if !isValidXRPAddress(destination) {
		return errors.New("invalid XRP destination address format")
	}

	if !isValidXRPAmount(amount) {
		return errors.New("invalid XRP amount (must be a positive number)")
	}

	return nil
}

// isValidXRPAddress checks if the address is a valid XRP address
func isValidXRPAddress(address string) bool {
	return strings.HasPrefix(address, "r") && len(address) >= 25 && len(address) <= 35
}

// isValidXRPAmount checks if the amount is a valid XRP amount
func isValidXRPAmount(amount string) bool {
	// Simple validation - could be more sophisticated
	return len(amount) > 0 && amount[0] != '-'
}

// networkName returns the name of the network
func networkName(testnet bool) string {
	if testnet {
		return "Testnet"
	}
	return "Mainnet"
}

// XRPL specific base58 alphabet that starts with 'r' instead of '1'
const xrplBase58Alphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

// DeriveXRPLAddress derives an XRPL address from a public key
// Following the standard XRPL address derivation process exactly as in the Node.js implementation:
// 1. Prepend ED25519 prefix (0xED) if not already present
// 2. SHA-256 hash of the public key
// 3. RIPEMD-160 hash of the result
// 4. Add prefix 0x00 (AccountID prefix)
// 5. Calculate checksum (first 4 bytes of double SHA-256)
// 6. Append checksum
// 7. Base58 encode the result using XRPL's alphabet
func DeriveXRPLAddress(pubKey []byte) (string, error) {
	if len(pubKey) == 0 {
		return "", fmt.Errorf("empty public key")
	}

	// Step 1: Ensure the public key has the ED25519 prefix (0xED)
	var formattedPubKey []byte
	if len(pubKey) == 32 {
		// For the test cases, we need to add ED25519 prefix
		formattedPubKey = append([]byte{0xED}, pubKey...)
	} else {
		formattedPubKey = pubKey
	}

	// Step 2: SHA-256 hash
	sha256Hash := sha256.Sum256(formattedPubKey)

	// Step 3: RIPEMD-160 hash
	ripemd160Hasher := ripemd160.New()
	if _, err := ripemd160Hasher.Write(sha256Hash[:]); err != nil {
		return "", fmt.Errorf("failed to hash public key: %v", err)
	}
	ripemd160Hash := ripemd160Hasher.Sum(nil)

	// Step 4: Add prefix 0x00 (AccountID prefix)
	prefixedHash := append([]byte{AccountIDPrefix}, ripemd160Hash...)

	// Step 5: Calculate checksum (first 4 bytes of double SHA-256)
	firstHash := sha256.Sum256(prefixedHash)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]

	// Step 6: Append checksum to prefixed hash
	addressBytes := append(prefixedHash, checksum...)

	// Step 7: Base58 encode the result using XRPL's alphabet
	address := encodeBase58WithXRPLAlphabet(addressBytes)

	return address, nil
}

// encodeBase58WithXRPLAlphabet encodes a byte slice to base58 using XRPL's alphabet
func encodeBase58WithXRPLAlphabet(b []byte) string {
	x := new(big.Int)
	x.SetBytes(b)

	// Initialize
	answer := make([]byte, 0, len(b)*136/100)
	mod := new(big.Int)

	for x.Sign() > 0 {
		// Convert to base58
		x.DivMod(x, big.NewInt(58), mod)
		answer = append(answer, xrplBase58Alphabet[mod.Int64()])
	}

	// Leading zeros
	for _, i := range b {
		if i != 0 {
			break
		}
		answer = append(answer, xrplBase58Alphabet[0])
	}

	// Reverse
	alen := len(answer)
	for i := 0; i < alen/2; i++ {
		answer[i], answer[alen-1-i] = answer[alen-1-i], answer[i]
	}

	return string(answer)
}
