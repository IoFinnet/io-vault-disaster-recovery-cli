// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package xrpl

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/rubblelabs/ripple/data"
	"github.com/rubblelabs/ripple/websockets"
	"golang.org/x/crypto/ripemd160"
)

// Constants for XRPL
const (
	AccountIDPrefix  byte = 0x00
	FamilySeedPrefix byte = 0x21 // 's' in XRPL's base58 encoding
)

// HandleTransaction processes an XRPL transaction
func HandleTransaction(privateKey []byte, destination, amount string, testnet bool) error {
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
		return buildAndSubmitXRPLTransaction(privateKey, pubKeyBytes, destination, amount, testnet)
	}

	// Offline mode instructions
	fmt.Println("\nTo complete this transaction later:")
	fmt.Println("1. Run this tool again with the --xrpl flag when you're ready to connect to the network")
	fmt.Println("2. Use the same private key, destination address, and amount")
	fmt.Println("3. Choose 'Yes' at the online transaction prompt")

	return nil
}

// buildAndSubmitXRPLTransaction builds and submits an XRPL transaction
func buildAndSubmitXRPLTransaction(privateKey, publicKey []byte, destination, amount string, testnet bool) error {
	fmt.Println("\nPreparing transaction...")

	// Use XRPL libraries for transaction building

	// Connect to XRPL network
	var endpoint string
	if testnet {
		endpoint = "wss://s.altnet.rippletest.net:51233"
		fmt.Println("Connecting to XRPL testnet...")
	} else {
		endpoint = "wss://s1.ripple.com:51233"
		fmt.Println("Connecting to XRPL mainnet...")
	}

	// Derive the source address from the public key
	sourceAddress := pubKeyToAddress(publicKey)
	fmt.Printf("Source address: %s\n", sourceAddress)

	// Connect to the XRP Ledger WebSocket API
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	r, err := websockets.NewRemote(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to XRPL: %v", err)
	}
	defer r.Close()

	fmt.Println("Fetching account information...")

	// Get account info for sequence number
	accountInfo, err := r.AccountInfo(ctx, sourceAddress)
	if err != nil {
		return fmt.Errorf("failed to get account info: %v", err)
	}

	// Get fee information
	fees, err := r.Fee(ctx)
	if err != nil {
		return fmt.Errorf("failed to get fee info: %v", err)
	}
	feeCost := fees.Drops.OpenLedgerFee
	fmt.Printf("Current transaction fee: %s drops\n", feeCost)

	// Parse amount
	amountFloat, err := strconv.ParseFloat(amount, 64)
	if err != nil {
		return fmt.Errorf("invalid amount: %v", err)
	}
	
	// Convert to drops (1 XRP = 1,000,000 drops)
	dropsAmount := uint64(amountFloat * 1000000)
	
	// Build payment transaction
	payment := &data.Payment{
		Destination: data.Account(destination),
		Amount:      data.Amount{Value: data.Native(dropsAmount)},
	}

	base := data.TxBase{
		TransactionType: data.PAYMENT,
		Account:         data.Account(sourceAddress),
		Fee:             data.Amount{Value: *feeCost},
		Sequence:        *accountInfo.AccountData.Sequence,
		LastLedgerSequence: data.UInt32(accountInfo.LedgerSequence + 4),
	}
	payment.TxBase = base

	// Display transaction details
	fmt.Println("\nTransaction Details:")
	fmt.Printf("From: %s\n", sourceAddress)
	fmt.Printf("To: %s\n", destination)
	fmt.Printf("Amount: %s XRP\n", amount)
	fmt.Printf("Fee: %s drops\n", feeCost)
	fmt.Printf("Network: %s\n", networkName(testnet))
	
	// Ask for confirmation
	var confirm string
	fmt.Print("\nConfirm transaction? (y/n): ")
	fmt.Scanln(&confirm)
	
	if confirm != "y" && confirm != "Y" {
		fmt.Println("Transaction cancelled.")
		return nil
	}
	
	// Sign the transaction
	fmt.Println("Signing transaction...")
	
	// The following code is specialized for Ed25519 signing:
	txJson, err := payment.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize transaction: %v", err)
	}
	
	// Create a sha512 hash of the transaction
	txHash := sha512.Sum512(txJson)
	
	// Generate signature
	signature, err := ed25519Sign(privateKey, txHash[:])
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %v", err)
	}
	
	// Set the signature and public key in the transaction
	payment.SigningPubKey = data.VariableLength(publicKey)
	payment.TxnSignature = data.VariableLength(signature)
	
	// Submit transaction
	fmt.Println("Submitting transaction...")
	submitResponse, err := r.Submit(ctx, payment)
	if err != nil {
		return fmt.Errorf("failed to submit transaction: %v", err)
	}
	
	// Process the response
	if submitResponse.EngineResult != "tesSUCCESS" {
		return fmt.Errorf("transaction submission failed: %s - %s", 
			submitResponse.EngineResult, submitResponse.EngineResultMessage)
	}
	
	// Get the transaction hash
	txHash, err := payment.Hash()
	if err != nil {
		return fmt.Errorf("failed to get transaction hash: %v", err)
	}
	transactionHash := txHash.String()
	
	fmt.Println("\nTransaction successful!")
	fmt.Printf("Transaction hash: %s\n", transactionHash)
	if testnet {
		fmt.Printf("View on XRPL Testnet Explorer: https://testnet.xrpl.org/transactions/%s\n", transactionHash)
	} else {
		fmt.Printf("View on XRPL Explorer: https://livenet.xrpl.org/transactions/%s\n", transactionHash)
	}
	
	return nil
}

// ed25519Sign signs a message with an Ed25519 private key
func ed25519Sign(privateKey, message []byte) ([]byte, error) {
	// Convert our raw private key to the format expected by crypto/ed25519
	// First check if our privateKey is the right length for Ed25519
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("invalid private key length: %d", len(privateKey))
	}
	
	// Ed25519 expects a 64-byte private key that contains both private and public components
	pubKey, _, err := edwards.PrivKeyFromScalar(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive Ed25519 key: %v", err)
	}
	
	fullPrivKey := append(privateKey, pubKey.SerializeCompressed()...)
	
	// Sign the message
	signature := ed25519.Sign(fullPrivKey, message)
	return signature, nil
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
