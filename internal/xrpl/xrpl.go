// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package xrpl

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
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
	// For EdDSA keys, we need to ensure we're using the correct format
	pubKeyBytes := pubKey.SerializeCompressed()

	// Debug info about the key format
	fmt.Printf("Debug: Public key length: %d bytes\n", len(pubKeyBytes))
	fmt.Printf("Debug: Public key bytes: %x\n", pubKeyBytes)

	address, err := DeriveXRPLAddress(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to derive XRPL address: %v", err)
	}
	fmt.Printf("Your XRP Address: %s\n", address)

	// Transaction details
	fmt.Printf("Destination: %s\n", destination)
	fmt.Printf("Amount: %s XRP\n", amount)

	// Instructions for manual transaction
	fmt.Println("\nTo complete this transaction:")
	fmt.Println("(Warning! These scripts require that you go online to perform the transaction as live data must be fetched from the chain.)")
	fmt.Println("1. Install Node.js on your machine: https://nodejs.org")
	fmt.Println("2. In a terminal, go to scripts/xrpl-tool/ and run `npm start`")
	fmt.Println("3. Enter your eddsa key, the destination address and amount")
	fmt.Println("4. Submit the transaction")

	return nil
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

// GenerateFamilySeed converts a private key to XRPL's family seed format
func GenerateFamilySeed(privateKey []byte) (string, error) {
	if len(privateKey) == 0 {
		return "", fmt.Errorf("empty private key")
	}

	// Family seed format for XRPL:
	// 1. Add prefix 0x21 (FamilySeedPrefix)
	// 2. Base58 encode with checksum

	// Add prefix - use only first 16 bytes of private key for family seed
	prefixedKey := append([]byte{FamilySeedPrefix}, privateKey[:16]...)

	// Calculate checksum (first 4 bytes of double SHA-256)
	firstHash := sha256.Sum256(prefixedKey)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]

	// Append checksum
	seedBytes := append(prefixedKey, checksum...)

	// Base58 encode
	seed := base58.Encode(seedBytes)

	return seed, nil
}
