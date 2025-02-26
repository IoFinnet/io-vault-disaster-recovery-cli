// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package xrpl

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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
	address, err := DeriveXRPLAddress(pubKey.SerializeCompressed())
	if err != nil {
		return fmt.Errorf("failed to derive XRPL address: %v", err)
	}
	fmt.Printf("Your XRP Address: %s\n", address)

	// Transaction details
	fmt.Printf("Destination: %s\n", destination)
	fmt.Printf("Amount: %s XRP\n", amount)

	// Instructions for manual transaction
	fmt.Println("\nTo complete this transaction:")
	fmt.Println("1. Use the XRPL tool in scripts/xrpl-tool/")
	fmt.Println("2. Import your private key")
	fmt.Println("3. Enter the destination address and amount")
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

// DeriveXRPLAddress derives an XRPL address from a public key
func DeriveXRPLAddress(pubKey []byte) (string, error) {
	// XRPL addresses use a specific algorithm:
	// 1. SHA-256 hash of the public key
	// 2. RIPEMD-160 hash of the result
	// 3. Add prefix 0x00
	// 4. Base58 encode with checksum
	
	// Step 1: SHA-256 hash
	sha256Hash := sha256.Sum256(pubKey)
	
	// Step 2: RIPEMD-160 hash
	ripemd160Hasher := ripemd160.New()
	if _, err := ripemd160Hasher.Write(sha256Hash[:]); err != nil {
		return "", fmt.Errorf("failed to hash public key: %v", err)
	}
	ripemd160Hash := ripemd160Hasher.Sum(nil)
	
	// Step 3: Add prefix 0x00 (AccountID prefix)
	prefixedHash := append([]byte{AccountIDPrefix}, ripemd160Hash...)
	
	// Step 4: Calculate checksum (first 4 bytes of double SHA-256)
	firstHash := sha256.Sum256(prefixedHash)
	secondHash := sha256.Sum256(firstHash[:])
	checksum := secondHash[:4]
	
	// Append checksum to prefixed hash
	addressBytes := append(prefixedHash, checksum...)
	
	// Base58 encode
	address := "r" + base58.Encode(addressBytes)
	
	return address, nil
}

// GenerateFamilySeed converts a private key to XRPL's family seed format
func GenerateFamilySeed(privateKey []byte) (string, error) {
	// Family seed format for XRPL:
	// 1. Add prefix 0x21 (FamilySeedPrefix)
	// 2. Base58 encode with checksum
	
	// Add prefix
	prefixedKey := append([]byte{FamilySeedPrefix}, privateKey[:16]...) // Use only first 16 bytes
	
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
