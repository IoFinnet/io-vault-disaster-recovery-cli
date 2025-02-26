// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package bittensor

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"golang.org/x/crypto/blake2b"
)

// Constants for Bittensor
const (
	SS58Prefix = 42 // Bittensor network prefix
)

// HandleTransaction processes a BitTensor transaction
func HandleTransaction(privateKey []byte, destination, amount, endpoint string) error {
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

	// Get SS58 address from public key
	ss58Address, err := GenerateSS58Address(pubKey.SerializeCompressed())
	if err != nil {
		return fmt.Errorf("failed to generate SS58 address: %v", err)
	}
	fmt.Printf("Your Bittensor Address: %s\n", ss58Address)

	// Transaction details
	fmt.Printf("Network Endpoint: %s\n", endpoint)
	fmt.Printf("Destination: %s\n", destination)
	fmt.Printf("Amount: %s TAO\n", amount)

	// Instructions for manual transaction
	fmt.Println("\nTo complete this transaction:")
	fmt.Println("1. Use the Bittensor tool in scripts/bittensor-tool/")
	fmt.Println("2. Import your private key")
	fmt.Println("3. Enter the destination address and amount")
	fmt.Println("4. Submit the transaction")

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

	if !strings.HasPrefix(endpoint, "wss://") {
		return errors.New("invalid endpoint (must start with wss://)")
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
