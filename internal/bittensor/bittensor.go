// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package bittensor

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/edwards/v2"
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
	// For simplicity, we'll return a placeholder SS58 address
	// In a production environment, you'd want to use a proper Substrate library

	// Simplified SS58 address generation - not actual implementation
	// In production, use a proper SS58 encoding library
	pubKeyHex := hex.EncodeToString(pubKey)
	return fmt.Sprintf("5%s", pubKeyHex[:40]), nil
}
