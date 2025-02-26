// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package solana

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

// Constants for Solana
const (
	SolanaAddressLength = 44 // Base58 encoded public key length
)

// HandleTransaction processes a Solana transaction
func HandleTransaction(privateKey []byte, destination, amount string) error {
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

	// Get Solana address from public key
	solanaAddress, err := DeriveSolanaAddress(pubKey.SerializeCompressed())
	if err != nil {
		return fmt.Errorf("failed to derive Solana address: %v", err)
	}
	fmt.Printf("Your Solana Address: %s\n", solanaAddress)

	// Transaction details
	fmt.Printf("Destination: %s\n", destination)
	fmt.Printf("Amount: %s SOL\n", amount)

	// Instructions for manual transaction
	fmt.Println("\nTo complete this transaction:")
	fmt.Println("(Warning! These scripts require that you go online to perform the transaction as live data must be fetched from the chain.)")
	fmt.Println("1. Install the Solana CLI or use a wallet like Phantom or Solflare")
	fmt.Println("2. Import your private key")
	fmt.Println("3. Create a transfer transaction to the destination address")
	fmt.Println("4. Submit the transaction")

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

// GetBase58EncodedPrivateKey returns the Base58 encoded private key
// This format is used by Phantom Wallet for private key import
func GetBase58EncodedPrivateKey(privateKey []byte) (string, error) {
	if len(privateKey) != 32 {
		return "", fmt.Errorf("invalid private key length: expected 32 bytes, got %d", len(privateKey))
	}
	
	// For Phantom Wallet, we need to encode the private key in the proper format
	// Solana wallets expect a 64-byte array where:
	// - First 32 bytes are the private key
	// - Second 32 bytes are the public key derived from the private key
	
	// Derive the public key from the private key
	_, pubKey, err := edwards.PrivKeyFromScalar(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to derive public key: %v", err)
	}
	
	// Combine private key and public key
	fullKeypair := append(privateKey, pubKey.SerializeCompressed()...)
	
	// Base58 encode the full keypair
	return base58.Encode(fullKeypair), nil
}
