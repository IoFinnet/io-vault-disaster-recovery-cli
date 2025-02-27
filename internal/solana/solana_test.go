// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package solana

import (
	"crypto/ed25519"
	"testing"
	
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

func TestSolanaTransactionSerializationAndSigning(t *testing.T) {
	// Create a mock valid scalar private key
	priv := make([]byte, 32)
	priv[0] = 1 // Set first byte to non-zero to avoid zero scalar error
	
	// Generate a public key from this private key
	_, edPub, err := edwards.PrivKeyFromScalar(priv)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	
	// Serialize the public key
	pub := edPub.SerializeCompressed()

	// Derive Solana address from public key
	sourceAddress, err := DeriveSolanaAddress(pub)
	if err != nil {
		t.Fatalf("Failed to derive source address: %v", err)
	}

	// Create a test transfer instruction
	instruction := createTransferInstruction(
		sourceAddress,
		"9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", // Arbitrary destination
		1000000000,                                      // 1 SOL
	)

	// Build transaction
	tx := &SolanaTransaction{
		RecentBlockhash: "11111111111111111111111111111111",
		FeePayer:        sourceAddress,
		Instructions:    []SolanaTransactionInstruction{instruction},
	}

	// Serialize transaction for signing
	txBytes, err := serializeTransaction(tx)
	if err != nil {
		t.Fatalf("Failed to serialize transaction: %v", err)
	}

	// Sign the transaction
	signature, err := ed25519Sign(priv, txBytes)
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}

	// Verify signature
	if !verifySignature(pub, txBytes, signature) {
		t.Fatalf("Signature verification failed")
	}
}

func TestSolanaAddressDerivation(t *testing.T) {
	// Generate a test key pair
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Derive Solana address
	address, err := DeriveSolanaAddress(pub)
	if err != nil {
		t.Fatalf("Failed to derive Solana address: %v", err)
	}

	// Check that the address is valid
	if !isValidSolanaAddress(address) {
		t.Fatalf("Generated address is invalid: %s", address)
	}
}

func TestSolanaKeyPairString(t *testing.T) {
	// Generate a test key pair
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Generate keypair string
	keypairStr, err := GenerateKeyPairString(priv.Seed(), pub)
	if err != nil {
		t.Fatalf("Failed to generate keypair string: %v", err)
	}

	// Check that keypair string is not empty
	if keypairStr == "" {
		t.Fatalf("Generated keypair string is empty")
	}
}