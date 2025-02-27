// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package bittensor

import (
	"crypto/ed25519"
	"testing"
	
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

func TestBittensorSerializeAndSignTransaction(t *testing.T) {
	// Create a mock valid scalar private key
	priv := make([]byte, 32)
	priv[0] = 1 // Set first byte to non-zero to avoid zero scalar error
	
	// Generate a public key from this private key
	_, pubKey, err := edwards.PrivKeyFromScalar(priv)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	
	// Serialize the public key
	pub := pubKey.SerializeCompressed()

	// Create a test transaction
	tx := &BittensorTransaction{
		From:        "5C4hrfjw9DjXZTzV3MwzrrAr9P1MJhSrvWGWqi1eSuyUpnhM",
		To:          "5DD6SqQQKMb4V4vPNvygqtYiYxPXB4kYz8yB2RgETGS3V6Zw",
		Amount:      1000000000, // 1 TAO
		Nonce:       1,
		Tip:         10000000, // 0.01 TAO
		EraPeriod:   64,
		BlockHash:   "0x0000000000000000000000000000000000000000000000000000000000000000",
		BlockNumber: 1,
		PublicKey:   pub,
	}

	// Serialize the transaction
	txBytes, err := serializeTransaction(tx)
	if err != nil {
		t.Fatalf("Failed to serialize transaction: %v", err)
	}

	// Sign the transaction
	signature, err := ed25519Sign(priv, txBytes)
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}

	// Verify the signature
	if !verifySignature(pub, txBytes, signature) {
		t.Fatalf("Signature verification failed")
	}
}

func TestGenerateSS58Address(t *testing.T) {
	// Generate a test key pair
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Generate SS58 address
	address, err := GenerateSS58Address(pub)
	if err != nil {
		t.Fatalf("Failed to generate SS58 address: %v", err)
	}

	// Check that the address is valid
	if !isValidSS58Address(address) {
		t.Fatalf("Generated address is invalid: %s", address)
	}
}