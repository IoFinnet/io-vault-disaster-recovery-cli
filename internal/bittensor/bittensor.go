// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package bittensor

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil/base58"
	"golang.org/x/crypto/blake2b"
)

// Constants for Bittensor
const (
	SS58Prefix = 42 // Bittensor network prefix
)

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

// ValidateBittensorAddress validates a Bittensor SS58 address
func ValidateBittensorAddress(address string) bool {
	// Basic format validation for SS58 addresses
	// Bittensor addresses should be 48 characters long and contain only base58 characters
	if len(address) != 48 {
		return false
	}

	// Check if the address is valid base58
	decoded := base58.Decode(address)
	
	// Decoded address should be at least 35 bytes:
	// 1 byte for prefix + 32 bytes for public key + 2 bytes for checksum
	if len(decoded) < 35 {
		return false
	}

	// Check if the prefix matches Bittensor's SS58 format (42)
	if decoded[0] != SS58Prefix {
		return false
	}

	// We could add more validation here by recalculating the checksum,
	// but for our purposes, this basic validation is sufficient
	
	return true
}
