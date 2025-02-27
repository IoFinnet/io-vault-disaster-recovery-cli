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
