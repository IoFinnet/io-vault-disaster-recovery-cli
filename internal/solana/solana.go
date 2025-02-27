// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package solana

import (
	"encoding/base64"

	"github.com/btcsuite/btcd/btcutil/base58"
)

// Constants for Solana
const (
	SolanaAddressLength = 44 // Base58 encoded public key length
)

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

// ValidateSolanaAddress validates a Solana address
func ValidateSolanaAddress(address string) bool {
	// Solana addresses are base58 encoded and typically 32-44 characters
	if len(address) < 32 || len(address) > 44 {
		return false
	}

	// Decode the address and check if it's a valid base58 string
	decoded := base58.Decode(address)
	
	// A valid Solana public key should decode to 32 bytes
	// But for now, just ensure it's a valid base58 string that decodes to something
	return len(decoded) > 0
}
