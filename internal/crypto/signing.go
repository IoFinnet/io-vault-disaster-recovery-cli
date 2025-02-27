// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package crypto

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"

	"github.com/decred/dcrd/dcrec/edwards/v2"
)

// SignWithScalar signs a message using an Ed25519 private key scalar
// This function ensures consistent signing behavior across all blockchain implementations
func SignWithScalar(privateKey, message []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("invalid private key length: %d", len(privateKey))
	}

	// Convert to edwards privkey
	edwardsPrivKey, publicKey, err := edwards.PrivKeyFromScalar(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert scalar to private key: %v", err)
	}

	// Get the public key bytes
	pubKeyBytes := publicKey.SerializeCompressed()

	// Standard Ed25519 signing process:
	// 1. Hash the private key to derive the secret scalar and prefix
	h := sha512.Sum512(privateKey)
	prefix := h[:32]

	// 2. Derive deterministic nonce from prefix and message
	nonceData := append(prefix, message...)
	nonceHash := sha512.Sum512(nonceData)

	// 3. Sign the message using the edwards library
	signature, err := edwardsPrivKey.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %v", err)
	}

	// 4. Verify the signature
	if !ed25519.Verify(pubKeyBytes, message, signature.Serialize()) {
		return nil, fmt.Errorf("signature verification failed")
	}

	return signature.Serialize(), nil
}

// VerifySignature verifies an Ed25519 signature
func VerifySignature(publicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}
