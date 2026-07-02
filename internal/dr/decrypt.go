// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package dr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"encoding/pem"
	"fmt"
)

// kemCapsuleSize is the fixed size in bytes of an ML-KEM-768 ciphertext capsule (NIST standard).
const kemCapsuleSize = 1088

// DecryptFile decrypts a Virtual Signer ".dr" file's raw bytes using the ML-KEM-768 private key PEM.
// Wire format: [1088-byte ML-KEM ciphertext][AES-256-GCM nonce(12) + ciphertext + tag].
func DecryptFile(pemBytes, raw []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse private key PEM")
	}
	decapsulationKey, err := mlkem.NewDecapsulationKey768(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM-768 private key: %w", err)
	}
	if len(raw) <= kemCapsuleSize {
		return nil, fmt.Errorf("file is too small to contain a valid .dr payload")
	}
	cipherTextKEM, aesPayload := raw[:kemCapsuleSize], raw[kemCapsuleSize:]

	sharedSecret, err := decapsulationKey.Decapsulate(cipherTextKEM)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulation failed (wrong private key or corrupted file): %w", err)
	}

	blk, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(aesPayload) < nonceSize {
		return nil, fmt.Errorf(".dr AES payload is too short")
	}
	nonce, ciphertext := aesPayload[:nonceSize], aesPayload[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed (wrong private key or corrupted file): %w", err)
	}
	return plaintext, nil
}
