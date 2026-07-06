// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package dr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

// kemCapsuleSize is the fixed size in bytes of an ML-KEM-768 ciphertext capsule (NIST standard).
const kemCapsuleSize = 1088

// mlkem768SeedLen is the length in bytes of a raw ML-KEM-768 private key seed (FIPS 203).
const mlkem768SeedLen = 64

// oidMLKEM768 is the ML-KEM-768 algorithm identifier (RFC 9935 / NIST CSOR
// 2.16.840.1.101.3.4.4.2). OpenSSL 3.5+'s `genpkey -algorithm ML-KEM-768`
// (and RFC 9935-compliant tooling generally) wraps the raw 64-byte seed in a
// standard PKCS#8 PrivateKeyInfo DER structure using this OID.
var oidMLKEM768 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}

type mlkemAlgorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

type mlkemPKCS8PrivateKeyInfo struct {
	Version    int
	Algo       mlkemAlgorithmIdentifier
	PrivateKey []byte
}

// parseMLKEM768PrivateKeyPKCS8 unwraps a standard PKCS#8 PrivateKeyInfo DER
// structure (RFC 9935) to recover the raw 64-byte ML-KEM-768 seed.
func parseMLKEM768PrivateKeyPKCS8(der []byte) ([]byte, error) {
	var info mlkemPKCS8PrivateKeyInfo
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#8 structure: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after PKCS#8 structure")
	}
	if !info.Algo.Algorithm.Equal(oidMLKEM768) {
		return nil, fmt.Errorf("unexpected algorithm OID %v, expected ML-KEM-768 (%v)", info.Algo.Algorithm, oidMLKEM768)
	}
	if len(info.PrivateKey) != mlkem768SeedLen {
		return nil, fmt.Errorf("unexpected private key length %d, expected a %d-byte seed", len(info.PrivateKey), mlkem768SeedLen)
	}
	return info.PrivateKey, nil
}

// DecryptFile decrypts a Virtual Signer ".dr" file's raw bytes using the ML-KEM-768 private key PEM.
// Wire format: [1088-byte ML-KEM ciphertext][AES-256-GCM nonce(12) + ciphertext + tag].
func DecryptFile(pemBytes, raw []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse private key PEM")
	}
	seed, err := parseMLKEM768PrivateKeyPKCS8(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM-768 private key PEM: %w", err)
	}
	decapsulationKey, err := mlkem.NewDecapsulationKey768(seed)
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
