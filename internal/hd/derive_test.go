// Copyright (C) 2025 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package hd

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDerivationPath(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    []uint32
		expectError bool
		errorType   error
	}{
		// Valid paths
		{
			name:     "root path m",
			input:    "m",
			expected: []uint32{},
		},
		{
			name:     "root path m/",
			input:    "m/",
			expected: []uint32{},
		},
		{
			name:     "empty string",
			input:    "",
			expected: []uint32{},
		},
		{
			name:     "simple path m/0",
			input:    "m/0",
			expected: []uint32{0},
		},
		{
			name:     "path m/44/0/0",
			input:    "m/44/0/0",
			expected: []uint32{44, 0, 0},
		},
		{
			name:     "uppercase M",
			input:    "M/44/0/0",
			expected: []uint32{44, 0, 0},
		},
		{
			name:     "long path",
			input:    "m/44/60/0/0/0",
			expected: []uint32{44, 60, 0, 0, 0},
		},
		{
			name:     "max non-hardened index",
			input:    "m/2147483647",
			expected: []uint32{2147483647},
		},

		// Invalid paths - hardened
		{
			name:        "hardened with apostrophe",
			input:       "m/44'/0",
			expectError: true,
			errorType:   ErrHardenedDerivation,
		},
		{
			name:        "hardened with h",
			input:       "m/44h/0",
			expectError: true,
			errorType:   ErrHardenedDerivation,
		},
		{
			name:        "index >= 2^31",
			input:       "m/2147483648",
			expectError: true,
			errorType:   ErrHardenedDerivation,
		},

		// Invalid paths - format
		{
			name:        "missing m prefix",
			input:       "44/0/0",
			expectError: true,
			errorType:   ErrInvalidDerivationPath,
		},
		{
			name:        "invalid character",
			input:       "m/abc",
			expectError: true,
			errorType:   ErrInvalidDerivationPath,
		},
		{
			name:        "negative number (overflow)",
			input:       "m/-1",
			expectError: true,
			errorType:   ErrInvalidDerivationPath,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			indices, err := ParseDerivationPath(tc.input)

			if tc.expectError {
				require.Error(t, err)
				if tc.errorType != nil {
					assert.ErrorIs(t, err, tc.errorType)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, indices)
			}
		})
	}
}

func TestNewDeriver(t *testing.T) {
	t.Run("valid ECDSA key only", func(t *testing.T) {
		ecdsaSK := make([]byte, 32)
		deriver, err := NewDeriver(ecdsaSK, nil)
		require.NoError(t, err)
		assert.NotNil(t, deriver)
	})

	t.Run("valid EdDSA key only", func(t *testing.T) {
		eddsaSK := make([]byte, 32)
		deriver, err := NewDeriver(nil, eddsaSK)
		require.NoError(t, err)
		assert.NotNil(t, deriver)
	})

	t.Run("both keys valid", func(t *testing.T) {
		ecdsaSK := make([]byte, 32)
		eddsaSK := make([]byte, 32)
		deriver, err := NewDeriver(ecdsaSK, eddsaSK)
		require.NoError(t, err)
		assert.NotNil(t, deriver)
	})

	t.Run("invalid ECDSA key length", func(t *testing.T) {
		ecdsaSK := make([]byte, 31)
		_, err := NewDeriver(ecdsaSK, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ECDSA private key must be 32 bytes")
	})

	t.Run("invalid EdDSA key length", func(t *testing.T) {
		eddsaSK := make([]byte, 33)
		_, err := NewDeriver(nil, eddsaSK)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "EdDSA private key must be 32 bytes")
	})
}

func TestComputePublicKey_Secp256k1(t *testing.T) {
	// Known private key -> public key for secp256k1
	// Private key: 0x01
	privKey := make([]byte, 32)
	privKey[31] = 0x01

	pubKey, err := computePublicKey(privKey, AlgorithmECDSA, CurveSecp256k1)
	require.NoError(t, err)

	// For private key 1, the public key is the generator point G
	// Compressed: 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
	assert.Len(t, pubKey, 33)
	assert.Equal(t, byte(0x02), pubKey[0]) // Even y coordinate
	assert.Equal(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		hex.EncodeToString(pubKey))
}

func TestComputePublicKey_Edwards25519(t *testing.T) {
	// Test with a known Edwards25519 private key
	privKey, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")

	pubKey, err := computePublicKey(privKey, AlgorithmEDDSA, CurveEdwards25519)
	require.NoError(t, err)
	assert.Len(t, pubKey, 32)
}

func TestDeriveChildKey_RootPath(t *testing.T) {
	masterSK := make([]byte, 32)
	masterSK[31] = 0x01

	chainCode := make([]byte, 32)
	parentPubKey := make([]byte, 33)
	parentPubKey[0] = 0x02

	// Root path returns master key
	childSK, childPK, err := deriveChildKey(masterSK, chainCode, parentPubKey, []uint32{}, AlgorithmECDSA, CurveSecp256k1)
	require.NoError(t, err)
	assert.Equal(t, masterSK, childSK)
	assert.NotNil(t, childPK)
}

func TestDeriveChildKey_SingleLevel(t *testing.T) {
	// Use deterministic test values
	masterSK, _ := hex.DecodeString("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
	chainCode, _ := hex.DecodeString("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")

	// Compute parent public key from master SK
	parentPubKey, err := computePublicKey(masterSK, AlgorithmECDSA, CurveSecp256k1)
	require.NoError(t, err)

	// Derive at m/0
	childSK, childPK, err := deriveChildKey(masterSK, chainCode, parentPubKey, []uint32{0}, AlgorithmECDSA, CurveSecp256k1)
	require.NoError(t, err)
	require.NotNil(t, childSK)
	require.NotNil(t, childPK)

	// Verify child key is different from master
	assert.NotEqual(t, masterSK, childSK)
	assert.Len(t, childSK, 32)
	assert.Len(t, childPK, 33)
}

func TestDeriveChildKey_Consistency(t *testing.T) {
	masterSK, _ := hex.DecodeString("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
	chainCode, _ := hex.DecodeString("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")

	parentPubKey, err := computePublicKey(masterSK, AlgorithmECDSA, CurveSecp256k1)
	require.NoError(t, err)

	// Derive the same key 5 times, ensure consistent results
	var results [][]byte
	for i := 0; i < 5; i++ {
		childSK, childPK, err := deriveChildKey(masterSK, chainCode, parentPubKey, []uint32{44, 0, 0}, AlgorithmECDSA, CurveSecp256k1)
		require.NoError(t, err)
		results = append(results, append(childSK, childPK...))
	}

	for i := 1; i < len(results); i++ {
		assert.Equal(t, results[0], results[i], "Derivation %d should match derivation 0", i)
	}
}

func TestDeriveChildKey_HierarchicalPath(t *testing.T) {
	masterSK, _ := hex.DecodeString("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
	chainCode, _ := hex.DecodeString("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")

	parentPubKey, err := computePublicKey(masterSK, AlgorithmECDSA, CurveSecp256k1)
	require.NoError(t, err)

	// Derive at increasing depths
	paths := [][]uint32{
		{44},
		{44, 0},
		{44, 0, 0},
		{44, 0, 0, 0},
	}

	var prevSK []byte
	for i, path := range paths {
		childSK, _, err := deriveChildKey(masterSK, chainCode, parentPubKey, path, AlgorithmECDSA, CurveSecp256k1)
		require.NoError(t, err)

		if prevSK != nil {
			assert.NotEqual(t, prevSK, childSK, "Path depth %d should produce different key", i)
		}
		prevSK = childSK
	}
}

func TestDeriveAll_ECDSA(t *testing.T) {
	// Create a test deriver with known master keys
	masterECDSA, _ := hex.DecodeString("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")

	deriver, err := NewDeriver(masterECDSA, nil)
	require.NoError(t, err)

	// Create test records - we need a valid xpub for this
	// Using a test xpub structure (not a real one, just for format testing)
	// For real tests, we need to generate a matching xpub

	// For now, test that missing EdDSA key causes proper error
	records := []AddressRecord{
		{
			Address:   "test_eddsa",
			Xpub:      "xpub661MyMwAqRbcEfDLGwPuHzSC8rjZoxf5VN8hQ2M3WrdkC1YBT7ZNdVjxQ1RhVSJkxp8cX18QAvrLqswNzrS6h8SQqkTqaBdDYtbpE1unwma",
			Path:      "m/0",
			Algorithm: AlgorithmEDDSA,
			Curve:     CurveEdwards25519,
			Flags:     0,
		},
	}

	_, err = deriver.DeriveAll(records)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing master key")
}

func TestDeriveAll_InvalidAlgorithmCurve(t *testing.T) {
	masterECDSA := make([]byte, 32)
	deriver, _ := NewDeriver(masterECDSA, nil)

	records := []AddressRecord{
		{
			Address:   "test",
			Xpub:      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			Path:      "m/0",
			Algorithm: AlgorithmECDSA,
			Curve:     CurveEdwards25519, // Invalid combo
			Flags:     0,
		},
	}

	_, err := deriver.DeriveAll(records)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAlgorithmCurve)
}

func TestLeftPadTo32Bytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{"1 byte", []byte{0x01}, 32},
		{"16 bytes", make([]byte, 16), 32},
		{"32 bytes", make([]byte, 32), 32},
		{"33 bytes", make([]byte, 33), 32},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bigInt := new(big.Int).SetBytes(tc.input)
			result := leftPadTo32Bytes(bigInt)
			assert.Len(t, result, tc.expected)
		})
	}
}

func TestDeriveChildKey_EdDSA(t *testing.T) {
	// Test with EdDSA/Edwards25519 keys
	masterSK, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	chainCode := make([]byte, 32)
	for i := range chainCode {
		chainCode[i] = byte(i)
	}

	// Compute parent public key
	parentPubKey, err := computePublicKey(masterSK, AlgorithmEDDSA, CurveEdwards25519)
	require.NoError(t, err)
	assert.Len(t, parentPubKey, 32)

	// Derive child
	childSK, childPK, err := deriveChildKey(masterSK, chainCode, parentPubKey, []uint32{0}, AlgorithmEDDSA, CurveEdwards25519)
	require.NoError(t, err)
	assert.Len(t, childSK, 32)
	assert.Len(t, childPK, 32)
	assert.NotEqual(t, masterSK, childSK)
}

func TestDeriveChildKey_P256(t *testing.T) {
	// Test with P-256 curve
	masterSK, _ := hex.DecodeString("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
	chainCode := make([]byte, 32)
	for i := range chainCode {
		chainCode[i] = byte(i)
	}

	// Compute parent public key
	parentPubKey, err := computePublicKey(masterSK, AlgorithmECDSA, CurveP256)
	require.NoError(t, err)
	assert.Len(t, parentPubKey, 33) // Compressed P-256 key

	// Derive child
	childSK, childPK, err := deriveChildKey(masterSK, chainCode, parentPubKey, []uint32{0}, AlgorithmECDSA, CurveP256)
	require.NoError(t, err)
	assert.Len(t, childSK, 32)
	assert.Len(t, childPK, 33)
	assert.NotEqual(t, masterSK, childSK)
}

func TestDeriveChildKey_Schnorr(t *testing.T) {
	// Test Schnorr derivation (uses secp256k1 with ECDSA master key)
	masterSK, _ := hex.DecodeString("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
	chainCode := make([]byte, 32)
	for i := range chainCode {
		chainCode[i] = byte(i)
	}

	// Compute parent public key
	parentPubKey, err := computePublicKey(masterSK, AlgorithmSCHNORR, CurveSecp256k1)
	require.NoError(t, err)
	assert.Len(t, parentPubKey, 33)

	// Derive child - Schnorr uses same derivation as ECDSA on secp256k1
	childSK, childPK, err := deriveChildKey(masterSK, chainCode, parentPubKey, []uint32{86, 0, 0}, AlgorithmSCHNORR, CurveSecp256k1)
	require.NoError(t, err)
	assert.Len(t, childSK, 32)
	assert.Len(t, childPK, 33)
	assert.NotEqual(t, masterSK, childSK)
}

// TestXRPLVector tests against the known XRPL test vector from TSS tests
// xpub: xpub661MyMwAqRbcG9aErp1paHxw5LYRQd4t24d7CBReN2EeqynEr3uSSjfP6Jr1RgMYqEFzNPTGKsS96dAALutAnFpdhmVCgNxXW7cB5GVAWse
// path: m/0
// expected pubkey: DA65F1ED202CFF9216443248FABE11F48AC0B816CF049E557C059E806204BDEB
//
// Note: This test validates the derivation algorithm but requires the matching
// master private key to produce the exact expected public key. Without the
// master key, we can only verify that derivation produces valid keys.
func TestXRPLVector_Format(t *testing.T) {
	xpub := "xpub661MyMwAqRbcG9aErp1paHxw5LYRQd4t24d7CBReN2EeqynEr3uSSjfP6Jr1RgMYqEFzNPTGKsS96dAALutAnFpdhmVCgNxXW7cB5GVAWse"

	// Parse the xpub to verify format
	parsed, err := ParseXpub(xpub, CurveEdwards25519)
	require.NoError(t, err)

	// Chain code should be 32 bytes
	assert.Len(t, parsed.ChainCode, 32)

	// Public key should be 32 bytes for EdDSA (after stripping 0x00 prefix)
	assert.Len(t, parsed.PublicKey, 32)

	t.Logf("XRPL xpub chain code: %s", hex.EncodeToString(parsed.ChainCode))
	t.Logf("XRPL xpub public key: %s", strings.ToUpper(hex.EncodeToString(parsed.PublicKey)))
}
