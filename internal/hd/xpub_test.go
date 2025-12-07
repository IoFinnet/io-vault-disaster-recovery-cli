// Copyright (C) 2025 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package hd

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Known test xpubs from TSS tests
const (
	// Standard BIP32 xpub for ECDSA (secp256k1)
	// From Bitcoin test vectors
	testXpubECDSA = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

	// EdDSA xpub from XRPL test vector
	testXpubEdDSA = "xpub661MyMwAqRbcG9aErp1paHxw5LYRQd4t24d7CBReN2EeqynEr3uSSjfP6Jr1RgMYqEFzNPTGKsS96dAALutAnFpdhmVCgNxXW7cB5GVAWse"

	// Another EdDSA xpub from backend test vector
	testXpubEdDSA2 = "xpub661MyMwAqRbcEfDLGwPuHzSC8rjZoxf5VN8hQ2M3WrdkC1YBT7ZNdVjxQ1RhVSJkxp8cX18QAvrLqswNzrS6h8SQqkTqaBdDYtbpE1unwma"
)

func TestParseXpub_ECDSA_Secp256k1(t *testing.T) {
	parsed, err := ParseXpub(testXpubECDSA, CurveSecp256k1)
	require.NoError(t, err)

	// Verify structure
	assert.Len(t, parsed.Version, 4)
	assert.Len(t, parsed.Fingerprint, 4)
	assert.Len(t, parsed.ChildNumber, 4)
	assert.Len(t, parsed.ChainCode, 32)
	assert.Len(t, parsed.PublicKey, 33)

	// Verify this is a compressed public key (starts with 02 or 03)
	assert.True(t, parsed.PublicKey[0] == 0x02 || parsed.PublicKey[0] == 0x03,
		"ECDSA public key should be compressed (start with 02 or 03)")

	t.Logf("ECDSA xpub chain code: %s", hex.EncodeToString(parsed.ChainCode))
	t.Logf("ECDSA xpub public key: %s", hex.EncodeToString(parsed.PublicKey))
}

func TestParseXpub_ECDSA_P256(t *testing.T) {
	// Use the same xpub format - P-256 uses same BIP32 format
	parsed, err := ParseXpub(testXpubECDSA, CurveP256)
	require.NoError(t, err)

	assert.Len(t, parsed.ChainCode, 32)
	assert.Len(t, parsed.PublicKey, 33)
	assert.True(t, parsed.PublicKey[0] == 0x02 || parsed.PublicKey[0] == 0x03)
}

func TestParseXpub_EdDSA_Edwards25519(t *testing.T) {
	parsed, err := ParseXpub(testXpubEdDSA, CurveEdwards25519)
	require.NoError(t, err)

	// EdDSA xpub has 0x00 prefix before 32-byte key, which is stripped
	assert.Len(t, parsed.ChainCode, 32)
	assert.Len(t, parsed.PublicKey, 32, "EdDSA public key should be 32 bytes after stripping 0x00 prefix")

	t.Logf("EdDSA xpub chain code: %s", hex.EncodeToString(parsed.ChainCode))
	t.Logf("EdDSA xpub public key: %s", hex.EncodeToString(parsed.PublicKey))
}

func TestParseXpub_EdDSA_KnownVector(t *testing.T) {
	// Test against the known backend EdDSA vector
	// Expected chaincode: 0bbd6d8fac75c721ddf115a8f2c0e7559a47b4405c5bf28ef5a1bfb6094ebf85
	// Expected pubkey: 475635bc3b935ec24875bd125e8038c9852e3dc6b3027416817bb3e1a5c396d1
	parsed, err := ParseXpub(testXpubEdDSA2, CurveEdwards25519)
	require.NoError(t, err)

	expectedChainCode := "0bbd6d8fac75c721ddf115a8f2c0e7559a47b4405c5bf28ef5a1bfb6094ebf85"
	expectedPubKey := "475635bc3b935ec24875bd125e8038c9852e3dc6b3027416817bb3e1a5c396d1"

	assert.Equal(t, expectedChainCode, hex.EncodeToString(parsed.ChainCode))
	assert.Equal(t, expectedPubKey, hex.EncodeToString(parsed.PublicKey))
}

func TestParseXpub_InvalidBase58(t *testing.T) {
	// Test with invalid base58 characters
	_, err := ParseXpub("xpub0OIl", CurveSecp256k1) // 0, O, I, l are not valid base58
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidXpub)
}

func TestParseXpub_TooShort(t *testing.T) {
	// Test with too short data
	_, err := ParseXpub("xpub", CurveSecp256k1)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidXpub)
}

func TestParseXpub_InvalidChecksum(t *testing.T) {
	// Modify the last character to invalidate checksum
	invalidXpub := testXpubECDSA[:len(testXpubECDSA)-1] + "A"
	_, err := ParseXpub(invalidXpub, CurveSecp256k1)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidXpub)
	assert.Contains(t, err.Error(), "checksum")
}

func TestParseXpub_WrongCurve(t *testing.T) {
	// Try to parse an ECDSA xpub as EdDSA
	// This should fail because the public key format is different
	_, err := ParseXpub(testXpubECDSA, CurveEdwards25519)
	require.Error(t, err)
	// The ECDSA xpub has a 02 or 03 prefix, not 00
	assert.Contains(t, err.Error(), "0x00 prefix")
}

func TestExtractChainCode(t *testing.T) {
	t.Run("ECDSA secp256k1", func(t *testing.T) {
		chainCode, err := ExtractChainCode(testXpubECDSA, CurveSecp256k1)
		require.NoError(t, err)
		assert.Len(t, chainCode, 32)
	})

	t.Run("EdDSA Edwards25519", func(t *testing.T) {
		chainCode, err := ExtractChainCode(testXpubEdDSA, CurveEdwards25519)
		require.NoError(t, err)
		assert.Len(t, chainCode, 32)
	})

	t.Run("Invalid xpub", func(t *testing.T) {
		_, err := ExtractChainCode("invalid", CurveSecp256k1)
		require.Error(t, err)
	})
}

func TestParseXpub_AllVersions(t *testing.T) {
	// Test that we can parse xpubs with different version bytes
	// The test xpub uses mainnet version (0x0488B21E)

	parsed, err := ParseXpub(testXpubECDSA, CurveSecp256k1)
	require.NoError(t, err)

	// Check version bytes match mainnet xpub
	assert.Equal(t, []byte{0x04, 0x88, 0xB2, 0x1E}, parsed.Version)
}

func TestParseXpub_Depth(t *testing.T) {
	// For a master xpub, depth should be 0
	parsed, err := ParseXpub(testXpubECDSA, CurveSecp256k1)
	require.NoError(t, err)

	// These test xpubs are master keys, so depth should be 0
	assert.Equal(t, byte(0), parsed.Depth)
}

func TestXpubConstants(t *testing.T) {
	// Verify constant values
	assert.Equal(t, 78, XpubTotalLength)
	assert.Equal(t, 4, XpubVersionLength)
	assert.Equal(t, 4, XpubDepthOffset)
	assert.Equal(t, 32, XpubChainCodeLength)
	assert.Equal(t, 33, XpubPublicKeyLength)
	assert.Equal(t, 4, XpubChecksumLength)

	// Verify version bytes
	assert.Equal(t, []byte{0x04, 0x88, 0xB2, 0x1E}, XpubVersionMainnet)
	assert.Equal(t, []byte{0x04, 0x35, 0x87, 0xCF}, XpubVersionTestnet)
}
