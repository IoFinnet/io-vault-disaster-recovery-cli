// Copyright (C) 2025 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/hd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Known master keys for testing (derived from BIP32 test vectors)
var (
	// Master ECDSA private key for secp256k1/P-256 (BIP32 Test Vector 1)
	testMasterECDSASK, _ = hex.DecodeString("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")

	// Master EdDSA private key for Edwards25519 (matches tss-lib test vectors)
	testMasterEdDSASK, _ = hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
)

func TestHDIntegration_ParseCSV(t *testing.T) {
	records, err := hd.ParseCSV("test-files/hd_test_addresses.csv")
	require.NoError(t, err)
	require.NotEmpty(t, records)

	t.Logf("Parsed %d records from CSV", len(records))

	// Verify we have expected algorithm/curve combinations
	algCurveCount := make(map[string]int)
	for _, rec := range records {
		key := string(rec.Algorithm) + "/" + string(rec.Curve)
		algCurveCount[key]++
	}

	assert.Equal(t, 3, algCurveCount["ECDSA/secp256k1"], "Expected 3 ECDSA/secp256k1 records")
	assert.Equal(t, 2, algCurveCount["EDDSA/Edwards25519"], "Expected 2 EdDSA/Edwards25519 records")
	assert.Equal(t, 1, algCurveCount["SCHNORR/secp256k1"], "Expected 1 Schnorr/secp256k1 record")
	assert.Equal(t, 1, algCurveCount["ECDSA/P-256"], "Expected 1 ECDSA/P-256 record")
}

func TestHDIntegration_DeriverCreation(t *testing.T) {
	t.Run("ECDSA only", func(t *testing.T) {
		deriver, err := hd.NewDeriver(testMasterECDSASK, nil)
		require.NoError(t, err)
		assert.NotNil(t, deriver)
	})

	t.Run("EdDSA only", func(t *testing.T) {
		deriver, err := hd.NewDeriver(nil, testMasterEdDSASK)
		require.NoError(t, err)
		assert.NotNil(t, deriver)
	})

	t.Run("Both keys", func(t *testing.T) {
		deriver, err := hd.NewDeriver(testMasterECDSASK, testMasterEdDSASK)
		require.NoError(t, err)
		assert.NotNil(t, deriver)
	})
}

func TestHDIntegration_DeriveECDSA(t *testing.T) {
	deriver, err := hd.NewDeriver(testMasterECDSASK, nil)
	require.NoError(t, err)

	// Test ECDSA/secp256k1 derivation
	records := []hd.AddressRecord{
		{
			Address:   "test_ecdsa_1",
			Xpub:      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			Path:      "m/0",
			Algorithm: hd.AlgorithmECDSA,
			Curve:     hd.CurveSecp256k1,
			Flags:     0,
		},
		{
			Address:   "test_ecdsa_2",
			Xpub:      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			Path:      "m/44/0/0",
			Algorithm: hd.AlgorithmECDSA,
			Curve:     hd.CurveSecp256k1,
			Flags:     0,
		},
	}

	derived, err := deriver.DeriveAll(records)
	require.NoError(t, err)
	require.Len(t, derived, 2)

	for i, d := range derived {
		t.Logf("Record %d: path=%s, pubkey=%s", i, d.Path, d.PublicKey)

		// Verify output is hex-encoded and correct length
		assert.Len(t, d.PrivateKey, 64, "Private key should be 32 bytes hex (64 chars)")
		assert.Len(t, d.PublicKey, 66, "secp256k1 compressed public key should be 33 bytes hex (66 chars)")

		// Verify public key starts with 02 or 03 (compressed format)
		assert.True(t, d.PublicKey[:2] == "02" || d.PublicKey[:2] == "03",
			"Compressed public key should start with 02 or 03")
	}

	// Verify different paths produce different keys
	assert.NotEqual(t, derived[0].PrivateKey, derived[1].PrivateKey)
	assert.NotEqual(t, derived[0].PublicKey, derived[1].PublicKey)
}

func TestHDIntegration_DeriveEdDSA(t *testing.T) {
	deriver, err := hd.NewDeriver(nil, testMasterEdDSASK)
	require.NoError(t, err)

	// Test EdDSA/Edwards25519 derivation (xpub matches testMasterEdDSASK)
	records := []hd.AddressRecord{
		{
			Address:   "test_eddsa_1",
			Xpub:      "xpub661MyMwAqRbcEZ6F7ZYpZTTdD8ToN2UCzBt5jjXxBm3y4jwbUJncoqTbB4zY28NpWEvDswPSAoYigFG6PAhzMZ3SMDz4KNaQvKzUtaEqJuL",
			Path:      "m/0",
			Algorithm: hd.AlgorithmEDDSA,
			Curve:     hd.CurveEdwards25519,
			Flags:     0,
		},
	}

	derived, err := deriver.DeriveAll(records)
	require.NoError(t, err)
	require.Len(t, derived, 1)

	d := derived[0]
	t.Logf("EdDSA: path=%s, pubkey=%s", d.Path, d.PublicKey)

	// EdDSA keys are 32 bytes
	assert.Len(t, d.PrivateKey, 64, "Private key should be 32 bytes hex (64 chars)")
	assert.Len(t, d.PublicKey, 64, "Edwards25519 public key should be 32 bytes hex (64 chars)")
}

func TestHDIntegration_DeriveSchnorr(t *testing.T) {
	deriver, err := hd.NewDeriver(testMasterECDSASK, nil)
	require.NoError(t, err)

	// Test Schnorr/secp256k1 derivation
	records := []hd.AddressRecord{
		{
			Address:   "test_schnorr_1",
			Xpub:      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			Path:      "m/86/0/0/0/0",
			Algorithm: hd.AlgorithmSCHNORR,
			Curve:     hd.CurveSecp256k1,
			Flags:     0,
		},
	}

	derived, err := deriver.DeriveAll(records)
	require.NoError(t, err)
	require.Len(t, derived, 1)

	d := derived[0]
	t.Logf("Schnorr: path=%s, pubkey=%s", d.Path, d.PublicKey)

	// Schnorr uses secp256k1, same as ECDSA
	assert.Len(t, d.PrivateKey, 64, "Private key should be 32 bytes hex (64 chars)")
	assert.Len(t, d.PublicKey, 66, "secp256k1 compressed public key should be 33 bytes hex (66 chars)")
}

func TestHDIntegration_DeriveP256(t *testing.T) {
	deriver, err := hd.NewDeriver(testMasterECDSASK, nil)
	require.NoError(t, err)

	// Test ECDSA/P-256 derivation (xpub encodes P-256 public key from same master SK)
	records := []hd.AddressRecord{
		{
			Address:   "test_p256_1",
			Xpub:      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ1rxaVqyxRSgbLorQN2Q1RJiLfHtqHqAcK8WosMpL4tCGungDyV",
			Path:      "m/0",
			Algorithm: hd.AlgorithmECDSA,
			Curve:     hd.CurveP256,
			Flags:     0,
		},
	}

	derived, err := deriver.DeriveAll(records)
	require.NoError(t, err)
	require.Len(t, derived, 1)

	d := derived[0]
	t.Logf("P-256: path=%s, pubkey=%s", d.Path, d.PublicKey)

	// P-256 compressed keys are 33 bytes
	assert.Len(t, d.PrivateKey, 64, "Private key should be 32 bytes hex (64 chars)")
	assert.Len(t, d.PublicKey, 66, "P-256 compressed public key should be 33 bytes hex (66 chars)")
}

func TestHDIntegration_FullCSVFlow(t *testing.T) {
	// Create temporary input/output files
	tmpDir := t.TempDir()
	inputCSV := filepath.Join(tmpDir, "input.csv")
	outputCSV := hd.DeriveOutputPath(inputCSV)

	// Write a simple test CSV
	inputContent := `address,xpub,path,algorithm,curve,flags
test_1,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8,m/0,ECDSA,secp256k1,0
test_2,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8,m/44/0/0,ECDSA,secp256k1,1
`
	err := os.WriteFile(inputCSV, []byte(inputContent), 0644)
	require.NoError(t, err)

	// Parse CSV
	records, err := hd.ParseCSV(inputCSV)
	require.NoError(t, err)
	require.Len(t, records, 2)

	// Create deriver and derive keys
	deriver, err := hd.NewDeriver(testMasterECDSASK, nil)
	require.NoError(t, err)

	derived, err := deriver.DeriveAll(records)
	require.NoError(t, err)
	require.Len(t, derived, 2)

	// Write output CSV
	err = hd.WriteCSV(outputCSV, derived)
	require.NoError(t, err)

	// Verify output file exists
	_, err = os.Stat(outputCSV)
	require.NoError(t, err)

	// Read and verify output
	content, err := os.ReadFile(outputCSV)
	require.NoError(t, err)

	t.Logf("Output CSV content:\n%s", string(content))

	// Verify output contains expected columns
	assert.Contains(t, string(content), "publickey")
	assert.Contains(t, string(content), "privatekey")
	assert.Contains(t, string(content), "test_1")
	assert.Contains(t, string(content), "test_2")
}

func TestHDIntegration_ConsistentDerivation(t *testing.T) {
	deriver, err := hd.NewDeriver(testMasterECDSASK, nil)
	require.NoError(t, err)

	record := hd.AddressRecord{
		Address:   "consistency_test",
		Xpub:      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		Path:      "m/44/60/0/0/0",
		Algorithm: hd.AlgorithmECDSA,
		Curve:     hd.CurveSecp256k1,
		Flags:     0,
	}

	// Derive the same key 5 times
	var results []hd.DerivedRecord
	for i := 0; i < 5; i++ {
		derived, err := deriver.DeriveAll([]hd.AddressRecord{record})
		require.NoError(t, err)
		results = append(results, derived[0])
	}

	// All derivations should produce identical results
	for i := 1; i < len(results); i++ {
		assert.Equal(t, results[0].PrivateKey, results[i].PrivateKey,
			"Derivation %d private key should match derivation 0", i)
		assert.Equal(t, results[0].PublicKey, results[i].PublicKey,
			"Derivation %d public key should match derivation 0", i)
	}
}

func TestHDIntegration_ErrorHandling(t *testing.T) {
	deriver, err := hd.NewDeriver(testMasterECDSASK, nil)
	require.NoError(t, err)

	t.Run("Invalid xpub", func(t *testing.T) {
		records := []hd.AddressRecord{
			{
				Address:   "invalid_xpub",
				Xpub:      "invalid_xpub_string",
				Path:      "m/0",
				Algorithm: hd.AlgorithmECDSA,
				Curve:     hd.CurveSecp256k1,
				Flags:     0,
			},
		}

		_, err := deriver.DeriveAll(records)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid xpub")
	})

	t.Run("Missing EdDSA key", func(t *testing.T) {
		records := []hd.AddressRecord{
			{
				Address:   "missing_eddsa",
				Xpub:      "xpub661MyMwAqRbcEZ6F7ZYpZTTdD8ToN2UCzBt5jjXxBm3y4jwbUJncoqTbB4zY28NpWEvDswPSAoYigFG6PAhzMZ3SMDz4KNaQvKzUtaEqJuL",
				Path:      "m/0",
				Algorithm: hd.AlgorithmEDDSA,
				Curve:     hd.CurveEdwards25519,
				Flags:     0,
			},
		}

		_, err := deriver.DeriveAll(records)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing master key")
	})
}

func TestHDIntegration_OutputPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"addresses.csv", "addresses_recovered.csv"},
		{"test-files/hd_test_addresses.csv", "test-files/hd_test_addresses_recovered.csv"},
		{"data.csv", "data_recovered.csv"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := hd.DeriveOutputPath(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
