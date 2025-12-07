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

	// Test ECDSA/secp256k1 derivation with expected values from tss-lib
	tests := []struct {
		address    string
		path       string
		expectedSK string
		expectedPK string
	}{
		{
			address:    "test_ecdsa_m0",
			path:       "m/0",
			expectedSK: "4e2cdcf2f14e802810e878cf9e6411fc4e712edf19a06bcfcc5d5572e489a3b7",
			expectedPK: "027c4b09ffb985c298afe7e5813266cbfcb7780b480ac294b0b43dc21f2be3d13c",
		},
		{
			address:    "test_ecdsa_m44_0_0",
			path:       "m/44/0/0",
			expectedSK: "c95ea3f7d9e32d8356eb630d77ede8c1e8a7578ed0b61ec9c4915b0dca96c217",
			expectedPK: "02b41ee4dfdf05264b0eaad3c8e271b973ff225e1e81ab0585b23cad4de0c4a1e6",
		},
		{
			address:    "test_ecdsa_eth",
			path:       "m/44/60/0/0/0",
			expectedSK: "70d32e0e32025fdf1f41cafbe3ae21d78134e9f3a639c4a889336eb4b2b4a605",
			expectedPK: "0389988f76588819d77d0a639a962fee68e94441878d01121d65c602f28d5e17a4",
		},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			records := []hd.AddressRecord{
				{
					Address:   tc.address,
					Xpub:      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
					Path:      tc.path,
					Algorithm: hd.AlgorithmECDSA,
					Curve:     hd.CurveSecp256k1,
					Flags:     0,
				},
			}

			derived, err := deriver.DeriveAll(records)
			require.NoError(t, err)
			require.Len(t, derived, 1)

			d := derived[0]
			assert.Equal(t, tc.expectedSK, d.PrivateKey, "Private key mismatch for %s", tc.path)
			assert.Equal(t, tc.expectedPK, d.PublicKey, "Public key mismatch for %s", tc.path)
		})
	}
}

func TestHDIntegration_DeriveEdDSA(t *testing.T) {
	deriver, err := hd.NewDeriver(nil, testMasterEdDSASK)
	require.NoError(t, err)

	// Test EdDSA/Edwards25519 derivation with expected values from tss-lib
	tests := []struct {
		address    string
		path       string
		expectedSK string
		expectedPK string
	}{
		{
			address:    "test_eddsa_m0",
			path:       "m/0",
			expectedSK: "0a4f1b3e9c9b6703326323221740da1c9b6c315f212837ba6c3435edfdd7c295",
			expectedPK: "f0668f57fe91dd5ef7c83ef38754831e37116aedcaaaeb248e3c90005e6ea51c",
		},
		{
			address:    "test_eddsa_solana",
			path:       "m/44/501/0/0",
			expectedSK: "0cb845b159035c3285e5a08fc2980221270745affc74e952d71764da41240722",
			expectedPK: "9531744deb5d0128ad55a3bc544dc89e6bf6e2ea359f56eaae604fc4eb2536ff",
		},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			records := []hd.AddressRecord{
				{
					Address:   tc.address,
					Xpub:      "xpub661MyMwAqRbcEZ6F7ZYpZTTdD8ToN2UCzBt5jjXxBm3y4jwbUJncoqTbB4zY28NpWEvDswPSAoYigFG6PAhzMZ3SMDz4KNaQvKzUtaEqJuL",
					Path:      tc.path,
					Algorithm: hd.AlgorithmEDDSA,
					Curve:     hd.CurveEdwards25519,
					Flags:     0,
				},
			}

			derived, err := deriver.DeriveAll(records)
			require.NoError(t, err)
			require.Len(t, derived, 1)

			d := derived[0]
			assert.Equal(t, tc.expectedSK, d.PrivateKey, "Private key mismatch for %s", tc.path)
			assert.Equal(t, tc.expectedPK, d.PublicKey, "Public key mismatch for %s", tc.path)
		})
	}
}

func TestHDIntegration_DeriveSchnorr(t *testing.T) {
	deriver, err := hd.NewDeriver(testMasterECDSASK, nil)
	require.NoError(t, err)

	// Test Schnorr/secp256k1 derivation with expected values from tss-lib
	records := []hd.AddressRecord{
		{
			Address:   "test_schnorr_taproot",
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

	// Expected values from tss-lib
	expectedSK := "989ad7fcd714e2ffed41e287422e96e39df6225e4145bc45dc0cbc024c4641fb"
	expectedPK := "0258387941128a0f18720ff2ba08416015dca2603a86a9a62b98dfbc1130b291e7"

	assert.Equal(t, expectedSK, d.PrivateKey, "Schnorr private key mismatch")
	assert.Equal(t, expectedPK, d.PublicKey, "Schnorr public key mismatch")
}

func TestHDIntegration_DeriveP256(t *testing.T) {
	deriver, err := hd.NewDeriver(testMasterECDSASK, nil)
	require.NoError(t, err)

	// Test ECDSA/P-256 derivation with expected values from tss-lib
	records := []hd.AddressRecord{
		{
			Address:   "test_p256_m0",
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

	// Expected values from tss-lib
	expectedSK := "aa99fd5bdbefd92f802f278e0c8998ac0408b8afab8a77e695dcb9dc3addcc81"
	expectedPK := "02d3cbd426c052a03c9027eafcb4b13873163ad24680b0cc58c76d3762fbc6cebf"

	assert.Equal(t, expectedSK, d.PrivateKey, "P-256 private key mismatch")
	assert.Equal(t, expectedPK, d.PublicKey, "P-256 public key mismatch")
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
