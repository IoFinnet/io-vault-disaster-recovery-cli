// Copyright (C) 2025 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package hd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveOutputPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple csv", "input.csv", "input_recovered.csv"},
		{"no extension", "addresses", "addresses_recovered"},
		{"path with directory", "/path/to/file.csv", "/path/to/file_recovered.csv"},
		{"relative path", "./data/addresses.csv", "./data/addresses_recovered.csv"},
		{"uppercase extension", "INPUT.CSV", "INPUT_recovered.CSV"},
		{"multiple dots", "my.file.csv", "my.file_recovered.csv"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := DeriveOutputPath(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseCSV_Valid(t *testing.T) {
	// Create a temporary CSV file
	content := `address,xpub,path,algorithm,curve,flags
addr1,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8,m/0,ECDSA,secp256k1,0
addr2,xpub661MyMwAqRbcEfDLGwPuHzSC8rjZoxf5VN8hQ2M3WrdkC1YBT7ZNdVjxQ1RhVSJkxp8cX18QAvrLqswNzrS6h8SQqkTqaBdDYtbpE1unwma,m/44/0/0,EDDSA,Edwards25519,1
`
	tmpFile := createTempCSV(t, content)
	defer os.Remove(tmpFile)

	records, err := ParseCSV(tmpFile)
	require.NoError(t, err)
	require.Len(t, records, 2)

	// Check first record
	assert.Equal(t, "addr1", records[0].Address)
	assert.Equal(t, AlgorithmECDSA, records[0].Algorithm)
	assert.Equal(t, CurveSecp256k1, records[0].Curve)
	assert.Equal(t, "m/0", records[0].Path)
	assert.Equal(t, 0, records[0].Flags)

	// Check second record
	assert.Equal(t, "addr2", records[1].Address)
	assert.Equal(t, AlgorithmEDDSA, records[1].Algorithm)
	assert.Equal(t, CurveEdwards25519, records[1].Curve)
	assert.Equal(t, "m/44/0/0", records[1].Path)
	assert.Equal(t, 1, records[1].Flags)
}

func TestParseCSV_CaseInsensitiveHeaders(t *testing.T) {
	content := `ADDRESS,XPUB,PATH,ALGORITHM,CURVE,FLAGS
addr1,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8,m/0,ecdsa,SECP256K1,0
`
	tmpFile := createTempCSV(t, content)
	defer os.Remove(tmpFile)

	records, err := ParseCSV(tmpFile)
	require.NoError(t, err)
	require.Len(t, records, 1)

	assert.Equal(t, "addr1", records[0].Address)
	assert.Equal(t, AlgorithmECDSA, records[0].Algorithm)
	assert.Equal(t, CurveSecp256k1, records[0].Curve)
}

func TestParseCSV_MissingColumn(t *testing.T) {
	content := `address,xpub,path,algorithm,flags
addr1,xpub123,m/0,ECDSA,0
`
	tmpFile := createTempCSV(t, content)
	defer os.Remove(tmpFile)

	_, err := ParseCSV(tmpFile)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCSVMissingColumn)
	assert.Contains(t, err.Error(), "curve")
}

func TestParseCSV_InvalidAlgorithm(t *testing.T) {
	content := `address,xpub,path,algorithm,curve,flags
addr1,xpub123,m/0,INVALID,secp256k1,0
`
	tmpFile := createTempCSV(t, content)
	defer os.Remove(tmpFile)

	_, err := ParseCSV(tmpFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid algorithm")
	assert.Contains(t, err.Error(), "row 2")
}

func TestParseCSV_InvalidCurve(t *testing.T) {
	content := `address,xpub,path,algorithm,curve,flags
addr1,xpub123,m/0,ECDSA,unknown,0
`
	tmpFile := createTempCSV(t, content)
	defer os.Remove(tmpFile)

	_, err := ParseCSV(tmpFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid curve")
	assert.Contains(t, err.Error(), "row 2")
}

func TestParseCSV_InvalidAlgorithmCurveCombination(t *testing.T) {
	content := `address,xpub,path,algorithm,curve,flags
addr1,xpub123,m/0,ECDSA,Edwards25519,0
`
	tmpFile := createTempCSV(t, content)
	defer os.Remove(tmpFile)

	_, err := ParseCSV(tmpFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm/curve")
	assert.Contains(t, err.Error(), "row 2")
}

func TestParseCSV_InvalidFlags(t *testing.T) {
	content := `address,xpub,path,algorithm,curve,flags
addr1,xpub123,m/0,ECDSA,secp256k1,not_a_number
`
	tmpFile := createTempCSV(t, content)
	defer os.Remove(tmpFile)

	_, err := ParseCSV(tmpFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid flags")
	assert.Contains(t, err.Error(), "row 2")
}

func TestParseCSV_EmptyFlags(t *testing.T) {
	content := `address,xpub,path,algorithm,curve,flags
addr1,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8,m/0,ECDSA,secp256k1,
`
	tmpFile := createTempCSV(t, content)
	defer os.Remove(tmpFile)

	records, err := ParseCSV(tmpFile)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, 0, records[0].Flags)
}

func TestParseCSV_FileNotFound(t *testing.T) {
	_, err := ParseCSV("/nonexistent/path/to/file.csv")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestWriteCSV(t *testing.T) {
	records := []DerivedRecord{
		{
			AddressRecord: AddressRecord{
				Address:   "addr1",
				Xpub:      "xpub123",
				Path:      "m/0",
				Algorithm: AlgorithmECDSA,
				Curve:     CurveSecp256k1,
				Flags:     0,
			},
			PublicKey:  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			PrivateKey: "0000000000000000000000000000000000000000000000000000000000000001",
		},
		{
			AddressRecord: AddressRecord{
				Address:   "addr2",
				Xpub:      "xpub456",
				Path:      "m/44/0/0",
				Algorithm: AlgorithmEDDSA,
				Curve:     CurveEdwards25519,
				Flags:     1,
			},
			PublicKey:  "da65f1ed202cff9216443248fabe11f48ac0b816cf049e557c059e806204bdeb",
			PrivateKey: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "output.csv")
	err := WriteCSV(tmpFile, records)
	require.NoError(t, err)

	// Read and verify the file content
	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	require.Len(t, lines, 3) // header + 2 records

	// Check header
	assert.Equal(t, "address,xpub,path,algorithm,curve,flags,publickey,privatekey", lines[0])

	// Check first data row
	assert.Contains(t, lines[1], "addr1")
	assert.Contains(t, lines[1], "ECDSA")
	assert.Contains(t, lines[1], "secp256k1")
	assert.Contains(t, lines[1], "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

	// Check second data row
	assert.Contains(t, lines[2], "addr2")
	assert.Contains(t, lines[2], "EDDSA")
	assert.Contains(t, lines[2], "Edwards25519")
}

func TestInputOutputColumns(t *testing.T) {
	// Verify the column names match expected
	expectedInput := []string{"address", "xpub", "path", "algorithm", "curve", "flags"}
	expectedOutput := []string{"address", "xpub", "path", "algorithm", "curve", "flags", "publickey", "privatekey"}

	assert.Equal(t, expectedInput, InputColumns)
	assert.Equal(t, expectedOutput, OutputColumns)
}

// Helper function to create a temporary CSV file
func createTempCSV(t *testing.T, content string) string {
	t.Helper()
	tmpFile := filepath.Join(t.TempDir(), "test.csv")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)
	return tmpFile
}
