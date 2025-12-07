// Copyright (C) 2025 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package hd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    Algorithm
		expectError bool
	}{
		// Valid algorithms
		{"ECDSA uppercase", "ECDSA", AlgorithmECDSA, false},
		{"ECDSA lowercase", "ecdsa", AlgorithmECDSA, false},
		{"ECDSA mixed case", "EcDsA", AlgorithmECDSA, false},
		{"EDDSA uppercase", "EDDSA", AlgorithmEDDSA, false},
		{"EDDSA lowercase", "eddsa", AlgorithmEDDSA, false},
		{"SCHNORR uppercase", "SCHNORR", AlgorithmSCHNORR, false},
		{"SCHNORR lowercase", "schnorr", AlgorithmSCHNORR, false},
		{"with leading space", " ECDSA", AlgorithmECDSA, false},
		{"with trailing space", "ECDSA ", AlgorithmECDSA, false},

		// Invalid algorithms
		{"empty string", "", "", true},
		{"invalid algorithm", "RSA", "", true},
		{"partial match", "ECD", "", true},
		{"typo", "ECSDA", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseAlgorithm(tc.input)
			if tc.expectError {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseCurve(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    Curve
		expectError bool
	}{
		// secp256k1 variants
		{"secp256k1 lowercase", "secp256k1", CurveSecp256k1, false},
		{"SECP256K1 uppercase", "SECP256K1", CurveSecp256k1, false},
		{"Secp256k1 mixed case", "Secp256k1", CurveSecp256k1, false},

		// P-256 variants
		{"P-256 with dash", "P-256", CurveP256, false},
		{"P256 without dash", "P256", CurveP256, false},
		{"p-256 lowercase", "p-256", CurveP256, false},
		{"NIST P-256", "NIST P-256", CurveP256, false},
		{"NISTP256", "NISTP256", CurveP256, false},

		// Edwards25519 variants
		{"Edwards25519", "Edwards25519", CurveEdwards25519, false},
		{"EDWARDS25519 uppercase", "EDWARDS25519", CurveEdwards25519, false},
		{"ED25519 short form", "ED25519", CurveEdwards25519, false},
		{"ed25519 lowercase", "ed25519", CurveEdwards25519, false},

		// With whitespace
		{"with leading space", " secp256k1", CurveSecp256k1, false},
		{"with trailing space", "secp256k1 ", CurveSecp256k1, false},

		// Invalid curves
		{"empty string", "", "", true},
		{"invalid curve", "secp384r1", "", true},
		{"typo", "secp256k", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseCurve(tc.input)
			if tc.expectError {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedCurve)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestValidateAlgorithmCurve(t *testing.T) {
	validCombinations := []struct {
		alg   Algorithm
		curve Curve
	}{
		{AlgorithmECDSA, CurveSecp256k1},
		{AlgorithmECDSA, CurveP256},
		{AlgorithmEDDSA, CurveEdwards25519},
		{AlgorithmSCHNORR, CurveSecp256k1},
	}

	for _, tc := range validCombinations {
		t.Run(string(tc.alg)+"_"+string(tc.curve)+"_valid", func(t *testing.T) {
			err := ValidateAlgorithmCurve(tc.alg, tc.curve)
			assert.NoError(t, err)
		})
	}

	invalidCombinations := []struct {
		alg   Algorithm
		curve Curve
	}{
		{AlgorithmECDSA, CurveEdwards25519},
		{AlgorithmEDDSA, CurveSecp256k1},
		{AlgorithmEDDSA, CurveP256},
		{AlgorithmSCHNORR, CurveP256},
		{AlgorithmSCHNORR, CurveEdwards25519},
	}

	for _, tc := range invalidCombinations {
		t.Run(string(tc.alg)+"_"+string(tc.curve)+"_invalid", func(t *testing.T) {
			err := ValidateAlgorithmCurve(tc.alg, tc.curve)
			assert.ErrorIs(t, err, ErrInvalidAlgorithmCurve)
		})
	}
}

func TestRequiresECDSAKey(t *testing.T) {
	assert.True(t, RequiresECDSAKey(AlgorithmECDSA))
	assert.True(t, RequiresECDSAKey(AlgorithmSCHNORR)) // Schnorr uses ECDSA master key on secp256k1
	assert.False(t, RequiresECDSAKey(AlgorithmEDDSA))
}

func TestRequiresEdDSAKey(t *testing.T) {
	assert.True(t, RequiresEdDSAKey(AlgorithmEDDSA))
	assert.False(t, RequiresEdDSAKey(AlgorithmECDSA))
	assert.False(t, RequiresEdDSAKey(AlgorithmSCHNORR))
}
