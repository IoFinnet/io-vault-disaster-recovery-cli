// Copyright (C) 2025 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package hd

import (
	"errors"
	"strings"
)

// Algorithm represents the signing algorithm
type Algorithm string

const (
	AlgorithmECDSA   Algorithm = "ECDSA"
	AlgorithmEDDSA   Algorithm = "EDDSA"
	AlgorithmSCHNORR Algorithm = "SCHNORR"
)

// Curve represents the elliptic curve
type Curve string

const (
	CurveSecp256k1    Curve = "secp256k1"
	CurveP256         Curve = "P-256"
	CurveEdwards25519 Curve = "Edwards25519"
)

// Errors
var (
	ErrUnsupportedAlgorithm  = errors.New("unsupported algorithm")
	ErrUnsupportedCurve      = errors.New("unsupported curve")
	ErrInvalidAlgorithmCurve = errors.New("invalid algorithm/curve combination")
	ErrHardenedDerivation    = errors.New("hardened derivation not supported")
	ErrInvalidXpub           = errors.New("invalid xpub format")
	ErrInvalidDerivationPath = errors.New("invalid derivation path")
	ErrMissingMasterKey      = errors.New("missing master key for algorithm")
	ErrCSVMissingColumn      = errors.New("CSV missing required column")
	ErrCSVInvalidFormat      = errors.New("invalid CSV format")
)

// AddressRecord represents a single row from the input CSV
type AddressRecord struct {
	Address   string
	Xpub      string
	Path      string
	Algorithm Algorithm
	Curve     Curve
	Flags     int
}

// DerivedRecord represents a single row for the output CSV
type DerivedRecord struct {
	AddressRecord
	PublicKey  string // hex-encoded
	PrivateKey string // hex-encoded
}

// ParsedXpub contains the decoded components of an extended public key
type ParsedXpub struct {
	Version     []byte // 4 bytes
	Depth       byte
	Fingerprint []byte // 4 bytes
	ChildNumber []byte // 4 bytes
	ChainCode   []byte // 32 bytes
	PublicKey   []byte // 33 bytes (compressed) for ECDSA, 32 bytes for EdDSA
}

// ParseAlgorithm parses an algorithm string (case-insensitive)
func ParseAlgorithm(s string) (Algorithm, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ECDSA":
		return AlgorithmECDSA, nil
	case "EDDSA":
		return AlgorithmEDDSA, nil
	case "SCHNORR":
		return AlgorithmSCHNORR, nil
	default:
		return "", ErrUnsupportedAlgorithm
	}
}

// ParseCurve parses a curve string (case-insensitive)
func ParseCurve(s string) (Curve, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	switch upper {
	case "SECP256K1":
		return CurveSecp256k1, nil
	case "P-256", "P256", "NIST P-256", "NISTP256":
		return CurveP256, nil
	case "EDWARDS25519", "ED25519":
		return CurveEdwards25519, nil
	default:
		return "", ErrUnsupportedCurve
	}
}

// ValidateAlgorithmCurve validates that the algorithm/curve combination is supported
func ValidateAlgorithmCurve(alg Algorithm, curve Curve) error {
	switch alg {
	case AlgorithmECDSA:
		if curve == CurveSecp256k1 || curve == CurveP256 {
			return nil
		}
	case AlgorithmEDDSA:
		if curve == CurveEdwards25519 {
			return nil
		}
	case AlgorithmSCHNORR:
		if curve == CurveSecp256k1 {
			return nil
		}
	}
	return ErrInvalidAlgorithmCurve
}

// RequiresECDSAKey returns true if the algorithm requires an ECDSA master key
func RequiresECDSAKey(alg Algorithm) bool {
	return alg == AlgorithmECDSA || alg == AlgorithmSCHNORR
}

// RequiresEdDSAKey returns true if the algorithm requires an EdDSA master key
func RequiresEdDSAKey(alg Algorithm) bool {
	return alg == AlgorithmEDDSA
}
