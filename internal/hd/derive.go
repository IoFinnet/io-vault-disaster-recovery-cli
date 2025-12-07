// Copyright (C) 2025 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package hd

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

// Deriver handles HD key derivation for recovered master keys
type Deriver struct {
	ecdsaSK []byte // 32-byte ECDSA master private key (secp256k1/P-256)
	eddsaSK []byte // 32-byte EdDSA master private key (Edwards25519)
}

// NewDeriver creates a new HD key deriver with the recovered master keys
func NewDeriver(ecdsaSK, eddsaSK []byte) (*Deriver, error) {
	if ecdsaSK != nil && len(ecdsaSK) != 32 {
		return nil, fmt.Errorf("ECDSA private key must be 32 bytes, got %d", len(ecdsaSK))
	}
	if eddsaSK != nil && len(eddsaSK) != 32 {
		return nil, fmt.Errorf("EdDSA private key must be 32 bytes, got %d", len(eddsaSK))
	}
	return &Deriver{
		ecdsaSK: ecdsaSK,
		eddsaSK: eddsaSK,
	}, nil
}

// DeriveAll processes all address records and returns derived records
func (d *Deriver) DeriveAll(records []AddressRecord) ([]DerivedRecord, error) {
	results := make([]DerivedRecord, 0, len(records))

	for i, rec := range records {
		derived, err := d.deriveOne(rec)
		if err != nil {
			return nil, fmt.Errorf("derivation failed for record %d (address: %s): %w",
				i+1, rec.Address, err)
		}
		results = append(results, derived)
	}

	return results, nil
}

// deriveOne derives a single child key from the master key
func (d *Deriver) deriveOne(rec AddressRecord) (DerivedRecord, error) {
	result := DerivedRecord{AddressRecord: rec}

	// Validate algorithm/curve combination
	if err := ValidateAlgorithmCurve(rec.Algorithm, rec.Curve); err != nil {
		return result, err
	}

	// Select master key based on algorithm
	var masterSK []byte
	if RequiresECDSAKey(rec.Algorithm) {
		if d.ecdsaSK == nil {
			return result, fmt.Errorf("%w: ECDSA key required for %s", ErrMissingMasterKey, rec.Algorithm)
		}
		masterSK = d.ecdsaSK
	} else if RequiresEdDSAKey(rec.Algorithm) {
		if d.eddsaSK == nil {
			return result, fmt.Errorf("%w: EdDSA key required for %s", ErrMissingMasterKey, rec.Algorithm)
		}
		masterSK = d.eddsaSK
	}

	// Parse the xpub to extract chain code and parent public key
	parsedXpub, err := ParseXpub(rec.Xpub, rec.Curve)
	if err != nil {
		return result, fmt.Errorf("invalid xpub: %w", err)
	}

	// Parse derivation path
	indices, err := ParseDerivationPath(rec.Path)
	if err != nil {
		return result, fmt.Errorf("invalid derivation path: %w", err)
	}

	// Derive child key
	childSK, childPK, err := deriveChildKey(
		masterSK,
		parsedXpub.ChainCode,
		parsedXpub.PublicKey,
		indices,
		rec.Algorithm,
		rec.Curve,
	)
	if err != nil {
		return result, err
	}

	result.PrivateKey = hex.EncodeToString(childSK)
	result.PublicKey = hex.EncodeToString(childPK)

	return result, nil
}

// deriveChildKey derives a child private key using the direct scalar approach (BIP32)
// For non-hardened derivation: child_sk = (parent_sk + IL) mod n
// where IL = HMAC-SHA512(chainCode, parentPubKey || index)[:32]
func deriveChildKey(
	masterSK []byte,
	chainCode []byte,
	parentPubKey []byte,
	indices []uint32,
	alg Algorithm,
	curve Curve,
) ([]byte, []byte, error) {

	// If no indices (root path), return master key directly
	if len(indices) == 0 {
		childPK, err := computePublicKey(masterSK, alg, curve)
		if err != nil {
			return nil, nil, err
		}
		return masterSK, childPK, nil
	}

	// Get the curve order for modular arithmetic
	curveOrder := getCurveOrder(curve)
	if curveOrder == nil {
		return nil, nil, ErrUnsupportedCurve
	}

	// Start with master key
	currentSK := new(big.Int).SetBytes(masterSK)
	currentPubKey := parentPubKey
	currentChainCode := chainCode

	// Iterate through each index in the path
	for _, index := range indices {
		// Serialize public key for HMAC input
		// For ECDSA curves, pubkey is 33 bytes compressed (02/03 + X)
		// For EdDSA/Edwards25519, pubkey is 32 bytes Ed25519 format
		pubKeyForHMAC := currentPubKey

		// Compute HMAC-SHA512(chainCode, pubKey || index)
		data := make([]byte, len(pubKeyForHMAC)+4)
		copy(data, pubKeyForHMAC)
		binary.BigEndian.PutUint32(data[len(pubKeyForHMAC):], index)

		mac := hmac.New(sha512.New, currentChainCode)
		mac.Write(data)
		I := mac.Sum(nil)

		IL := I[:32] // Left 32 bytes for key derivation
		IR := I[32:] // Right 32 bytes for new chain code

		// child_private_key = (parent_private_key + IL) mod n
		// For Ed25519, IL is interpreted as little-endian scalar, so we reverse the bytes
		var delta *big.Int
		if curve == CurveEdwards25519 {
			// Ed25519 uses little-endian scalar representation
			// BIP32 HMAC output (IL) is big-endian, so reverse to convert
			ilReversed := make([]byte, 32)
			for i := 0; i < 32; i++ {
				ilReversed[31-i] = IL[i]
			}
			delta = new(big.Int).SetBytes(ilReversed)
			// Always reduce modulo N for Ed25519
			delta.Mod(delta, curveOrder)
		} else {
			delta = new(big.Int).SetBytes(IL)
		}
		childSK := new(big.Int).Add(currentSK, delta)
		childSK.Mod(childSK, curveOrder)

		// Compute new public key for next iteration
		childPubKey, err := computePublicKey(leftPadTo32Bytes(childSK), alg, curve)
		if err != nil {
			return nil, nil, err
		}

		currentSK = childSK
		currentPubKey = childPubKey
		currentChainCode = IR
	}

	// Return final child key
	childSKBytes := leftPadTo32Bytes(currentSK)

	return childSKBytes, currentPubKey, nil
}

// computePublicKey computes the public key from a private key scalar
func computePublicKey(sk []byte, alg Algorithm, curve Curve) ([]byte, error) {
	switch curve {
	case CurveSecp256k1:
		// Use btcec for secp256k1
		privKey, _ := btcec.PrivKeyFromBytes(sk)
		pubKey := privKey.PubKey()
		return pubKey.SerializeCompressed(), nil

	case CurveP256:
		// Use standard crypto/elliptic for P-256
		ec := elliptic.P256()
		x, y := ec.ScalarBaseMult(sk)
		return serializeCompressedP256(x, y), nil

	case CurveEdwards25519:
		// Use Edwards curve from dcrd
		// First reduce the scalar modulo the curve order to ensure it's valid
		ec := edwards.Edwards()
		scalar := new(big.Int).SetBytes(sk)
		scalar.Mod(scalar, ec.N)

		// Edwards.PrivKeyFromScalar requires the scalar to be within range
		scalarBytes := leftPadTo32Bytes(scalar)
		_, pubKey, err := edwards.PrivKeyFromScalar(scalarBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to derive EdDSA public key: %w", err)
		}
		// Return 32-byte Ed25519 public key (not compressed format)
		return pubKey.Serialize(), nil

	default:
		return nil, ErrUnsupportedCurve
	}
}

// ParseDerivationPath parses a BIP32 derivation path string
// Supports: "m/44/0/0", "M/44/0/0", "m/0", "m", "m/"
// Rejects hardened paths with ' or h suffix
func ParseDerivationPath(path string) ([]uint32, error) {
	path = strings.TrimSpace(path)

	// Handle empty path - return empty indices (root)
	if path == "" {
		return []uint32{}, nil
	}

	// Normalize to lowercase
	path = strings.ToLower(path)

	// Must start with "m"
	if !strings.HasPrefix(path, "m") {
		return nil, fmt.Errorf("%w: path must start with 'm', got '%s'", ErrInvalidDerivationPath, path)
	}

	// Remove "m" prefix
	path = strings.TrimPrefix(path, "m")

	// Handle root path ("m" or "m/")
	if path == "" || path == "/" {
		return []uint32{}, nil
	}

	// Must have "/" after "m"
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("%w: expected '/' after 'm', got '%s'", ErrInvalidDerivationPath, path)
	}

	path = strings.TrimPrefix(path, "/")

	// Handle trailing slash
	path = strings.TrimSuffix(path, "/")

	// If nothing left after trimming, it's root path
	if path == "" {
		return []uint32{}, nil
	}

	// Split by "/"
	parts := strings.Split(path, "/")
	indices := make([]uint32, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check for hardened notation
		if strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") {
			return nil, fmt.Errorf("%w: hardened derivation not supported (found '%s')", ErrHardenedDerivation, part)
		}

		// Parse as uint64 first to check bounds
		index, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid index '%s'", ErrInvalidDerivationPath, part)
		}

		// Check if it would be a hardened index (>= 2^31)
		if index >= 0x80000000 {
			return nil, fmt.Errorf("%w: index %d is >= 2^31 (hardened range)", ErrHardenedDerivation, index)
		}

		indices = append(indices, uint32(index))
	}

	return indices, nil
}

// getCurveOrder returns the order (n) of the curve for modular arithmetic
func getCurveOrder(curve Curve) *big.Int {
	switch curve {
	case CurveSecp256k1:
		return btcec.S256().N
	case CurveP256:
		return elliptic.P256().Params().N
	case CurveEdwards25519:
		return edwards.Edwards().N
	default:
		return nil
	}
}

// serializeCompressedP256 serializes a P-256 point in compressed format (33 bytes)
func serializeCompressedP256(x, y *big.Int) []byte {
	result := make([]byte, 33)
	if y.Bit(0) == 0 {
		result[0] = 0x02
	} else {
		result[0] = 0x03
	}
	xBytes := x.Bytes()
	copy(result[33-len(xBytes):], xBytes)
	return result
}

// leftPadTo32Bytes pads a big.Int to 32 bytes with leading zeros
func leftPadTo32Bytes(i *big.Int) []byte {
	padded := make([]byte, 32)
	if i == nil {
		return padded
	}
	bytes := i.Bytes()
	if len(bytes) > 32 {
		return bytes[len(bytes)-32:]
	}
	copy(padded[32-len(bytes):], bytes)
	return padded
}
