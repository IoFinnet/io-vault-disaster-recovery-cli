// Copyright (C) 2025 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package hd

import (
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/base58"
)

// Xpub version bytes
var (
	// Standard BIP32 mainnet xpub version
	XpubVersionMainnet = []byte{0x04, 0x88, 0xB2, 0x1E}
	// Standard BIP32 testnet tpub version
	XpubVersionTestnet = []byte{0x04, 0x35, 0x87, 0xCF}
)

// Xpub structure constants
const (
	XpubTotalLength       = 78 // Total length without checksum
	XpubVersionLength     = 4
	XpubDepthOffset       = 4
	XpubFingerprintOffset = 5
	XpubFingerprintLength = 4
	XpubChildNumOffset    = 9
	XpubChildNumLength    = 4
	XpubChainCodeOffset   = 13
	XpubChainCodeLength   = 32
	XpubPublicKeyOffset   = 45
	XpubPublicKeyLength   = 33 // Compressed ECDSA public key
	XpubEdDSAKeyLength    = 33 // 0x00 prefix + 32-byte key for EdDSA
	XpubChecksumLength    = 4
)

// ParseXpub decodes a base58check-encoded extended public key
// Handles both standard BIP32 (78 bytes) and EdDSA variant (0x00 prefix + 32 bytes)
func ParseXpub(xpub string, curve Curve) (*ParsedXpub, error) {
	// Decode base58
	decoded := base58.Decode(xpub)
	if len(decoded) == 0 {
		return nil, fmt.Errorf("%w: failed to decode base58", ErrInvalidXpub)
	}

	// Minimum length is 78 bytes + 4 bytes checksum = 82 bytes
	if len(decoded) < XpubTotalLength+XpubChecksumLength {
		return nil, fmt.Errorf("%w: decoded length %d < expected %d", ErrInvalidXpub, len(decoded), XpubTotalLength+XpubChecksumLength)
	}

	// Verify checksum
	payload := decoded[:len(decoded)-XpubChecksumLength]
	checksumBytes := decoded[len(decoded)-XpubChecksumLength:]

	h := sha256.Sum256(payload)
	h2 := sha256.Sum256(h[:])
	for i := 0; i < XpubChecksumLength; i++ {
		if checksumBytes[i] != h2[i] {
			return nil, fmt.Errorf("%w: checksum verification failed", ErrInvalidXpub)
		}
	}

	// Parse fields
	parsed := &ParsedXpub{
		Version:     payload[0:XpubVersionLength],
		Depth:       payload[XpubDepthOffset],
		Fingerprint: payload[XpubFingerprintOffset : XpubFingerprintOffset+XpubFingerprintLength],
		ChildNumber: payload[XpubChildNumOffset : XpubChildNumOffset+XpubChildNumLength],
		ChainCode:   payload[XpubChainCodeOffset : XpubChainCodeOffset+XpubChainCodeLength],
		PublicKey:   payload[XpubPublicKeyOffset:],
	}

	// Validate public key format based on curve
	switch curve {
	case CurveSecp256k1, CurveP256:
		// ECDSA curves use 33-byte compressed public key
		if len(parsed.PublicKey) != XpubPublicKeyLength {
			return nil, fmt.Errorf("%w: expected %d-byte public key for %s, got %d",
				ErrInvalidXpub, XpubPublicKeyLength, curve, len(parsed.PublicKey))
		}
		// Compressed public key should start with 0x02 or 0x03
		if parsed.PublicKey[0] != 0x02 && parsed.PublicKey[0] != 0x03 {
			return nil, fmt.Errorf("%w: invalid compressed public key prefix for %s", ErrInvalidXpub, curve)
		}

	case CurveEdwards25519:
		// EdDSA uses 0x00 prefix + 32-byte key
		if len(parsed.PublicKey) != XpubEdDSAKeyLength {
			return nil, fmt.Errorf("%w: expected %d-byte public key for %s, got %d",
				ErrInvalidXpub, XpubEdDSAKeyLength, curve, len(parsed.PublicKey))
		}
		if parsed.PublicKey[0] != 0x00 {
			return nil, fmt.Errorf("%w: EdDSA public key should have 0x00 prefix", ErrInvalidXpub)
		}
		// Store just the 32-byte key portion
		parsed.PublicKey = parsed.PublicKey[1:]

	default:
		return nil, fmt.Errorf("%w: unsupported curve %s", ErrUnsupportedCurve, curve)
	}

	return parsed, nil
}

// ExtractChainCode returns only the chain code from an xpub string
func ExtractChainCode(xpub string, curve Curve) ([]byte, error) {
	parsed, err := ParseXpub(xpub, curve)
	if err != nil {
		return nil, err
	}
	return parsed.ChainCode, nil
}
