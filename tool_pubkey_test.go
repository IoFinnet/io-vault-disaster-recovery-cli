// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

import (
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pubKeyForScalar returns the secp256k1 public key coordinates for a small scalar.
func pubKeyForScalar(k uint32) (x, y *big.Int) {
	var modk secp256k1.ModNScalar
	modk.SetInt(k)
	pub := secp256k1.NewPrivateKey(&modk).PubKey()
	return new(big.Int).SetBytes(pub.X().Bytes()), new(big.Int).SetBytes(pub.Y().Bytes())
}

// TestGetTSSPubKeyForEthereum_LeadingZeroCoordinate is a regression test for coordinates whose
// high byte is zero. big.Int.Bytes() strips leading zeros, so building the uncompressed encoding
// by plain concatenation produced a 64-byte buffer instead of 65 and recovery failed outright
// with "malformed public key: invalid length: 64". This hits roughly 1 in 128 vaults, so it
// surfaced only as a flaky test.
//
// The scalars below are chosen because their public keys have a short coordinate:
// k=153 has a 31-byte X, k=122 has a 31-byte Y. k=1 is the both-full-length control.
func TestGetTSSPubKeyForEthereum_LeadingZeroCoordinate(t *testing.T) {
	tests := []struct {
		name               string
		scalar             uint32
		wantXLen, wantYLen int
	}{
		{"short X coordinate", 153, 31, 32},
		{"short Y coordinate", 122, 32, 31},
		{"both coordinates full length", 1, 32, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x, y := pubKeyForScalar(tt.scalar)

			// Guard the premise of the test: these vectors must really be short/full as claimed,
			// otherwise the regression would silently stop being exercised.
			require.Len(t, x.Bytes(), tt.wantXLen, "test vector premise: X byte length")
			require.Len(t, y.Bytes(), tt.wantYLen, "test vector premise: Y byte length")

			pubKey, addr, err := getTSSPubKeyForEthereum(x, y)
			require.NoError(t, err, "short coordinates must still parse")
			require.NotNil(t, pubKey)

			// The parsed key must be the point we asked for, not some shifted misparse.
			assert.Equal(t, 0, pubKey.X().Cmp(x), "recovered X must match")
			assert.Equal(t, 0, pubKey.Y().Cmp(y), "recovered Y must match")

			// Independent oracle: go-ethereum's own address derivation.
			expected := ethcrypto.PubkeyToAddress(*pubKey.ToECDSA()).Hex()
			assert.Equal(t, expected, addr, "address must match go-ethereum's derivation")
		})
	}
}

// TestGetTSSPubKeyForEthereum_NilCoordinates keeps the nil guard covered.
func TestGetTSSPubKeyForEthereum_NilCoordinates(t *testing.T) {
	one, _ := pubKeyForScalar(1)
	for _, tt := range []struct {
		name string
		x, y *big.Int
	}{
		{"nil x", nil, one},
		{"nil y", one, nil},
		{"both nil", nil, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := getTSSPubKeyForEthereum(tt.x, tt.y)
			assert.Error(t, err)
		})
	}
}
