// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// shortCoordinateKeys are secp256k1 points k*G whose affine coordinates are shorter than 32 bytes,
// i.e. the big-endian value has at least one leading zero byte. Roughly 1 in 128 keys is affected,
// so recovery of such a vault must not depend on big.Int.Bytes() preserving the coordinate width.
var shortCoordinateKeys = []struct {
	name string
	x    string
	y    string
}{
	{
		// k=153: X is 31 bytes.
		name: "short X",
		x:    "e3ae1974566ca06cc516d47e0fb165a674a3dabcfca15e722f0e3450f45889",
		y:    "2aeabe7e4531510116217f07bf4d07300de97e4874f81f533420a72eeb0bd6a4",
	},
	{
		// k=122: Y is 31 bytes.
		name: "short Y",
		x:    "139ae46a1133f1f9d23f25efba0f6dd87bf7ddaf568a5fb9e0a3bfda73176237",
		y:    "995e555c8aabd263fd238833a12188b8a5ffbeb480ba0e3e6ec481a8991472",
	},
}

// TestGetTSSPubKeyForEthereum_ShortCoordinates: a coordinate with a leading zero byte must still
// parse and derive an address. Concatenating big.Int.Bytes() drops that byte and yields a 64-byte
// key that secp256k1.ParsePubKey rejects as "malformed public key: invalid length: 64".
func TestGetTSSPubKeyForEthereum_ShortCoordinates(t *testing.T) {
	for _, tc := range shortCoordinateKeys {
		t.Run(tc.name, func(t *testing.T) {
			x, ok := new(big.Int).SetString(tc.x, 16)
			require.True(t, ok)
			y, ok := new(big.Int).SetString(tc.y, 16)
			require.True(t, ok)
			require.Less(t, len(x.Bytes())+len(y.Bytes()), 64, "fixture must exercise a short coordinate")

			pubKey, address, err := getTSSPubKeyForEthereum(x, y)
			require.NoError(t, err)
			require.Equal(t, x, pubKey.X(), "X coordinate must survive the round trip")
			require.Equal(t, y, pubKey.Y(), "Y coordinate must survive the round trip")
			require.Len(t, address, 42)
		})
	}
}
