// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGetTSSPubKeyForEthereum_ShortCoordinates mirrors the CLI regression: a coordinate with a
// leading zero byte must still parse. See the root package test for the fixture derivation.
func TestGetTSSPubKeyForEthereum_ShortCoordinates(t *testing.T) {
	cases := []struct {
		name string
		x    string
		y    string
	}{
		{
			name: "short X",
			x:    "e3ae1974566ca06cc516d47e0fb165a674a3dabcfca15e722f0e3450f45889",
			y:    "2aeabe7e4531510116217f07bf4d07300de97e4874f81f533420a72eeb0bd6a4",
		},
		{
			name: "short Y",
			x:    "139ae46a1133f1f9d23f25efba0f6dd87bf7ddaf568a5fb9e0a3bfda73176237",
			y:    "995e555c8aabd263fd238833a12188b8a5ffbeb480ba0e3e6ec481a8991472",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x, ok := new(big.Int).SetString(tc.x, 16)
			require.True(t, ok)
			y, ok := new(big.Int).SetString(tc.y, 16)
			require.True(t, ok)
			require.Less(t, len(x.Bytes())+len(y.Bytes()), 64, "fixture must exercise a short coordinate")

			pubKey, address, err := getTSSPubKeyForEthereum(x, y)
			require.NoError(t, err)
			require.Equal(t, x, pubKey.X())
			require.Equal(t, y, pubKey.Y())
			require.Len(t, address, 42)
		})
	}
}
