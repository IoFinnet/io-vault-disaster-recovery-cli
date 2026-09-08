// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetTSSPubKeyForEthereum_ShortCoordinate guards against regressing to raw
// big.Int.Bytes(), which drops leading zeros and yields a 64-byte key that
// ParsePubKey rejects. Roughly 1 vault in 128 has such a coordinate, and the
// failure would only surface during an emergency recovery.
//
// The fixture is the generator times 122, the lowest scalar whose public key
// has a coordinate short enough to trigger the defect.
func TestGetTSSPubKeyForEthereum_ShortCoordinate(t *testing.T) {
	x, ok := new(big.Int).SetString("139ae46a1133f1f9d23f25efba0f6dd87bf7ddaf568a5fb9e0a3bfda73176237", 16)
	require.True(t, ok)
	y, ok := new(big.Int).SetString("995e555c8aabd263fd238833a12188b8a5ffbeb480ba0e3e6ec481a8991472", 16)
	require.True(t, ok)

	// If Y ever grows to a full 32 bytes this stops exercising the defect.
	require.Equal(t, 31, len(y.Bytes()), "fixture must keep a short Y coordinate")

	pubKey, address, err := getTSSPubKeyForEthereum(x, y)
	require.NoError(t, err)
	require.NotNil(t, pubKey)

	// Padding must not move the point.
	assert.Equal(t, 0, pubKey.X().Cmp(x))
	assert.Equal(t, 0, pubKey.Y().Cmp(y))
	assert.Equal(t, "0x872917cEC8992487651Ee633DBA73bd3A9dcA309", address)
}
