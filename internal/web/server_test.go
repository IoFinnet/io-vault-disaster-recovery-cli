// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecoveryResult_Zeroize(t *testing.T) {
	result := RecoveryResult{
		Success:         true,
		Address:         "0xABC",
		EcdsaPrivateKey: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		TestnetWIF:      []byte("testnet-wif-value"),
		MainnetWIF:      []byte("mainnet-wif-value"),
		EddsaPrivateKey: []byte{0xCA, 0xFE, 0xBA, 0xBE},
		EddsaPublicKey:  "pubkey-hex",
	}

	result.Zeroize()

	// Sensitive fields must be zeroed
	assert.Equal(t, []byte{0, 0, 0, 0}, result.EcdsaPrivateKey)
	assert.Equal(t, make([]byte, len("testnet-wif-value")), result.TestnetWIF)
	assert.Equal(t, make([]byte, len("mainnet-wif-value")), result.MainnetWIF)
	assert.Equal(t, []byte{0, 0, 0, 0}, result.EddsaPrivateKey)

	// Non-sensitive fields must be untouched
	assert.True(t, result.Success)
	assert.Equal(t, "0xABC", result.Address)
	assert.Equal(t, "pubkey-hex", result.EddsaPublicKey)
}

func TestRecoveryResult_Zeroize_NilFields(t *testing.T) {
	result := RecoveryResult{
		Success: false,
	}

	// Must not panic on nil/empty fields
	assert.NotPanics(t, func() {
		result.Zeroize()
	})
}
