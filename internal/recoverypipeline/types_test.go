// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package recoverypipeline

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// A vault entry that fails to decode is reported with its vault id, so a user can tell which vault
// in a multi-vault export is broken.
func TestSavedData_ErrorNamesTheVault(t *testing.T) {
	var saved SavedData
	err := json.Unmarshal([]byte(`{"vaults":{"vault-abc":{"currentRequestId":"req-absent","requests":{}}}}`), &saved)
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault vault-abc:")
	require.Contains(t, err.Error(), `"currentRequestId" "req-absent" not present in "requests"`)
}

// Valid entries decode as before, in both shapes, and a file without vaults leaves the map nil.
func TestSavedData_DecodesBothShapes(t *testing.T) {
	var saved SavedData
	require.NoError(t, json.Unmarshal([]byte(`{"vaults":{
		"v4-vault":{"currentRequestId":"req-1","requests":{"req-1":{"ciphertext":"","cipherparams":{"iv":"","tag":""},"cipher":"aes-256-gcm","hash":""}}},
		"legacy-vault":{"2":{"ciphertext":"","cipherparams":{"iv":"","tag":""},"cipher":"aes-256-gcm","hash":""}}
	}}`), &saved))
	require.Len(t, saved.Vaults, 2)
	require.Equal(t, "req-1", saved.Vaults["v4-vault"].CurrentRequestID)
	require.True(t, saved.Vaults["legacy-vault"].IsLegacy)

	var empty SavedData
	require.NoError(t, json.Unmarshal([]byte(`{}`), &empty))
	require.Nil(t, empty.Vaults)
}
