// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui_test

import (
	"encoding/json"
	"testing"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/recoverypipeline"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLegacyPeekMatchesRecoveryPipelineUnmarshal(t *testing.T) {
	cases := []struct {
		name          string
		fixture       string
		wantPeek      bool
		wantUnmarshal bool // false → recoverypipeline.SavedData unmarshal must error
		check         func(t *testing.T, sd recoverypipeline.SavedData)
	}{
		{
			name:          "legacy flat-nonce vault",
			fixture:       ui.LegacyFlatNonceJSONForTest,
			wantPeek:      true,
			wantUnmarshal: true,
			check: func(t *testing.T, sd recoverypipeline.SavedData) {
				require.Contains(t, sd.Vaults, "v1")
				assert.True(t, sd.Vaults["v1"].IsLegacy)
			},
		},
		{
			name:          "mobile wrapper",
			fixture:       ui.MobileWrapperJSONForTest,
			wantPeek:      false,
			wantUnmarshal: true,
			check: func(t *testing.T, sd recoverypipeline.SavedData) {
				require.Contains(t, sd.Vaults, "v1")
				assert.False(t, sd.Vaults["v1"].IsLegacy)
			},
		},
		{
			name: "mixed file one legacy one mobile",
			fixture: `{"vaults":{` +
				`"legacy":{"0":{"ciphertext":"YQ==","nonce":"YQ=="}},` +
				`"mobile":{"currentRequestId":"req-1","requests":{"req-1":{"ciphertext":"YQ==","nonce":"YQ=="}}}` +
				`}}`,
			wantPeek:      true,
			wantUnmarshal: true,
			check: func(t *testing.T, sd recoverypipeline.SavedData) {
				legacyCount := 0
				for _, e := range sd.Vaults {
					if e.IsLegacy {
						legacyCount++
					}
				}
				assert.GreaterOrEqual(t, legacyCount, 1)
			},
		},
		{
			name: "requests present but currentRequestId missing",
			// Both sides must branch on "requests" presence, not currentRequestId.
			fixture:       `{"vaults":{"v1":{"requests":{"req-1":{"ciphertext":"YQ==","nonce":"YQ=="}}}}}`,
			wantPeek:      false,
			wantUnmarshal: false,
		},
		{
			name:          "requests present as null",
			fixture:       `{"vaults":{"v1":{"currentRequestId":"req-1","requests":null}}}`,
			wantPeek:      false,
			wantUnmarshal: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.fixture)
			assert.Equal(t, tc.wantPeek, ui.LooksLikeLegacyFlatNonceJSONForTest(content))

			var sd recoverypipeline.SavedData
			err := json.Unmarshal(content, &sd)
			if tc.wantUnmarshal {
				require.NoError(t, err)
				if tc.check != nil {
					tc.check(t, sd)
				}
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "v4")
			}
		})
	}
}
