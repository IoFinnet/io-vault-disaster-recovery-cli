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
		name    string
		fixture string
		// wantPeek is the ui-side verdict; wantLegacy pins the pipeline-side
		// IsLegacy flag per vault. wantUnmarshalErr non-empty → the pipeline
		// unmarshal must fail with that substring (and wantLegacy is ignored).
		wantPeek         bool
		wantLegacy       map[string]bool
		wantUnmarshalErr string
	}{
		{
			name:       "legacy flat-nonce vault",
			fixture:    ui.LegacyFlatNonceJSONForTest,
			wantPeek:   true,
			wantLegacy: map[string]bool{"v1": true},
		},
		{
			name:       "mobile wrapper",
			fixture:    ui.MobileWrapperJSONForTest,
			wantPeek:   false,
			wantLegacy: map[string]bool{"v1": false},
		},
		{
			name: "mixed file one legacy one mobile",
			fixture: `{"vaults":{` +
				`"legacy":{"0":{"ciphertext":"YQ==","nonce":"YQ=="}},` +
				`"mobile":{"currentRequestId":"req-1","requests":{"req-1":{"ciphertext":"YQ==","nonce":"YQ=="}}}` +
				`}}`,
			wantPeek:   true,
			wantLegacy: map[string]bool{"legacy": true, "mobile": false},
		},
		{
			name: "requests present but currentRequestId missing",
			// Both sides must branch on "requests" presence, not currentRequestId.
			fixture:          `{"vaults":{"v1":{"requests":{"req-1":{"ciphertext":"YQ==","nonce":"YQ=="}}}}}`,
			wantPeek:         false,
			wantUnmarshalErr: "v4",
		},
		{
			name:             "requests present as null",
			fixture:          `{"vaults":{"v1":{"currentRequestId":"req-1","requests":null}}}`,
			wantPeek:         false,
			wantUnmarshalErr: "v4",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.fixture)
			assert.Equal(t, tc.wantPeek, ui.LooksLikeLegacyFlatNonceJSONForTest(content))

			var sd recoverypipeline.SavedData
			err := json.Unmarshal(content, &sd)
			if tc.wantUnmarshalErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantUnmarshalErr)
				return
			}
			require.NoError(t, err)
			for vaultID, wantLegacy := range tc.wantLegacy {
				require.Contains(t, sd.Vaults, vaultID)
				assert.Equal(t, wantLegacy, sd.Vaults[vaultID].IsLegacy, "vault %s", vaultID)
			}
		})
	}
}
