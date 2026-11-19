// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func postRecover(t *testing.T, uploads []uploadFixture, fields map[string]string) RecoveryResult {
	t.Helper()
	req := multipartRequest(t, "/api/recover", uploads, func(form *multipart.Writer) {
		for k, v := range fields {
			require.NoError(t, form.WriteField(k, v))
		}
	})
	rec := httptest.NewRecorder()
	newTestServer(t).handleRecovery(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var result RecoveryResult
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	return result
}

// The results page shows which reshare and threshold the keys were rebuilt from.
func TestHandleRecovery_ReportsReshareAndThreshold(t *testing.T) {
	result := postRecover(t, lqnsUploads(), map[string]string{"vaultId": fixtureLqnsVaultID})
	require.True(t, result.Success, result.ErrorMessage)
	require.Equal(t, fixtureLqnsAddress, result.Address)
	// The lqns fixtures are legacy flat-nonce exports, so the reshare is identified by its nonce;
	// /api/verify reports the same value as the vault's current reshare.
	require.Equal(t, "4", result.RequestID)
	require.Equal(t, 3, result.Threshold)
	require.Equal(t, 3, result.SharesUsed)
}

func TestHandleRecovery_ThresholdOverrideIsReported(t *testing.T) {
	result := postRecover(t, lqnsUploads(), map[string]string{"vaultId": fixtureLqnsVaultID, "quorumOverride": "2"})
	require.True(t, result.Success, result.ErrorMessage)
	require.Equal(t, 2, result.Threshold)
}

func TestHandleRecovery_FailureCarriesNoDetails(t *testing.T) {
	result := postRecover(t, lqnsUploads()[:1], map[string]string{"vaultId": fixtureLqnsVaultID})
	require.False(t, result.Success)
	require.Empty(t, result.RequestID)
	require.Zero(t, result.Threshold)
}
