// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"archive/zip"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeZipWithEntry writes dir/zipName holding one entry, entryName, with srcPath's content.
func writeZipWithEntry(t *testing.T, dir, zipName, entryName, srcPath string) string {
	t.Helper()
	content, err := os.ReadFile(srcPath)
	require.NoError(t, err)
	path := filepath.Join(dir, zipName)
	f, err := os.Create(path)
	require.NoError(t, err)
	zw := zip.NewWriter(f)
	w, err := zw.Create(entryName)
	require.NoError(t, err)
	_, err = w.Write(content)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, f.Close())
	return path
}

func postVerifyWithFields(t *testing.T, uploads []uploadFixture, fields map[string]string) VerifyResponse {
	t.Helper()
	req := multipartRequest(t, "/api/verify", uploads, func(form *multipart.Writer) {
		for k, v := range fields {
			require.NoError(t, form.WriteField(k, v))
		}
	})
	rec := httptest.NewRecorder()
	newTestServer(t).handleVerify(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp VerifyResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp
}

// Two archives that both contain backup.json, sealed with different phrases, are each unlocked by
// their own "mnemonic_<archive>/<entry>" field.
func TestHandleVerify_SameEntryNameInTwoZipsUsesEachArchivesPhrase(t *testing.T) {
	dir := t.TempDir()
	a := writeZipWithEntry(t, dir, "a.zip", "backup.json", filepath.Join(fixtureTestFilesDir, "new_bvn.json"))
	b := writeZipWithEntry(t, dir, "b.zip", "backup.json", filepath.Join(fixtureTestFilesDir, "new_x2q.json"))

	resp := postVerifyWithFields(t, []uploadFixture{{path: a}, {path: b}}, map[string]string{
		formFieldMnemonicPfx + "a.zip/backup": fixtureMnemonicBvn,
		formFieldMnemonicPfx + "b.zip/backup": fixtureMnemonicX2q,
	})

	require.Len(t, resp.Sources, 2)
	for _, src := range resp.Sources {
		require.Equal(t, "decrypted", src.Level, src.Error)
	}
}

// The older "mnemonic_<entry>" field still works, but unlocks one entry only: it is never applied
// to a second export of the same name, which needs its own phrase.
func TestHandleVerify_PlainZipEntryFieldUnlocksOneEntryOnly(t *testing.T) {
	dir := t.TempDir()
	a := writeZipWithEntry(t, dir, "a.zip", "backup.json", filepath.Join(fixtureTestFilesDir, "new_bvn.json"))
	b := writeZipWithEntry(t, dir, "b.zip", "backup.json", filepath.Join(fixtureTestFilesDir, "new_x2q.json"))

	resp := postVerifyWithFields(t, []uploadFixture{{path: a}, {path: b}}, map[string]string{
		formFieldMnemonicPfx + "backup": fixtureMnemonicBvn,
	})

	require.Len(t, resp.Sources, 2)
	require.Equal(t, "decrypted", resp.Sources[0].Level, resp.Sources[0].Error)
	require.NotEqual(t, "decrypted", resp.Sources[1].Level, "the plain field must not unlock a second entry")
	require.NotEqual(t, "error", resp.Sources[1].Level, "the second entry was never given a phrase, so it is not a wrong-phrase error")
}
