// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/config"
	"github.com/stretchr/testify/assert"
)

// buildTestZip writes a synthetic zip into t.TempDir() and returns its path.
type zipEntry struct {
	name string
	data []byte
}

func buildTestZip(t *testing.T, filename string, entries []zipEntry) string {
	t.Helper()
	zipPath := filepath.Join(t.TempDir(), filename)
	f, err := os.Create(zipPath)
	assert.NoError(t, err)
	w := zip.NewWriter(f)
	for _, e := range entries {
		fw, err := w.Create(e.name)
		assert.NoError(t, err)
		_, err = fw.Write(e.data)
		assert.NoError(t, err)
	}
	assert.NoError(t, w.Close())
	assert.NoError(t, f.Close())
	return zipPath
}

func makeBundleZip(t *testing.T) string {
	t.Helper()
	return buildTestZip(t, "bundle.zip", []zipEntry{
		{name: "manifest.json", data: []byte(`{"version":2}`)},
		{name: "dr/v1/share.dr", data: []byte{0x01, 0x02}},
	})
}

func makeLegacyZip(t *testing.T, shareJSON []byte) string {
	t.Helper()
	return buildTestZip(t, "legacy.zip", []zipEntry{
		{name: "share1.json", data: shareJSON},
	})
}

func cleanupZipExtractedDirs(t *testing.T, cfg *config.AppConfig) {
	t.Helper()
	t.Cleanup(func() {
		for _, dir := range cfg.ZipExtractedDirs {
			_ = os.RemoveAll(dir)
		}
	})
}

func TestValidateFiles(t *testing.T) {
	shareJSON := []byte(`{"share":1}`)

	t.Run("bundle pass-through", func(t *testing.T) {
		// Bundle zip bytes start with 'P' (PK); a nil error proves the pass-2 JSON-shape exemption.
		bundlePath := makeBundleZip(t)
		cfg := config.AppConfig{Filenames: []string{bundlePath}}

		err := ValidateFiles(&cfg)
		assert.NoError(t, err)
		assert.Equal(t, []string{bundlePath}, cfg.Filenames)
		assert.Empty(t, cfg.ZipExtractedDirs)
	})

	t.Run("bundle with loose .dr", func(t *testing.T) {
		bundlePath := makeBundleZip(t)
		drPath := filepath.Join(t.TempDir(), "share.dr")
		assert.NoError(t, os.WriteFile(drPath, []byte{0xaa, 0xbb}, 0o644))

		cfg := config.AppConfig{Filenames: []string{bundlePath, drPath}}
		err := ValidateFiles(&cfg)
		assert.NoError(t, err)
		assert.Equal(t, []string{bundlePath, drPath}, cfg.Filenames)
		assert.Empty(t, cfg.ZipExtractedDirs)
	})

	t.Run("bundle with legacy zip allowed in this commit", func(t *testing.T) {
		// Becomes the Q4 hard error in commit 2; documents commit-1 behavior and will be inverted there.
		// Also covers legacy extraction + byte identity (no separate legacy-only case).
		bundlePath := makeBundleZip(t)
		legacyPath := makeLegacyZip(t, shareJSON)

		cfg := config.AppConfig{Filenames: []string{bundlePath, legacyPath}}
		err := ValidateFiles(&cfg)
		cleanupZipExtractedDirs(t, &cfg)
		assert.NoError(t, err)

		assert.Len(t, cfg.Filenames, 2)
		assert.Equal(t, bundlePath, cfg.Filenames[0])
		assert.NotEqual(t, legacyPath, cfg.Filenames[1]) // legacy zip extracted to a temp path
		assert.Len(t, cfg.ZipExtractedDirs, 1)

		extracted, err := os.ReadFile(cfg.Filenames[1])
		assert.NoError(t, err)
		assert.Equal(t, shareJSON, extracted)
	})

	t.Run("legacy zip with loose .dr still errors", func(t *testing.T) {
		// .dr is classified as loose (same mix path as .json); keep the non-obvious case.
		legacyPath := makeLegacyZip(t, shareJSON)
		drPath := filepath.Join(t.TempDir(), "share.dr")
		assert.NoError(t, os.WriteFile(drPath, []byte{0xaa, 0xbb}, 0o644))

		cfg := config.AppConfig{Filenames: []string{legacyPath, drPath}}
		err := ValidateFiles(&cfg)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "cannot mix ZIP and JSON files")
		assert.ErrorContains(t, err, legacyPath)
		assert.ErrorContains(t, err, drPath)
	})
}
