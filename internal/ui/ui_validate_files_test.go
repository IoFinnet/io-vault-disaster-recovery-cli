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

type zipEntry struct {
	name string
	data []byte
}

// buildTestZip writes a synthetic zip into t.TempDir() and returns its path.
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
		{name: "manifest.json", data: []byte(`{"formatVersion":2}`)},
		{name: "dr/v1/share.dr", data: []byte{0x01, 0x02}},
	})
}

func makeLegacyZip(t *testing.T, shareJSON []byte) string {
	t.Helper()
	return buildTestZip(t, "legacy.zip", []zipEntry{
		{name: "share1.json", data: shareJSON},
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

	t.Run("bundle with loose .json", func(t *testing.T) {
		// Non-vault JSON peeks false (no vaults map); still allowed with a bundle.
		bundlePath := makeBundleZip(t)
		jsonPath := filepath.Join(t.TempDir(), "data.json")
		assert.NoError(t, os.WriteFile(jsonPath, shareJSON, 0o644))

		cfg := config.AppConfig{Filenames: []string{bundlePath, jsonPath}}
		err := ValidateFiles(&cfg)
		assert.NoError(t, err)
		assert.Equal(t, []string{bundlePath, jsonPath}, cfg.Filenames)
		assert.Empty(t, cfg.ZipExtractedDirs)
	})

	t.Run("bundle with legacy zip errors", func(t *testing.T) {
		bundlePath := makeBundleZip(t)
		legacyPath := makeLegacyZip(t, shareJSON)

		cfg := config.AppConfig{Filenames: []string{bundlePath, legacyPath}}
		err := ValidateFiles(&cfg)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "cannot mix a Virtual Signer bundle zip with a legacy vault-export ZIP")
		assert.ErrorContains(t, err, bundlePath)
		assert.ErrorContains(t, err, legacyPath)
		assert.Empty(t, cfg.ZipExtractedDirs)
	})

	t.Run("legacy JSON with bundle errors", func(t *testing.T) {
		bundlePath := makeBundleZip(t)
		legacyJSON := filepath.Join(t.TempDir(), "legacy.json")
		assert.NoError(t, os.WriteFile(legacyJSON, []byte(LegacyFlatNonceJSONForTest), 0o644))

		cfg := config.AppConfig{Filenames: []string{bundlePath, legacyJSON}}
		err := ValidateFiles(&cfg)
		assert.Error(t, err)
		assert.ErrorContains(t, err, legacyJSON)
		assert.ErrorContains(t, err, "legacy vault export")
		assert.ErrorContains(t, err, "request ID")
	})

	t.Run("legacy JSON with loose .dr errors", func(t *testing.T) {
		drPath := filepath.Join(t.TempDir(), "share.dr")
		assert.NoError(t, os.WriteFile(drPath, []byte{0xaa, 0xbb}, 0o644))
		legacyJSON := filepath.Join(t.TempDir(), "legacy.json")
		assert.NoError(t, os.WriteFile(legacyJSON, []byte(LegacyFlatNonceJSONForTest), 0o644))

		cfg := config.AppConfig{Filenames: []string{drPath, legacyJSON}}
		err := ValidateFiles(&cfg)
		assert.Error(t, err)
		assert.ErrorContains(t, err, legacyJSON)
		assert.ErrorContains(t, err, "legacy vault export")
		assert.ErrorContains(t, err, "request ID")
	})

	t.Run("mobile wrapper JSON with bundle allowed", func(t *testing.T) {
		// Mobile v4 and v5 share this pre-decrypt wrapper; neither is treated as legacy.
		bundlePath := makeBundleZip(t)
		mobileJSON := filepath.Join(t.TempDir(), "mobile.json")
		assert.NoError(t, os.WriteFile(mobileJSON, []byte(MobileWrapperJSONForTest), 0o644))

		cfg := config.AppConfig{Filenames: []string{bundlePath, mobileJSON}}
		err := ValidateFiles(&cfg)
		assert.NoError(t, err)
		assert.Equal(t, []string{bundlePath, mobileJSON}, cfg.Filenames)
	})

	t.Run("legacy JSON alone still fine", func(t *testing.T) {
		legacyJSON := filepath.Join(t.TempDir(), "legacy.json")
		assert.NoError(t, os.WriteFile(legacyJSON, []byte(LegacyFlatNonceJSONForTest), 0o644))

		cfg := config.AppConfig{Filenames: []string{legacyJSON}}
		err := ValidateFiles(&cfg)
		assert.NoError(t, err)
		assert.Equal(t, []string{legacyJSON}, cfg.Filenames)
	})

	t.Run("legacy JSON with mobile JSON allowed", func(t *testing.T) {
		// Reject only when a bundle or .dr is also present, not for mixed JSON alone.
		dir := t.TempDir()
		legacyJSON := filepath.Join(dir, "legacy.json")
		mobileJSON := filepath.Join(dir, "mobile.json")
		assert.NoError(t, os.WriteFile(legacyJSON, []byte(LegacyFlatNonceJSONForTest), 0o644))
		assert.NoError(t, os.WriteFile(mobileJSON, []byte(MobileWrapperJSONForTest), 0o644))

		cfg := config.AppConfig{Filenames: []string{legacyJSON, mobileJSON}}
		err := ValidateFiles(&cfg)
		assert.NoError(t, err)
		assert.Equal(t, []string{legacyJSON, mobileJSON}, cfg.Filenames)
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
