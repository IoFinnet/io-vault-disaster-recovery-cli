// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultsDataFilesZeroize(t *testing.T) {
	files := VaultsDataFiles{
		{File: "test1.json", Mnemonics: "word1 word2 word3"},
		{File: "test2.json", Mnemonics: "word4 word5 word6"},
	}

	files.Zeroize()

	for _, f := range files {
		assert.Equal(t, "", f.Mnemonics)
	}
}

func TestVaultsDataFilesZeroize_EmptySlice(t *testing.T) {
	files := VaultsDataFiles{}
	files.Zeroize() // should not panic
}

func TestVaultsDataFilesZeroize_EmptyMnemonics(t *testing.T) {
	files := VaultsDataFiles{
		{File: "test.json", Mnemonics: ""},
	}
	files.Zeroize() // should not panic
}

func restoreGlobalConfig(t *testing.T) {
	t.Helper()
	prev := config.GlobalConfig
	t.Cleanup(func() {
		config.GlobalConfig = prev
	})
}

func TestMnemonicsFormModel_Run_bundlePassThrough(t *testing.T) {
	restoreGlobalConfig(t)
	config.GlobalConfig = config.AppConfig{}

	bundlePath := makeBundleZip(t)
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(keyPath, []byte("dummy-key"), 0o644))

	m := NewMnemonicsForm(config.AppConfig{
		Filenames:       []string{bundlePath},
		PrivateKeyFiles: []string{keyPath},
	})
	files, err := m.Run()
	require.NoError(t, err)
	require.NotNil(t, files)
	assert.Equal(t, VaultsDataFiles{{File: bundlePath}}, *files)
	assert.Empty(t, config.GlobalConfig.ZipExtractedDirs)
}

func TestMnemonicsFormModel_Run_bundleWithLooseDR(t *testing.T) {
	restoreGlobalConfig(t)
	config.GlobalConfig = config.AppConfig{}

	bundlePath := makeBundleZip(t)
	drPath := filepath.Join(t.TempDir(), "share.dr")
	require.NoError(t, os.WriteFile(drPath, []byte{0xaa, 0xbb}, 0o644))
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(keyPath, []byte("dummy-key"), 0o644))

	m := NewMnemonicsForm(config.AppConfig{
		Filenames:       []string{bundlePath, drPath},
		PrivateKeyFiles: []string{keyPath},
	})
	files, err := m.Run()
	require.NoError(t, err)
	require.NotNil(t, files)
	assert.Equal(t, VaultsDataFiles{
		{File: bundlePath},
		{File: drPath},
	}, *files)
	assert.Equal(t, 2, m.totalFiles)
	assert.Empty(t, config.GlobalConfig.ZipExtractedDirs)
}

func TestIsBundleZip(t *testing.T) {
	assert.True(t, isBundleZip(makeBundleZip(t)))
	assert.False(t, isBundleZip(makeLegacyZip(t, []byte(`{"share":1}`))))
}

func TestEnsurePrivateKeyFile_keysPresetSkipsPrompt(t *testing.T) {
	restoreGlobalConfig(t)
	config.GlobalConfig = config.AppConfig{}

	keyPath := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(keyPath, []byte("dummy-key"), 0o644))

	m := NewMnemonicsForm(config.AppConfig{PrivateKeyFiles: []string{keyPath}})
	// .zip in the list means a bundle at this stage; keys already set so no prompt.
	err := m.ensurePrivateKeyFile(VaultsDataFiles{{File: "bundle.zip"}})
	assert.NoError(t, err)
	assert.Empty(t, config.GlobalConfig.PrivateKeyFiles)
}

func TestEnsurePrivateKeyFile_plainJSONNoPrompt(t *testing.T) {
	restoreGlobalConfig(t)
	config.GlobalConfig = config.AppConfig{}

	m := NewMnemonicsForm(config.AppConfig{})
	err := m.ensurePrivateKeyFile(VaultsDataFiles{{File: "vault.json"}})
	assert.NoError(t, err)
	assert.Empty(t, config.GlobalConfig.PrivateKeyFiles)
}
