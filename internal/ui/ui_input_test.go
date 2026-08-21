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

// resetGlobalConfig zeroes config.GlobalConfig for the test and restores the
// previous value on cleanup.
func resetGlobalConfig(t *testing.T) {
	t.Helper()
	prev := config.GlobalConfig
	config.GlobalConfig = config.AppConfig{}
	t.Cleanup(func() {
		config.GlobalConfig = prev
	})
}

func TestMnemonicsFormModel_Run_bundles(t *testing.T) {
	bundlePath := makeBundleZip(t)
	drPath := filepath.Join(t.TempDir(), "share.dr")
	require.NoError(t, os.WriteFile(drPath, []byte{0xaa, 0xbb}, 0o644))

	// ensurePrivateKeyFile only checks that keys were supplied, never reads them,
	// so a placeholder path suffices.
	keys := []string{"unused.pem"}

	tests := []struct {
		name  string
		files []string
	}{
		{"bundle alone", []string{bundlePath}},
		{"bundle with loose .dr", []string{bundlePath, drPath}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetGlobalConfig(t)

			m := NewMnemonicsForm(config.AppConfig{Filenames: tt.files, PrivateKeyFiles: keys})
			files, err := m.Run()
			require.NoError(t, err)
			require.NotNil(t, files)

			want := make(VaultsDataFiles, 0, len(tt.files))
			for _, f := range tt.files {
				want = append(want, VaultsDataFile{File: f})
			}
			assert.Equal(t, want, *files)
			assert.Equal(t, len(tt.files), m.totalFiles)
			assert.Empty(t, config.GlobalConfig.ZipExtractedDirs)
		})
	}
}

func TestEnsurePrivateKeyFile_keysPresetSkipsPrompt(t *testing.T) {
	resetGlobalConfig(t)

	m := NewMnemonicsForm(config.AppConfig{PrivateKeyFiles: []string{"unused.pem"}})
	// .zip in the list means a bundle at this stage; keys already set so no prompt.
	err := m.ensurePrivateKeyFile(VaultsDataFiles{{File: "bundle.zip"}})
	assert.NoError(t, err)
	assert.Empty(t, config.GlobalConfig.PrivateKeyFiles)
}

func TestEnsurePrivateKeyFile_plainJSONNoPrompt(t *testing.T) {
	resetGlobalConfig(t)

	m := NewMnemonicsForm(config.AppConfig{})
	err := m.ensurePrivateKeyFile(VaultsDataFiles{{File: "vault.json"}})
	assert.NoError(t, err)
	assert.Empty(t, config.GlobalConfig.PrivateKeyFiles)
}
