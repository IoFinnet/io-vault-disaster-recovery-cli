// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package config

type AppConfig struct {
	Filenames        []string
	NonceOverride    int
	QuorumOverride   int
	ExportKSFile     string
	PasswordForKS    string
	PrivateKeyFile   string   // Path to the ML-KEM-768 private key PEM used to decrypt Virtual Signer .dr files
	ZipExtractedDirs []string // Tracks temporary directories created for ZIP extraction
}

// GlobalConfig is a singleton instance available globally to track application state
var GlobalConfig AppConfig
