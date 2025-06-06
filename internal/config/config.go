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
	ZipExtractedDirs []string // Tracks temporary directories created for ZIP extraction
}

// GlobalConfig is a singleton instance available globally to track application state
var GlobalConfig AppConfig
