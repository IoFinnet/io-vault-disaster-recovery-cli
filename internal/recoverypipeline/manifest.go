// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package recoverypipeline

import (
	"encoding/json"
	"errors"
	"fmt"
)

// maxManifestBytes caps how much of a bundle's manifest.json is read — the
// manifest has no declared size of its own.
const maxManifestBytes = 16 * 1024 * 1024

var errUnsupportedManifestVersion = errors.New("unsupported bundle manifest version")

type bundleManifest struct {
	FormatVersion int             `json:"formatVersion"`
	SignerID      string          `json:"signerId"`
	Vaults        []manifestVault `json:"vaults"`
}

type manifestVault struct {
	VaultID          string         `json:"vaultId"`
	CurrentRequestID string         `json:"currentRequestId"` // omitted for orphans
	Files            []manifestFile `json:"files"`
}

type manifestFile struct {
	Path     string   `json:"path"`
	SHA256   string   `json:"sha256"`
	Bytes    int64    `json:"bytes"`
	Problems []string `json:"problems"` // omitted when healthy
}

func parseBundleManifest(raw []byte) (*bundleManifest, error) {
	var m bundleManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	if m.FormatVersion != 2 {
		return nil, fmt.Errorf("%w: %d", errUnsupportedManifestVersion, m.FormatVersion)
	}
	return &m, nil
}
