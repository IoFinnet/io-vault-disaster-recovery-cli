// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package recoverypipeline

import "github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"

// Artifact is one input file the decode step reads.
type Artifact struct {
	Path      string
	Mnemonics string // empty for Virtual Signer .dr files
}

// discoverArtifacts turns frontend inputs into the flat list decode walks. Direct inputs map
// one-to-one; expanding archives into temporary files comes later.
func discoverArtifacts(files []ui.VaultsDataFile) ([]Artifact, error) {
	artifacts := make([]Artifact, 0, len(files))
	for _, file := range files {
		artifacts = append(artifacts, Artifact{Path: file.File, Mnemonics: file.Mnemonics})
	}
	return artifacts, nil
}
