// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package recoverypipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ziputils"
)

// Artifact is one input file the decode step reads.
type Artifact struct {
	Path          string
	Mnemonics     string // empty for Virtual Signer .dr files
	SourceID      string // bundle filename, or the input path for direct inputs
	ContentSHA256 string
}

// BundleInfo is manifest metadata for a later selection step. Identifiers only.
type BundleInfo struct {
	SourceID          string
	SignerID          string
	CurrentRequestIDs map[string]string // vaultID -> currentRequestId at bundle time
}

type cleanupFunc func() error

// discoverArtifacts turns frontend inputs into the flat list decode walks.
// Bundle zips expand into temp dirs registered for cleanup before expansion
// starts, so partial work is always removed. Content-identical artifacts are
// dropped (first wins) — duplicate shares crash reconstruction later.
func discoverArtifacts(files []ui.VaultsDataFile, presentation ErrorPresentation) (
	[]Artifact, []BundleInfo, []Warning, cleanupFunc, error) {

	var (
		artifacts []Artifact
		bundles   []BundleInfo
		warnings  []Warning
		tempDirs  []string
	)

	cleanup := func() error {
		var firstErr error
		for _, dir := range tempDirs {
			if err := os.RemoveAll(dir); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}

	for _, file := range files {
		if ziputils.IsBundleZip(file.File) {
			tempDir, err := os.MkdirTemp("", "vault-recovery-bundle-")
			if err != nil {
				return nil, nil, warnings, cleanup, fmt.Errorf(
					"⚠ unable to create a temporary directory for bundle `%s`: %s",
					presentation.path(file.File), presentation.err(err))
			}
			// Register before expand so partial extraction is always cleaned up.
			tempDirs = append(tempDirs, tempDir)

			bundleArtifacts, info, bundleWarnings, err := expandBundle(file.File, tempDir, presentation)
			warnings = append(warnings, bundleWarnings...)
			if err != nil {
				return nil, nil, warnings, cleanup, err
			}

			artifacts = append(artifacts, bundleArtifacts...)
			if info != nil {
				bundles = append(bundles, *info)
			}
			continue
		}

		// .json / .dr / non-bundle zips pass through; dedup hashes them once.
		artifacts = append(artifacts, Artifact{
			Path: file.File, Mnemonics: file.Mnemonics, SourceID: file.File,
		})
	}

	deduped, dedupWarnings := dedupArtifacts(artifacts, presentation)
	warnings = append(warnings, dedupWarnings...)
	return deduped, bundles, warnings, cleanup, nil
}

// dedupArtifacts keeps the first artifact for each content hash (input order).
// Prefers Artifact.ContentSHA256 when already set (bundle extract); otherwise
// hashes the file once. Unreadable files are kept so decode reports them.
func dedupArtifacts(artifacts []Artifact, presentation ErrorPresentation) ([]Artifact, []Warning) {
	type seenArt struct {
		path     string
		sourceID string
	}
	seen := make(map[string]seenArt, len(artifacts))
	kept := make([]Artifact, 0, len(artifacts))
	var warnings []Warning

	for _, a := range artifacts {
		// Identical content under different paths must collapse to one share
		// or reconstruction later divides by zero.
		sum := a.ContentSHA256
		if sum == "" {
			var err error
			sum, err = sha256File(a.Path)
			if err != nil {
				// Same unreadability decode will hit — don't mask it here.
				kept = append(kept, a)
				continue
			}
			a.ContentSHA256 = sum
		}

		if prev, ok := seen[sum]; ok {
			warnings = append(warnings, Warning{
				Code:     WarningDuplicateArtifact,
				SourceID: a.SourceID,
				Message: fmt.Sprintf("ignoring %s (from %s): identical content to %s (from %s)",
					presentation.path(a.Path), presentation.path(a.SourceID),
					presentation.path(prev.path), presentation.path(prev.sourceID)),
			})
			continue
		}

		seen[sum] = seenArt{path: a.Path, sourceID: a.SourceID}
		kept = append(kept, a)
	}

	return kept, warnings
}

func sha256File(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
