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
	"sync"

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

// InputSet is Discover's output, shared across every Prepare call of one recovery attempt.
// Close it after the last one: it holds a copy of each input's mnemonics, which the
// frontend's own Zeroize can no longer reach.
type InputSet struct {
	artifacts []Artifact
	bundles   []BundleInfo
	warnings  []Warning
	cleanup   cleanupFunc
	closeOnce sync.Once
	closeErr  error
}

// Discover returns a non-nil set even on error, so the caller can always Close it.
// On error close immediately; on success, defer.
func Discover(files []ui.VaultsDataFile, presentation ErrorPresentation) (*InputSet, error) {
	artifacts, bundles, warnings, cleanup, err := discoverArtifacts(files, presentation)
	inputs := &InputSet{
		artifacts: artifacts,
		bundles:   bundles,
		warnings:  warnings,
		cleanup:   cleanup,
	}
	return inputs, err
}

// Close removes temp dirs and drops the set's mnemonic references — Go strings are
// immutable, so the bytes are not overwritten. Later calls return the first call's
// result. Safe on a nil receiver. No Prepare may follow it.
func (s *InputSet) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.cleanup != nil {
			s.closeErr = s.cleanup()
		}

		// Outside the error path: a failed removal must not leave mnemonics reachable.
		for i := range s.artifacts {
			s.artifacts[i].Mnemonics = ""
		}
		s.artifacts = nil
	})
	return s.closeErr
}

// BundleCurrentRequestIDs returns the manifest-declared current request id per vault,
// merged across all bundles. When bundles disagree for a vault the entry is omitted
// and the chain walk decides instead.
func (s *InputSet) BundleCurrentRequestIDs() map[string]string {
	if s == nil {
		return nil
	}
	seen := make(map[string]string)
	conflicts := make(map[string]bool)
	for _, b := range s.bundles {
		for vID, reqID := range b.CurrentRequestIDs {
			if prev, ok := seen[vID]; ok && prev != reqID {
				conflicts[vID] = true
			} else if !ok {
				seen[vID] = reqID
			}
		}
	}
	if len(conflicts) == 0 {
		return seen
	}
	merged := make(map[string]string, len(seen)-len(conflicts))
	for vID, reqID := range seen {
		if !conflicts[vID] {
			merged[vID] = reqID
		}
	}
	return merged
}

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
