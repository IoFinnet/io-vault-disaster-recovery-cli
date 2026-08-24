// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package recoverypipeline

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/fileutils"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ziputils"
)

const (
	miB = int64(1024 * 1024)
	giB = 1024 * miB

	entryCapFloorBytes    = 64 * miB
	entryCapFallbackBytes = 1 * giB
	bundleCapFloorBytes   = 1 * giB
	// Encrypted payloads barely compress; 1000:1 is far beyond honest data.
	maxCompressionRatio = int64(1000)
)

type declaredFile struct {
	vaultID string
	manifestFile
}

// expandState is the mutable context shared across one expandBundle walk.
type expandState struct {
	tempDir        string
	sourceID       string
	declared       map[string]declaredFile
	hasManifest    bool
	bundleCap      int64
	readTotal      int64             // decompressed bytes read, whether kept or thrown away
	extractedByKey map[string]string // lower-cased cleaned path -> first entry name
	presentation   ErrorPresentation
}

// expandBundle extracts a Virtual Signer backup bundle into tempDir (caller-owned,
// already registered for cleanup).
//
// Algorithm: read manifest (or fall back to envelope-only) → index declarations →
// set a decompressed-byte budget → walk entries in zip order (reject / extract /
// reconcile) → warn about declared-but-absent paths. Every decompressed byte charges
// the budget, kept or not, so a stream of torn entries cannot drive unbounded work.
func expandBundle(zipPath, tempDir string, presentation ErrorPresentation) (
	artifacts []Artifact, info *BundleInfo, warnings []Warning, err error) {

	sourceID := filepath.Base(zipPath)

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("⚠ unable to open bundle `%s`: %s",
			presentation.path(zipPath), presentation.err(err))
	}
	defer reader.Close()

	manifest, manifestWarnings := readBundleManifest(&reader.Reader, sourceID)
	warnings = append(warnings, manifestWarnings...)

	info, declared, declaredTotal := indexManifest(manifest, sourceID)
	st := &expandState{
		tempDir:        tempDir,
		sourceID:       sourceID,
		declared:       declared,
		hasManifest:    manifest != nil,
		bundleCap:      computeBundleCap(manifest, declaredTotal, &reader.Reader, zipPath),
		extractedByKey: make(map[string]string),
		presentation:   presentation,
	}

	for _, f := range reader.File {
		if f.FileInfo().IsDir() || ziputils.IsIgnoredZipEntry(f.Name) {
			continue
		}
		if path.Clean(f.Name) == "manifest.json" {
			continue // already consumed; never an artifact
		}

		artifact, entryWarnings, stop := processBundleEntry(f, st)
		warnings = append(warnings, entryWarnings...)
		if stop {
			break
		}
		if artifact != nil {
			artifacts = append(artifacts, *artifact)
		}
	}

	warnings = append(warnings, warnDeclaredAbsent(manifest, st.extractedByKey, sourceID)...)
	return artifacts, info, warnings, nil
}

// processBundleEntry handles one zip member: guard checks, then budgeted extract
// and manifest reconcile. stop=true means the bundle budget is exhausted.
func processBundleEntry(f *zip.File, st *expandState) (art *Artifact, warnings []Warning, stop bool) {
	name := path.Clean(f.Name)

	// Reject entries that are unsafe, non-regular, have case-insensitive name collisions, or don't have a .dr extension.
	// Path safety: IsLocal covers absolute paths, '..', reserved names; backslash is a separator on Windows.
	if strings.Contains(f.Name, `\`) || !filepath.IsLocal(name) {
		return nil, []Warning{entryIgnored(st.sourceID, "",
			fmt.Sprintf("ignoring entry with unsafe path %q", f.Name))}, false
	}
	if !f.Mode().IsRegular() {
		return nil, []Warning{entryIgnored(st.sourceID, "",
			fmt.Sprintf("ignoring non-regular entry %q", f.Name))}, false
	}

	key := strings.ToLower(name)
	if first, ok := st.extractedByKey[key]; ok {
		return nil, []Warning{entryIgnored(st.sourceID, "",
			fmt.Sprintf("ignoring %q, which collides with earlier entry %q", f.Name, first))}, false
	}
	if !strings.EqualFold(path.Ext(name), ".dr") {
		return nil, []Warning{entryIgnored(st.sourceID, "",
			fmt.Sprintf("ignoring unsupported entry %q", f.Name))}, false
	}

	// Stop the whole walk once the decompressed-byte budget is spent.
	remaining := st.bundleCap - st.readTotal
	if remaining <= 0 {
		return nil, []Warning{entryIgnored(st.sourceID, "",
			fmt.Sprintf("stopping at the %d-byte bundle budget; %q and later entries skipped", st.bundleCap, f.Name))}, true
	}

	df, isDeclared := st.declared[key]

	// Declared: twice claimed size, floored at 64 MiB (even when claimed size is 0).
	// Undeclared: 1 GiB fallback. Never read past the remaining bundle budget.
	entryCap := entryCapFallbackBytes
	if isDeclared {
		entryCap = max(2*df.Bytes, entryCapFloorBytes)
	}
	limit := min(entryCap, remaining)

	// Extract under LimitReader. Charge what was decompressed even on failure, so an
	// archive full of over-cap entries cannot spend unbounded work for free.
	destPath := filepath.Join(st.tempDir, filepath.FromSlash(name))
	written, sum, extractErr := extractEntry(f, destPath, limit)
	st.readTotal += written
	if extractErr != nil {
		// limit < entryCap means the bundle budget (not the per-entry cap) was binding.
		if written > limit && limit < entryCap {
			return nil, []Warning{entryIgnored(st.sourceID, "",
				fmt.Sprintf("stopping at the %d-byte bundle budget while extracting %q; later entries skipped", st.bundleCap, f.Name))}, true
		}
		return nil, []Warning{entryIgnored(st.sourceID, df.vaultID,
			fmt.Sprintf("could not extract %q: %s", f.Name, st.presentation.err(extractErr)))}, false
	}

	// Keep + reconcile: mismatch/problems warn only; metadata never vetoes.
	st.extractedByKey[key] = f.Name
	warnings = reconcileKept(f.Name, st.sourceID, written, sum, df, isDeclared, st.hasManifest)
	return &Artifact{Path: destPath, SourceID: st.sourceID, ContentSHA256: sum}, warnings, false
}

func indexManifest(manifest *bundleManifest, sourceID string) (*BundleInfo, map[string]declaredFile, int64) {
	declared := make(map[string]declaredFile)
	if manifest == nil {
		return nil, declared, 0
	}

	info := &BundleInfo{
		SourceID:          sourceID,
		SignerID:          manifest.SignerID,
		CurrentRequestIDs: make(map[string]string, len(manifest.Vaults)),
	}

	var declaredTotal int64
	for _, v := range manifest.Vaults {
		if v.CurrentRequestID != "" {
			info.CurrentRequestIDs[v.VaultID] = v.CurrentRequestID
		}
		for _, mf := range v.Files {
			// Case-fold like extractedByKey / ProcessZipFile — macOS/Windows are case-insensitive.
			declared[strings.ToLower(path.Clean(mf.Path))] = declaredFile{vaultID: v.VaultID, manifestFile: mf}
			declaredTotal += mf.Bytes
		}
	}

	return info, declared, declaredTotal
}

// computeBundleCap chooses how many decompressed bytes may be read from this archive.
// The claimed size comes from the manifest when there is one, else from the zip headers;
// either way it is clamped by on-disk size × compression ratio, because both sources may
// lie upward (the stream still enforces the result).
func computeBundleCap(manifest *bundleManifest, declaredTotal int64, reader *zip.Reader, zipPath string) int64 {
	claimed := declaredTotal
	if manifest == nil {
		claimed = 0
		for _, f := range reader.File {
			claimed += int64(f.UncompressedSize64)
		}
	}

	// max() also absorbs a negative 2×claimed, which an overflowing claimed size produces.
	budget := max(2*claimed, bundleCapFloorBytes)
	st, statErr := os.Stat(zipPath)
	if statErr != nil {
		return budget
	}
	return min(budget, max(maxCompressionRatio*st.Size(), bundleCapFloorBytes))
}

// reconcileKept emits mismatch/problem/undeclared warnings but never drops the
// file — metadata is unauthenticated; decrypt decides usability later.
func reconcileKept(entryName, sourceID string, written int64, sum string, df declaredFile, isDeclared, hasManifest bool) []Warning {
	var warnings []Warning

	if isDeclared {
		if written != df.Bytes || !strings.EqualFold(sum, df.SHA256) {
			warnings = append(warnings, Warning{
				Code: WarningBundleFileMismatch, SourceID: sourceID, VaultID: df.vaultID,
				Message: fmt.Sprintf("%q does not match its manifest size or hash; keeping it anyway", entryName),
			})
		}
		if len(df.Problems) > 0 {
			warnings = append(warnings, Warning{
				Code: WarningBundleFileProblem, SourceID: sourceID, VaultID: df.vaultID,
				Message: fmt.Sprintf("manifest flags %q with problems %v; keeping it anyway", entryName, df.Problems),
			})
		}
		return warnings
	}

	if hasManifest {
		warnings = append(warnings, Warning{
			Code: WarningBundleFileMismatch, SourceID: sourceID,
			Message: fmt.Sprintf("%q is not declared in the manifest; keeping it anyway", entryName),
		})
	}
	return warnings
}

func warnDeclaredAbsent(manifest *bundleManifest, extractedByKey map[string]string, sourceID string) []Warning {
	if manifest == nil {
		return nil
	}

	var warnings []Warning
	for _, v := range manifest.Vaults {
		for _, mf := range v.Files {
			if _, ok := extractedByKey[strings.ToLower(path.Clean(mf.Path))]; !ok {
				warnings = append(warnings, Warning{
					Code: WarningBundleFileMismatch, SourceID: sourceID, VaultID: v.VaultID,
					Message: fmt.Sprintf("manifest declares %q but the archive does not contain it", mf.Path),
				})
			}
		}
	}
	return warnings
}

func entryIgnored(sourceID, vaultID, message string) Warning {
	return Warning{Code: WarningBundleEntryIgnored, SourceID: sourceID, VaultID: vaultID, Message: message}
}

// readBundleManifest loads the root manifest.json. Any failure downgrades to
// envelope-only expansion (nil manifest + manifest.ignored); only healthy v2 returns non-nil.
func readBundleManifest(reader *zip.Reader, sourceID string) (*bundleManifest, []Warning) {
	ignored := func(reason string) []Warning {
		return []Warning{{
			Code: WarningManifestIgnored, SourceID: sourceID,
			Message: fmt.Sprintf("ignoring manifest.json (%s); reading .dr envelopes directly", reason),
		}}
	}

	for _, f := range reader.File {
		if f.FileInfo().IsDir() || path.Clean(f.Name) != "manifest.json" {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return nil, ignored("unreadable")
		}

		raw, err := io.ReadAll(io.LimitReader(rc, maxManifestBytes+1))
		rc.Close()
		if err != nil {
			return nil, ignored("unreadable")
		}
		if int64(len(raw)) > maxManifestBytes {
			return nil, ignored("larger than the manifest size cap")
		}

		m, err := parseBundleManifest(raw)
		if err != nil {
			if errors.Is(err, errUnsupportedManifestVersion) {
				return nil, ignored(fmt.Sprintf("%s — this tool may be too old for this bundle", err))
			}
			return nil, ignored(err.Error())
		}
		return m, nil
	}

	return nil, ignored("not found at the archive root")
}

// extractEntry streams at most limit decompressed bytes to destPath while hashing.
// On any failure after create, the partial file is removed.
func extractEntry(f *zip.File, destPath string, limit int64) (written int64, sha256Hex string, err error) {
	rc, err := f.Open()
	if err != nil {
		return 0, "", err
	}
	defer rc.Close()

	if err := os.MkdirAll(filepath.Dir(destPath), fileutils.PermissionOwnerRWX); err != nil {
		return 0, "", err
	}

	out, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileutils.PermissionOwnerRW)
	if err != nil {
		return 0, "", err
	}
	defer func() {
		if err != nil {
			out.Close()
			os.Remove(destPath)
		}
	}()

	h := sha256.New()
	// limit+1 distinguishes "exactly at cap" from "over cap".
	written, err = io.Copy(io.MultiWriter(out, h), io.LimitReader(rc, limit+1))
	if err != nil {
		return written, "", err
	}
	if written > limit {
		err = fmt.Errorf("entry exceeds its %d-byte extraction cap", limit)
		return written, "", err
	}

	if err = out.Close(); err != nil {
		return written, "", err
	}
	return written, hex.EncodeToString(h.Sum(nil)), nil
}
