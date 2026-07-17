// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ziputils

import (
	"archive/zip"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/fileutils"
	errors2 "github.com/pkg/errors"
)

// IsZipFile checks if a file is a ZIP archive based on file extension
func IsZipFile(filename string) bool {
	return strings.ToLower(filepath.Ext(filename)) == ".zip"
}

// allowedZipExtensions are the file extensions ProcessZipFile accepts inside a flat ZIP archive:
// ".json" for legacy mnemonic-encrypted vault backups (mobile app exports), ".dr" for Virtual
// Signer disaster-recovery share files. Both are JSON documents, so both get the same
// first-byte-is-'{' sanity check below.
var allowedZipExtensions = map[string]bool{".json": true, ".dr": true}

// isIgnoredZipEntry reports whether a ZIP entry is OS-generated metadata rather
// than recovery payload. macOS Finder / Archive Utility inject a "__MACOSX/"
// folder of AppleDouble "._" resource-fork files (and ".DS_Store" entries) when
// creating archives; none of these are vault data and they must be skipped so a
// macOS-created ZIP of otherwise-flat files is still accepted.
func isIgnoredZipEntry(name string) bool {
	if strings.HasPrefix(name, "__MACOSX/") || strings.Contains(name, "/__MACOSX/") {
		return true
	}
	base := path.Base(name)
	return strings.HasPrefix(base, "._") || base == ".DS_Store"
}

// ProcessZipFile extracts JSON files from a ZIP archive to a temporary directory
// It returns a list of extracted file paths, or an error if the ZIP isn't valid
func ProcessZipFile(zipPath string) ([]string, error) {
	// Open the ZIP file
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, errors2.Errorf("unable to open ZIP file `%s`: %s", filepath.Base(zipPath), fileutils.StripPathFromError(err))
	}
	defer reader.Close()

	// Create a temporary directory to extract files
	tempDir, err := os.MkdirTemp("", "vault-recovery-zip-")
	if err != nil {
		return nil, errors2.Errorf("unable to create temporary directory: %s", err)
	}

	extractedFiles := make([]string, 0, len(reader.File))
	// Payload files are extracted flat, keyed by basename; track basenames so two
	// files from different directories can't silently overwrite each other.
	seenBasenames := make(map[string]string)

	// First pass: validate extensions. Directory structure is ignored entirely —
	// any .json/.dr file at any depth is treated as payload, and OS metadata
	// (macOS __MACOSX/._* and .DS_Store) is skipped.
	for _, f := range reader.File {
		if f.FileInfo().IsDir() || isIgnoredZipEntry(f.Name) {
			continue
		}
		if !allowedZipExtensions[strings.ToLower(path.Ext(f.Name))] {
			os.RemoveAll(tempDir)
			return nil, errors2.Errorf("ZIP file `%s` contains non-JSON files - only .json and .dr files are supported", filepath.Base(zipPath))
		}
	}

	// Second pass: Extract JSON/.dr files flat, by basename (we've already validated the extensions)
	for _, f := range reader.File {
		if f.FileInfo().IsDir() || isIgnoredZipEntry(f.Name) {
			continue
		}

		// Guard against basename collisions across directories, since we flatten the hierarchy
		base := path.Base(f.Name)
		if prev, ok := seenBasenames[base]; ok {
			os.RemoveAll(tempDir)
			return nil, errors2.Errorf("ZIP file `%s` contains multiple files named `%s` (`%s` and `%s`) - flatten the archive so each file name is unique", filepath.Base(zipPath), base, prev, f.Name)
		}
		seenBasenames[base] = f.Name

		// Extract file
		rc, err := f.Open()
		if err != nil {
			os.RemoveAll(tempDir)
			return nil, errors2.Errorf("unable to open file `%s` in ZIP archive: %s", f.Name, err)
		}

		// Create extracted file path
		extractPath := filepath.Join(tempDir, base)
		outFile, err := os.Create(extractPath)
		if err != nil {
			rc.Close()
			os.RemoveAll(tempDir)
			return nil, errors2.Errorf("unable to create extracted file `%s`: %s", filepath.Base(extractPath), err)
		}

		// Copy file contents
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			os.RemoveAll(tempDir)
			return nil, errors2.Errorf("unable to extract file `%s`: %s", f.Name, err)
		}

		// Read the first byte to verify it's a JSON file
		content, err := os.ReadFile(extractPath)
		if err != nil {
			os.RemoveAll(tempDir)
			return nil, errors2.Errorf("unable to read extracted file `%s`: %s", filepath.Base(extractPath), err)
		}
		if len(content) == 0 || content[0] != '{' {
			os.RemoveAll(tempDir)
			return nil, errors2.Errorf("⚠ invalid file format in ZIP archive, expecting JSON files. File `%s` first char is %s", f.Name, content[:1])
		}

		extractedFiles = append(extractedFiles, extractPath)
	}

	// Check if we found any JSON files
	if len(extractedFiles) == 0 {
		os.RemoveAll(tempDir)
		return nil, errors2.Errorf("ZIP file `%s` does not contain any JSON files", filepath.Base(zipPath))
	}

	return extractedFiles, nil
}
