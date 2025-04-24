// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ziputils

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"

	errors2 "github.com/pkg/errors"
)

// IsZipFile checks if a file is a ZIP archive based on file extension
func IsZipFile(filename string) bool {
	return strings.ToLower(filepath.Ext(filename)) == ".zip"
}

// ProcessZipFile extracts JSON files from a ZIP archive to a temporary directory
// It returns a list of extracted file paths, or an error if the ZIP isn't valid
func ProcessZipFile(zipPath string) ([]string, error) {
	// Open the ZIP file
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, errors2.Errorf("unable to open ZIP file `%s`: %s", zipPath, err)
	}
	defer reader.Close()

	// Create a temporary directory to extract files
	tempDir, err := os.MkdirTemp("", "vault-recovery-zip-")
	if err != nil {
		return nil, errors2.Errorf("unable to create temporary directory: %s", err)
	}

	extractedFiles := make([]string, 0, len(reader.File))
	hasNestedDirs := false

	// First pass: Validate ZIP structure (only allow flat hierarchy)
	for _, f := range reader.File {
		// Skip directories
		if f.FileInfo().IsDir() {
			continue
		}

		// Check if there are nested directories
		if filepath.Dir(f.Name) != "." && filepath.Dir(f.Name) != "/" {
			hasNestedDirs = true
			break
		}

		// Check file extension
		if strings.ToLower(filepath.Ext(f.Name)) != ".json" {
			continue
		}
	}

	// Reject ZIPs with nested directories
	if hasNestedDirs {
		os.RemoveAll(tempDir)
		return nil, errors2.Errorf("ZIP file `%s` contains nested directories - only flat hierarchy of JSON files is supported", zipPath)
	}

	// Second pass: Extract JSON files
	for _, f := range reader.File {
		// Skip directories
		if f.FileInfo().IsDir() {
			continue
		}

		// Only process JSON files
		if strings.ToLower(filepath.Ext(f.Name)) != ".json" {
			continue
		}

		// Extract file
		rc, err := f.Open()
		if err != nil {
			os.RemoveAll(tempDir)
			return nil, errors2.Errorf("unable to open file `%s` in ZIP archive: %s", f.Name, err)
		}

		// Create extracted file path
		extractPath := filepath.Join(tempDir, filepath.Base(f.Name))
		outFile, err := os.Create(extractPath)
		if err != nil {
			rc.Close()
			os.RemoveAll(tempDir)
			return nil, errors2.Errorf("unable to create extracted file `%s`: %s", extractPath, err)
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
			return nil, errors2.Errorf("unable to read extracted file `%s`: %s", extractPath, err)
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
		return nil, errors2.Errorf("ZIP file `%s` does not contain any JSON files", zipPath)
	}

	//fmt.Printf("Extracted %d JSON files from ZIP archive `%s`\n", len(extractedFiles), zipPath)
	return extractedFiles, nil
}
