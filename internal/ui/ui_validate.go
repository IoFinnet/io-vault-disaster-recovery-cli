// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/config"
	errors2 "github.com/pkg/errors"
)

// The WORDS constant is defined in ui.go (24)

func (v VaultsDataFile) ValidateMnemonics() error {
	phrase := cleanMnemonicInput(v.Mnemonics)
	return ValidateMnemonics(phrase)
}

// ValidateMnemonics validates that the provided mnemonic has exactly WORDS number of words
func ValidateMnemonics(mnemonic string) error {
	words := strings.Split(mnemonic, " ")
	if len(words) != WORDS {
		return errors2.Errorf("⚠ wanted %d phrase words but got %d", WORDS, len(words))
	}
	return nil
}

// IsZipFile checks if a file is a ZIP archive
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

	return extractedFiles, nil
}

func ValidateFiles(appConfig config.AppConfig) error {
	files := appConfig.Filenames
	processedFiles := make([]string, 0)
	zipExtractedDirs := make([]string, 0)

	// First pass: check file existence and process ZIP files
	uniqueFiles := make(map[string]struct{})
	for _, file := range files {
		// Verify file exists
		if _, err := os.Stat(file); err != nil {
			return errors2.Errorf("⚠ unable to see file `%s` - does it exist?: %s", file, err)
		}

		// Prevent duplicates
		if _, ok := uniqueFiles[file]; ok {
			return errors2.Errorf("⚠ duplicate file `%s`", file)
		}
		uniqueFiles[file] = struct{}{}

		// Process ZIP files
		if IsZipFile(file) {
			extractedFiles, err := ProcessZipFile(file)
			if err != nil {
				return err
			}

			// Track temp directory for cleanup (extract path from any file)
			if len(extractedFiles) > 0 {
				zipExtractedDirs = append(zipExtractedDirs, filepath.Dir(extractedFiles[0]))
			}

			// Add extracted files to the processed list
			processedFiles = append(processedFiles, extractedFiles...)
			fmt.Printf("Extracted %d JSON files from ZIP archive `%s`\n", len(extractedFiles), file)
		} else {
			// Add regular files to the processed list
			processedFiles = append(processedFiles, file)
		}
	}

	// Update appConfig with the processed files (original + extracted from ZIP)
	appConfig.Filenames = processedFiles
	appConfig.ZipExtractedDirs = zipExtractedDirs

	// Second pass: validate all files are readable and proper JSON
	for _, file := range processedFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			// Clean up extracted files before returning error
			for _, dir := range zipExtractedDirs {
				os.RemoveAll(dir)
			}
			return errors2.Errorf("unable to read file `%s`: %s", file, err)
		}
		if len(content) == 0 || content[0] != '{' {
			// Clean up extracted files before returning error
			for _, dir := range zipExtractedDirs {
				os.RemoveAll(dir)
			}
			return errors2.Errorf("⚠ invalid file format, expecting json. first char is %s", content[:1])
		}
	}
	
	return nil
}

// CleanMnemonicInput processes a mnemonic phrase by removing line breaks and extra whitespace
func CleanMnemonicInput(input string) string {
	input = strings.Replace(input, "\n", "", -1)
	input = strings.Replace(input, "\r", "", -1)
	input = strings.TrimSpace(input)
	return input
}

// cleanMnemonicInput is an alias for CleanMnemonicInput for backward compatibility
func cleanMnemonicInput(input string) string {
	return CleanMnemonicInput(input)
}
