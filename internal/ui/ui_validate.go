// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/config"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ziputils"
	errors2 "github.com/pkg/errors"
)

// ValidateExportFilename validates and sanitizes an export filename.
// It strips directory components, rejects empty/null-byte/hidden/non-JSON filenames,
// and returns the cleaned bare filename.
func commonValidateExportFilename(filename string) (string, error) {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return "", errors2.New("export filename cannot be empty")
	}
	if strings.ContainsRune(filename, 0) {
		return "", errors2.New("export filename contains invalid characters")
	}
	justFileName := filepath.Base(filename)
	if justFileName == "." || justFileName == "/" || justFileName == "" {
		return "", errors2.New("export filename is invalid")
	}
	if strings.HasPrefix(justFileName, ".") {
		return "", errors2.Errorf("export filename cannot be a hidden file: %s", justFileName)
	}
	if !strings.EqualFold(filepath.Ext(justFileName), ".json") {
		return "", errors2.Errorf("export filename must have .json extension, got: %s", justFileName)
	}
	return filename, nil
}

func ValidateExportFilenameForCli(filename string) error {
	sanitized, err := commonValidateExportFilename(filename)
	if err != nil {
		return errors2.Errorf("⚠ %s", err)
	}
	if _, err := os.Stat(sanitized); err == nil {
		return errors2.Errorf("⚠ export filename already exists: %s", sanitized)
	}
	return nil
}

// ScopeExportPath validates the filename, scopes it to the given base directory under a random subfolder each time
// Used by web mode to confine exported files to the server's temp directory.
func ScopeExportPathForWeb(filename string, baseDir string) (string, error) {
	sanitized, err := commonValidateExportFilename(filename)
	if err != nil {
		return "", err
	}
	justFileName := filepath.Base(sanitized)
	if sanitized != justFileName {
		return "", errors2.Errorf("export filename cannot include directory components: %s", filename)
	}

	uniqueSubfolder, err := os.MkdirTemp(baseDir, "req-")
	if err != nil {
		log.Printf("⚠ failed to create temporary subfolder %s: %v", uniqueSubfolder, err)
		return "", errors2.Errorf("failed to create temporary subfolder: %v", err)
	}

	fullPath := filepath.Join(uniqueSubfolder, justFileName)
	if _, err := os.Stat(fullPath); err == nil {
		// This error should not be possible to happen because the subfolder is random every time, but just in case, log it and return an error
		log.Printf("⚠ export filename already exists in the temporary directory: %s", fullPath)
		return "", errors2.Errorf("⚠ export filename already exists in the temporary directory: %s", filename)
	}
	return fullPath, nil
}

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

func ValidateFiles(appConfig *config.AppConfig) error {
	files := appConfig.Filenames
	processedFiles := make([]string, 0)
	zipExtractedDirs := make([]string, 0)

	// If appConfig already has extracted dirs from a previous run, keep them
	if len(appConfig.ZipExtractedDirs) > 0 {
		zipExtractedDirs = append(zipExtractedDirs, appConfig.ZipExtractedDirs...)
	}

	// First pass: check file existence and validate no mixing of ZIP and JSON
	uniqueFiles := make(map[string]struct{})
	hasZip := false
	hasJson := false
	var firstZipFile, firstJsonFile string

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

		// Track file types
		if ziputils.IsZipFile(file) {
			hasZip = true
			if firstZipFile == "" {
				firstZipFile = file
			}
		} else {
			hasJson = true
			if firstJsonFile == "" {
				firstJsonFile = file
			}
		}
	}

	// Validate no mixing of formats
	if hasZip && hasJson {
		return errors2.Errorf("⚠ cannot mix ZIP and JSON files. Found ZIP file '%s' and JSON file '%s'. Please provide either all JSON files or all ZIP files.",
			firstZipFile, firstJsonFile)
	}

	// Process files
	for _, file := range files {
		// Process ZIP files
		if ziputils.IsZipFile(file) {
			extractedFiles, err := ziputils.ProcessZipFile(file)
			if err != nil {
				return err
			}

			// Track temp directory for cleanup (extract path from any file)
			if len(extractedFiles) > 0 {
				extractDir := filepath.Dir(extractedFiles[0])
				zipExtractedDirs = append(zipExtractedDirs, extractDir)
			}

			// Add extracted files to the processed list
			processedFiles = append(processedFiles, extractedFiles...)
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
