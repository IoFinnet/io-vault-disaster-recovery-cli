// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/config"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ziputils"
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
		if ziputils.IsZipFile(file) {
			extractedFiles, err := ziputils.ProcessZipFile(file)
			if err != nil {
				return err
			}

			// Track temp directory for cleanup (extract path from any file)
			if len(extractedFiles) > 0 {
				zipExtractedDirs = append(zipExtractedDirs, filepath.Dir(extractedFiles[0]))
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
