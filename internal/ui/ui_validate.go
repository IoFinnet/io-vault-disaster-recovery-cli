// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

// Validates that a string is not vulnerable to ANSI injection attacks if printed to terminal. 
// Checks if the string contains any ANSI control codes. 
func validateStringIsSafeForShell(fileName string) (error, string) {
	// See https://pkg.go.dev/unicode#CategoryAliases
	const forbiddenPattern = `\p{Control}`
	if matched := regexp.MustCompile(forbiddenPattern).FindAllString(fileName, 1); len(matched) > 0 {
		matchedString := strconv.Quote(matched[0])
		return errors2.Errorf("Character not allowed %s", matchedString), matchedString
	}

	return nil, ""
}

// Prevent user input from containing any ANSI escape characters, that if printed to terminal later would allow for ANSI injection attacks.
func ValidateUserInputsAreSafe(appConfig *config.AppConfig) error {
	//File names
	for idx, fileName := range appConfig.Filenames {
		if err, _ := validateStringIsSafeForShell(fileName); err != nil {
			return errors2.Errorf("⚠ invalid file name at position %d. %s", idx+1, err)
		}
	}

	//Export KS file
	if err, _ := validateStringIsSafeForShell(appConfig.ExportKSFile); err != nil {
		return errors2.Errorf("⚠ invalid export file name. %s", err)
	}

	//Zip extracted dirs
	for idx, dir := range appConfig.ZipExtractedDirs {
		if err, _ := validateStringIsSafeForShell(dir); err != nil {
			return errors2.Errorf("⚠ invalid zip extracted dir name, position %d. %s", idx+1, err)
		}
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
