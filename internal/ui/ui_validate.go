// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

import (
	"os"
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

func ValidateFiles(appConfig config.AppConfig) error {
	files := appConfig.Filenames

	// Make sure all files exist, and ensure they're unique
	{
		uniqueFiles := make(map[string]struct{})
		for _, file := range files {
			// read file and basic validate
			if _, err := os.Stat(file); err != nil {
				return errors2.Errorf("⚠ unable to see file `%s` - does it exist?: %s", file, err)
			}
			if _, ok := uniqueFiles[file]; ok {
				return errors2.Errorf("⚠ duplicate file `%s`", file)
			}
			uniqueFiles[file] = struct{}{}
		}
	}

	for _, file := range files {
		// read file and basic validate
		if _, err := os.Stat(file); err != nil {
			return errors2.Errorf("unable to see file `%s` - does it exist?: %s", file, err)
		}
		// fmt.Print("Reading file ", file, " ... ")

		content, err := os.ReadFile(file)
		if err != nil {
			return errors2.Errorf("unable to read file `%s`: %s", file, err)
		}
		if len(content) == 0 || content[0] != '{' {
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
