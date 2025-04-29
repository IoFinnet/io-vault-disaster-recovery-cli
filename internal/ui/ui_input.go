// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/config"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ziputils"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/list"
	errors2 "github.com/pkg/errors"
)

type (
	VaultsDataFile struct {
		File      string
		Mnemonics string
	}

	// MnemonicsFormModel is a struct that represents the model for the mnemonics entry.
	MnemonicsFormModel struct {
		filenames    []string
		totalFiles   int
		extractedAll bool
	}
)

func NewMnemonicsForm(config config.AppConfig) MnemonicsFormModel {
	return MnemonicsFormModel{
		filenames:    config.Filenames,
		totalFiles:   len(config.Filenames),
		extractedAll: false,
	}
}

func (m *MnemonicsFormModel) Run() (*[]VaultsDataFile, error) {
	filesWithMnemonics := make([]VaultsDataFile, 0, len(m.filenames))

	// Make a first pass to calculate the total number of files
	totalJSONFiles := 0
	var extractedFiles []string

	// First, determine if we're dealing with ZIP files and get the total count
	// and collect all extracted files
	extractedFilesMap := make(map[string]bool) // Use a map to deduplicate

	for _, pathname := range m.filenames {
		if strings.ToLower(filepath.Ext(pathname)) == ".zip" {
			// Process ZIP file to get a list of JSON files inside
			files, err := processZipFileForMnemonics(pathname)
			if err != nil {
				return nil, err
			}

			// Add all extracted files to our map (handles duplicates automatically)
			for _, file := range files {
				extractedFilesMap[file] = true
			}
		} else {
			// For regular JSON files, just count them
			totalJSONFiles++
		}
	}

	// Convert map keys to slice for easier processing
	for file := range extractedFilesMap {
		extractedFiles = append(extractedFiles, file)
	}

	// Add extracted files count to total
	totalJSONFiles += len(extractedFiles)

	// Update the total files count
	m.totalFiles = totalJSONFiles

	// Now process the files
	for _, pathname := range m.filenames {
		// Check if this is a ZIP file
		if strings.ToLower(filepath.Ext(pathname)) == ".zip" {
			m.extractedAll = true
			fmt.Printf("Processing ZIP file: %s\n", pathname)

			// Skip processing ZIPs here - we'll process all extracted files together below
			continue
		}

		// Process regular JSON files
		displayFileName := filepath.Base(pathname)

		input := huh.NewText().
			Key("phrase").
			Title(fmt.Sprintf("Mnemonics for %s", displayFileName)).
			Description(fmt.Sprintf("Enter the %d word phrase", WORDS)).
			Validate(func(input string) error {
				fileWithMnemonic := VaultsDataFile{File: pathname, Mnemonics: input}
				return fileWithMnemonic.ValidateMnemonics()
			})

		var form *huh.Form

		// Show the list of files added if there are more than one
		if len(filesWithMnemonics) > 0 {
			form = huh.NewForm(
				huh.NewGroup(
					huh.NewNote().Description(m.fileList(filesWithMnemonics)),
					input,
				),
			).WithTheme(huh.ThemeBase16())
		} else {
			form = huh.NewForm(huh.NewGroup(input)).WithTheme(huh.ThemeBase16())
		}

		err := form.Run()
		if err != nil {
			return nil, err
		}

		mnemonics := form.GetString("phrase")
		if mnemonics == "" {
			return nil, fmt.Errorf("phrase for %s is empty", displayFileName)
		}

		f := VaultsDataFile{File: pathname, Mnemonics: mnemonics}
		filesWithMnemonics = append(filesWithMnemonics, f)
	}

	// Process all extracted files from ZIPs
	if len(extractedFiles) > 0 {
		fmt.Printf("Processing %d extracted JSON files from ZIP archives\n", len(extractedFiles))

		for _, extractedFile := range extractedFiles {
			// Use the full filename from the ZIP
			fileName := filepath.Base(extractedFile)
			displayFileName := fileName

			// Get the base name just for the description
			baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))

			input := huh.NewText().
				Key("phrase").
				Title(fmt.Sprintf("Mnemonics for %s (from ZIP)", displayFileName)).
				Description(fmt.Sprintf("Enter the %d word phrase for %s signer", WORDS, baseName)).
				Validate(func(input string) error {
					fileWithMnemonic := VaultsDataFile{File: extractedFile, Mnemonics: input}
					return fileWithMnemonic.ValidateMnemonics()
				})

			var form *huh.Form

			// Show the list of files added if there are more than one
			if len(filesWithMnemonics) > 0 {
				form = huh.NewForm(
					huh.NewGroup(
						huh.NewNote().Description(m.fileList(filesWithMnemonics)),
						input,
					),
				).WithTheme(huh.ThemeBase16())
			} else {
				form = huh.NewForm(huh.NewGroup(input)).WithTheme(huh.ThemeBase16())
			}

			err := form.Run()
			if err != nil {
				return nil, err
			}

			mnemonics := form.GetString("phrase")
			if mnemonics == "" {
				return nil, fmt.Errorf("phrase for %s is empty", displayFileName)
			}

			f := VaultsDataFile{File: extractedFile, Mnemonics: mnemonics}
			filesWithMnemonics = append(filesWithMnemonics, f)
		}
	}

	fmt.Println(m.fileList(filesWithMnemonics))
	fmt.Print("All mnemonics entered\n\n")

	return &filesWithMnemonics, nil
}

// processZipFileForMnemonics extracts JSON files from a ZIP archive
// and prepares them for mnemonic entry
func processZipFileForMnemonics(zipPath string) ([]string, error) {
	// Use the ziputils package to extract the files
	extractedFiles, err := ziputils.ProcessZipFile(zipPath)
	if err != nil {
		return nil, err
	}

	// Get the temp directory where files were extracted
	if len(extractedFiles) > 0 {
		tempDir := filepath.Dir(extractedFiles[0])
		fmt.Printf("Extracted files to temporary directory: %s\n", tempDir)

		// Track this directory in a global variable that main.go can access
		config.GlobalConfig.ZipExtractedDirs = append(config.GlobalConfig.ZipExtractedDirs, tempDir)
	}

	return extractedFiles, nil
}

func (m *MnemonicsFormModel) fileList(filesWithMnemonics []VaultsDataFile) string {
	if len(filesWithMnemonics) == 0 {
		return ""
	}

	special := lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}
	checklistEnumStyle := func(items list.Items, index int) lipgloss.Style {
		return lipgloss.NewStyle().
			Foreground(special).
			PaddingRight(1)
	}

	checklistEnum := func(items list.Items, index int) string {
		return "✓"
	}

	l := list.New().
		Enumerator(checklistEnum).
		EnumeratorStyleFunc(checklistEnumStyle)

	for i, f := range filesWithMnemonics {
		// Always use the precalculated total files count
		l = l.Item(fmt.Sprintf("%s (file %d of %d)", filepath.Base(f.File), i+1, m.totalFiles))
	}

	return l.String()
}

/**
 * VaultPickerItem is a struct that represents the model for the vault picker form.
 */
type VaultPickerItem struct {
	VaultID          string
	Name             string
	Quorum           int
	LastReShareNonce int
	NumberOfShares   int
}

func RunVaultPickerForm(vaultsData []VaultPickerItem) (string, error) {
	var chosenVaultId string

	vaultSelectOptions := make([]huh.Option[string], len(vaultsData))
	for i, vault := range vaultsData {
		vaultSelectOptions[i] = huh.NewOption(fmt.Sprintf("%s (%d/%d)", vault.Name, vault.NumberOfShares, vault.Quorum), vault.VaultID)
	}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select a vault").
				Options(vaultSelectOptions...).
				Value(&chosenVaultId),
		),
	).WithTheme(huh.ThemeBase16())
	err := form.Run()
	if err != nil {
		return "", errors2.Wrapf(err, "unable to run form")
	}
	if chosenVaultId == "" {
		fmt.Println("No vault selected")
		return "", errors2.Errorf("No vault selected")
	}
	return chosenVaultId, nil
}
