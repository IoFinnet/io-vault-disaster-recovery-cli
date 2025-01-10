// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

import (
	"fmt"
	"path/filepath"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/config"
	"github.com/cdfmlr/ellipsis"
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
		filenames []string
	}
)

func NewMnemonicsForm(config config.AppConfig) MnemonicsFormModel {
	return MnemonicsFormModel{
		filenames: config.Filenames,
	}
}

func (m MnemonicsFormModel) Run() (*[]VaultsDataFile, error) {
	filesWithMnemonics := make([]VaultsDataFile, 0, len(m.filenames))

	for _, pathname := range m.filenames {
		displayFileName := ellipsis.Centering(filepath.Base(pathname), 64)

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

	fmt.Println(m.fileList(filesWithMnemonics))
	fmt.Print("All mnemonics entered\n\n")

	return &filesWithMnemonics, nil
}

func (m MnemonicsFormModel) fileList(filesWithMnemonics []VaultsDataFile) string {
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
		l = l.Item(fmt.Sprintf("%s (file %d of %d)", filepath.Base(f.File), i+1, len(m.filenames)))
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
