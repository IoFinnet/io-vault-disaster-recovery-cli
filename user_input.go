package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	errors2 "github.com/pkg/errors"
)

type VaultsDataFile struct {
	File      string
	Mnemonics string
}

func RunGetVaultsDataFiles(files []string) ([]VaultsDataFile, error) {
	fmt.Println("Preparing to decrypt the files")

	list := make([]VaultsDataFile, len(files))

	// Make sure all files exist, and ensure they're unique
	{
		uniqueFiles := make(map[string]struct{})
		for _, file := range files {
			// read file and basic validate
			if _, err := os.Stat(file); err != nil {
				return nil, errors2.Errorf("⚠ unable to see file `%s` - does it exist?: %s", file, err)
			}
			if _, ok := uniqueFiles[file]; ok {
				return nil, errors2.Errorf("⚠ duplicate file `%s`", file)
			}
			uniqueFiles[file] = struct{}{}
		}
	}

	for i, file := range files {

		// read file and basic validate
		if _, err := os.Stat(file); err != nil {
			return nil, errors2.Errorf("unable to see file `%s` - does it exist?: %s", file, err)
		}
		fmt.Print("Reading file ", file, " ... ")

		content, err := os.ReadFile(file)
		if err != nil {
			return nil, errors2.Errorf("unable to read file `%s`: %s", file, err)
		}
		if len(content) == 0 || content[0] != '{' {
			return nil, errors2.Errorf("⚠ invalid file format, expecting json. first char is %s", content[:1])
		}

		// Input secret passphrase
		phrase := ""
		err = huh.NewText().
			Title(fmt.Sprintf("Decrypt %s (file %d of %d)", file, i+1, len(files))).
			Value(&phrase).
			Placeholder(fmt.Sprintf("Enter the %d word passphrase", WORDS)).
			WithTheme(huh.ThemeBase16()).
			Run()
		if err != nil {
			return nil, errors2.Errorf("Unable to read passphrase")
		}

		// validate the passphrase
		phrase = strings.Replace(phrase, "\n", "", -1)
		phrase = strings.Replace(phrase, "\r", "", -1)
		phrase = strings.TrimSpace(phrase)
		words := strings.Split(phrase, " ")
		if len(words) != WORDS {
			return nil, errors2.Errorf("⚠ wanted %d phrase words but got %d", WORDS, len(words))
		}

		list[i] = VaultsDataFile{File: file, Mnemonics: phrase}
	}

	return list, nil
}

type VaultFormData struct {
	VaultID          string
	Name             string
	Quorum           int
	LastReShareNonce int
	NumberOfShares   int
}

/**
 * @return string: the id of the vault
 * @return error: if any error occurs
 */
func RunVaultPickerForm(vaultsData []VaultFormData) (string, error) {
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
