// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/wif"
	"github.com/charmbracelet/lipgloss"
)

const (
	WORDS         = 24
	v2MagicPrefix = "_V2_"
)

var (
	// ANSI escape seqs for colours in the terminal
	ansiCodes = map[string]string{
		"bold":        "\033[1m",
		"invertOn":    "\033[7m",
		"darkRedBG":   "\033[41m",
		"darkGreenBG": "\033[42m",
		"reset":       "\033[0m",
	}
)

func main() {
	vaultID := flag.String("vault-id", "", "(Optional) The vault id to export the keys for.")
	nonceOverride := flag.Int("nonce", -1, "(Optional) Reshare Nonce override. Try it if the tool advises you to do so.")
	quorumOverride := flag.Int("threshold", 0, "(Optional) Vault Quorum (Threshold) override. Try it if the tool advises you to do so.")
	passwordForKS := flag.String("password", "", "(Optional) Encryption password for the Ethereum wallet v3 file; use with -export")
	exportKSFile := flag.String("export", "wallet.json", "(Optional) Filename to export a Ethereum wallet v3 JSON to; use with -password.")

	flag.Parse()
	files := flag.Args()
	if len(files) < 1 {
		fmt.Println("Please supply some input files on the command line. \nExample: recovery-tool.exe [-flags] file1.json file2.json … \n\nOptional flags:")
		flag.PrintDefaults()
		return
	}

	fmt.Print(banner())

	appConfig := AppConfig{
		filenames:      files,
		nonceOverride:  *nonceOverride,
		quorumOverride: *quorumOverride,
		exportKSFile:   *exportKSFile,
		passwordForKS:  *passwordForKS,
	}

	// First validate that files exist and are readable
	if err := ValidateFiles(appConfig); err != nil {
		fmt.Print(errorBox(err))
		os.Exit(1)
	}

	/**
	 * Run the steps to get the menmonics
	 */
	// var vaultsDataFiles []VaultsDataFile = make([]VaultsDataFile, 0, len(appConfig.filenames))
	f := NewMnemonicsForm(appConfig)
	vaultsDataFiles, err := f.Run()
	if err != nil {
		// if err := f.Run(&vaultsDataFiles); err != nil {
		fmt.Println(errorBox(err))
		os.Exit(1)
	}
	if vaultsDataFiles == nil {
		fmt.Println("No vaults data files were selected.")
		os.Exit(0)
	}

	/**
	 * Retrieve vaults information and select a vault
	 */
	_, _, _, vaultsFormInfo, err := runTool(*vaultsDataFiles, nil, nonceOverride, quorumOverride, exportKSFile, passwordForKS)
	if err != nil {
		fmt.Printf("Failed to run tool to retrieve vault information: %s\n", err)
		os.Exit(1)
	}

	var selectedVaultId string
	// If the vault ID is not provided, run the vault picker form
	if *vaultID == "" {
		selectedVaultId, err = RunVaultPickerForm(vaultsFormInfo)
		if err != nil {
			fmt.Printf("Failed to run form: %s\n", err)
			os.Exit(1)
		}
	} else {
		// Use the vault ID provided by CLI argument
		selectedVaultId = *vaultID
	}

	var selectedVault VaultPickerItem
	// Get the selected vault from the vaults form data
	for _, vault := range vaultsFormInfo {
		if vault.VaultID == selectedVaultId {
			selectedVault = vault
			break
		}
	}
	if selectedVault.VaultID == "" {
		fmt.Println(errorBox(fmt.Errorf("vault with ID %s not found", selectedVaultId)))
		os.Exit(1)
	}

	/**
	 * Run the recovery for the chosen vault
	 */
	fmt.Println(
		lipgloss.NewStyle().Bold(true).Render(fmt.Sprintf("RECOVERING VAULT \"%s\" WITH ID %s\n", selectedVault.Name, selectedVault.VaultID)),
	)

	address, ecSK, edSK, _, err := runTool(*vaultsDataFiles, &selectedVault.VaultID, nonceOverride, quorumOverride, exportKSFile, passwordForKS)
	if err != nil {
		fmt.Println(errorBox(err))
		os.Exit(1)
		return
	}
	defer func() {
		clear(ecSK)
		clear(edSK)
	}()
	if ecSK == nil {
		// only listing vaults
		os.Exit(0)
		return
	}

	fmt.Printf("%s%s                %s\n", ansiCodes["darkGreenBG"], ansiCodes["bold"], ansiCodes["reset"])
	fmt.Printf("%s%s    Success!    %s\n", ansiCodes["darkGreenBG"], ansiCodes["bold"], ansiCodes["reset"])
	fmt.Printf("%s%s                %s\n", ansiCodes["darkGreenBG"], ansiCodes["bold"], ansiCodes["reset"])

	fmt.Printf("\nYour vault has been recovered. Make sure this address matches your vault's Ethereum address:\n")
	fmt.Printf("%s%s%s\n", ansiCodes["bold"], address, ansiCodes["reset"])

	fmt.Printf("\nHere is your private key for Ethereum and Tron assets. Keep safe and do not share.\n")
	fmt.Printf("Recovered ECDSA private key (for ETH/MetaMask, Tron/TronLink): %s%s%s\n",
		ansiCodes["bold"], hex.EncodeToString(ecSK), ansiCodes["reset"])

	fmt.Printf("\nHere are your private keys for Bitcoin assets. Keep safe and do not share.\n")
	fmt.Printf("Recovered testnet WIF (for BTC/Electrum Wallet): %s%s%s\n", ansiCodes["bold"],
		wif.ToBitcoinWIF(ecSK, true, true), ansiCodes["reset"])
	fmt.Printf("Recovered mainnet WIF (for BTC/Electrum Wallet): %s%s%s\n", ansiCodes["bold"],
		wif.ToBitcoinWIF(ecSK, false, true), ansiCodes["reset"])

	fmt.Printf("\nHere is your private key for EDDSA based assets. Keep safe and do not share.\n")
	fmt.Printf("Recovered EdDSA/Ed25519 private key (for XRPL, SOL, TAO, etc): %s%s%s\n",
		ansiCodes["bold"], hex.EncodeToString(edSK), ansiCodes["reset"])

	fmt.Printf("\nNote: Some wallet apps may require you to prefix hex strings with 0x to load the key.\n")
}
