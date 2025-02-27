// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/bittensor"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/config"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/solana"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/wif"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/xrpl"
	"github.com/charmbracelet/lipgloss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

const (
	v2MagicPrefix = "_V2_"
)

func main() {
	vaultID := flag.String("vault-id", "", "(Optional) The vault id to export the keys for.")
	nonceOverride := flag.Int("nonce", -1, "(Optional) Reshare Nonce override. Try it if the tool advises you to do so.")
	quorumOverride := flag.Int("threshold", 0, "(Optional) Vault Quorum (Threshold) override. Try it if the tool advises you to do so.")
	passwordForKS := flag.String("password", "", "(Optional) Encryption password for the Ethereum wallet v3 file; use with -export")
	exportKSFile := flag.String("export", "wallet.json", "(Optional) Filename to export a Ethereum wallet v3 JSON to; use with -password.")

	// Transaction mode flags
	xrplMode := flag.Bool("xrpl", false, "Enable XRPL guided mode")
	bitTensorMode := flag.Bool("bittensor", false, "Enable Bittensor guided mode")
	solanaMode := flag.Bool("solana", false, "Enable Solana guided mode")

	flag.Parse()
	files := flag.Args()
	if len(files) < 1 {
		fmt.Println("Please supply some input files on the command line. \nExample: recovery-tool.exe [-flags] file1.json file2.json … \n\nOptional flags:")
		flag.PrintDefaults()
		return
	}

	fmt.Print(ui.Banner())

	appConfig := config.AppConfig{
		Filenames:      files,
		NonceOverride:  *nonceOverride,
		QuorumOverride: *quorumOverride,
		ExportKSFile:   *exportKSFile,
		PasswordForKS:  *passwordForKS,
		XRPLMode:       *xrplMode,
		BitTensorMode:  *bitTensorMode,
		SolanaMode:     *solanaMode,
	}

	// First validate that files exist and are readable
	if err := ui.ValidateFiles(appConfig); err != nil {
		fmt.Print(ui.ErrorBox(err))
		os.Exit(1)
	}

	/**
	 * Run the steps to get the menmonics
	 */
	// var vaultsDataFiles []VaultsDataFile = make([]VaultsDataFile, 0, len(appConfig.Filenames))
	f := ui.NewMnemonicsForm(appConfig)
	vaultsDataFiles, err := f.Run()
	if err != nil {
		// if err := f.Run(&vaultsDataFiles); err != nil {
		fmt.Println(ui.ErrorBox(err))
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
		selectedVaultId, err = ui.RunVaultPickerForm(vaultsFormInfo)
		if err != nil {
			fmt.Printf("Failed to run form: %s\n", err)
			os.Exit(1)
		}
	} else {
		// Use the vault ID provided by CLI argument
		selectedVaultId = *vaultID
	}

	var selectedVault ui.VaultPickerItem
	// Get the selected vault from the vaults form data
	for _, vault := range vaultsFormInfo {
		if vault.VaultID == selectedVaultId {
			selectedVault = vault
			break
		}
	}
	if selectedVault.VaultID == "" {
		fmt.Println(ui.ErrorBox(fmt.Errorf("vault with ID %s not found", selectedVaultId)))
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
		fmt.Println(ui.ErrorBox(err))
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

	fmt.Printf("%s%s                %s\n", ui.AnsiCodes["darkGreenBG"], ui.AnsiCodes["bold"], ui.AnsiCodes["reset"])
	fmt.Printf("%s%s    Success!    %s\n", ui.AnsiCodes["darkGreenBG"], ui.AnsiCodes["bold"], ui.AnsiCodes["reset"])
	fmt.Printf("%s%s                %s\n", ui.AnsiCodes["darkGreenBG"], ui.AnsiCodes["bold"], ui.AnsiCodes["reset"])

	fmt.Printf("\nYour vault has been recovered. Make sure this address matches your vault's Ethereum address.\n")
	fmt.Printf("%s%s%s\n", ui.AnsiCodes["bold"], address, ui.AnsiCodes["reset"])

	fmt.Printf("\nHere is your private key for Ethereum and Tron assets. Keep safe and do not share.\n")
	fmt.Printf("Recovered ECDSA private key (for MetaMask, Phantom, TronLink): %s%s%s\n",
		ui.AnsiCodes["bold"], hex.EncodeToString(ecSK), ui.AnsiCodes["reset"])

	fmt.Printf("\nHere are your private keys for Bitcoin assets. Keep safe and do not share.\n")
	fmt.Printf("Recovered testnet WIF (for BTC/Electrum Wallet): %s%s%s\n", ui.AnsiCodes["bold"],
		wif.ToBitcoinWIF(ecSK, true, true), ui.AnsiCodes["reset"])
	fmt.Printf("Recovered mainnet WIF (for BTC/Electrum Wallet): %s%s%s\n", ui.AnsiCodes["bold"],
		wif.ToBitcoinWIF(ecSK, false, true), ui.AnsiCodes["reset"])

	if edSK != nil {
		fmt.Printf("\nHere is your private key for EdDSA based assets. Keep safe and do not share.\n")
		fmt.Printf("Recovered EdDSA private key: %s%s%s\n",
			ui.AnsiCodes["bold"], hex.EncodeToString(edSK), ui.AnsiCodes["reset"])

		// load the eddsa private key in edSK and output the public key
		_, edPK, err2 := edwards.PrivKeyFromScalar(edSK)
		if err2 != nil {
			panic("ed25519: internal error: setting scalar failed")
		}
		edPKC := edPK.SerializeCompressed()
		fmt.Printf("Recovered EdDSA public key: %s%s%s\n",
			ui.AnsiCodes["bold"], hex.EncodeToString(edPKC), ui.AnsiCodes["reset"])

		// Generate XRPL-specific formats
		xrplAddress, err := xrpl.DeriveXRPLAddress(edPKC)
		if err == nil {
			fmt.Printf("\nXRP Ledger (XRPL) Information:\n")
			fmt.Printf("XRP Address: %s%s%s\n",
				ui.AnsiCodes["bold"], xrplAddress, ui.AnsiCodes["reset"])
		}

		// Generate Bittensor-specific formats
		bittensorAddress, err := bittensor.GenerateSS58Address(edPKC)
		if err == nil {
			fmt.Printf("\nBittensor Information:\n")
			fmt.Printf("Bittensor Address (SS58): %s%s%s\n",
				ui.AnsiCodes["bold"], bittensorAddress, ui.AnsiCodes["reset"])
		}

		// Generate Solana-specific formats
		solanaAddress, err := solana.DeriveSolanaAddress(edPKC)
		if err == nil {
			fmt.Printf("\nSolana Information:\n")
			fmt.Printf("Solana Address: %s%s%s\n",
				ui.AnsiCodes["bold"], solanaAddress, ui.AnsiCodes["reset"])
		}

		// Add transaction mode handling
		if appConfig.XRPLMode {
			fmt.Println("\nXRPL Guided Mode")
			details, err := ui.PromptXRPLTransaction()
			if err != nil {
				fmt.Println(ui.ErrorBox(err))
			} else {
				err := xrpl.HandleTransaction(edSK, details.Destination, details.Amount, details.TestNet)
				if err != nil {
					fmt.Println(ui.ErrorBox(err))
				}
			}
		}

		if appConfig.BitTensorMode {
			fmt.Println("\nBittensor Guided Mode")
			details, err := ui.PromptBittensorTransaction()
			if err != nil {
				fmt.Println(ui.ErrorBox(err))
			} else {
				err := bittensor.HandleTransaction(edSK, details.Destination, details.Amount, details.Endpoint)
				if err != nil {
					fmt.Println(ui.ErrorBox(err))
				}
			}
		}

		if appConfig.SolanaMode {
			fmt.Println("\nSolana Guided Mode")
			details, err := ui.PromptSolanaTransaction()
			if err != nil {
				fmt.Println(ui.ErrorBox(err))
			} else {
				err := solana.HandleTransaction(edSK, details.Destination, details.Amount)
				if err != nil {
					fmt.Println(ui.ErrorBox(err))
				}
			}
		}

		// Add wallet import instructions
		fmt.Println("\nWallet Import Instructions:")
		fmt.Println("- XRPL: Use the XRPL tool in scripts/xrpl-tool/ with your private key")
		fmt.Println("- Bittensor: Use the Bittensor tool in scripts/bittensor-tool/ with your private key")
		fmt.Println("- Solana (Phantom): Import using the Base58 private key")
		fmt.Println("- Solana: Import private key in hex format to your wallet")

		// Add transaction instructions
		if !appConfig.XRPLMode && !appConfig.BitTensorMode && !appConfig.SolanaMode {
			fmt.Println("\nFor Extra Guidance:")
			fmt.Println("- For XRPL: Run with --xrpl flag")
			fmt.Println("- For Bittensor: Run with --bittensor flag")
			fmt.Println("- For Solana: Run with --solana flag")
		}
	} else {
		fmt.Println("\nNo EdDSA/Ed25519 private key found for this older vault.")
	}
	fmt.Printf("\nNote: Some wallet apps may require you to prefix hex strings with 0x to load the key.\n")
}
