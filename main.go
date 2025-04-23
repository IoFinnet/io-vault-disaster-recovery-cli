// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/bittensor"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/config"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/solana"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/web"
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

	// Note: Transaction modes have been removed - use scripts in scripts/ directory instead

	// Web mode flags
	webMode := flag.Bool("web", false, "Launch in browser UI mode")
	webPort := flag.Int("port", 8080, "Port to use for browser UI (default: 8080)")
	noBrowser := flag.Bool("nobrowser", false, "Start http server without launching browser")

	flag.Parse()
	files := flag.Args()

	// Display banner
	fmt.Print(ui.Banner())

	// If no files provided, check if we should launch web mode
	if len(files) < 1 && !*webMode {
		// Ask the user if they want to use the browser UI
		fmt.Println("\nHow would you like to use the recovery tool?")
		fmt.Println("1. Launch browser UI (browser-based)")
		fmt.Println("2. Continue with command line interface")
		fmt.Print("\nEnter your choice (1 or 2): ")

		var choice string
		fmt.Scanln(&choice)

		if choice == "1" {
			*webMode = true
		} else if choice == "2" {
			fmt.Println("\nPlease supply some input files on the command line. \nExamples:")
			fmt.Println("- Individual JSON files: recovery-tool.exe [-flags] file1.json file2.json …")
			fmt.Println("- ZIP archive containing JSON files: recovery-tool.exe [-flags] backup.zip")
			fmt.Println("- Mixed formats: recovery-tool.exe [-flags] file1.json backup.zip file3.json")
			fmt.Println("\nNOTE: ZIP files must contain only a flat hierarchy of JSON files (no nested directories)")
			fmt.Println("\nOptional flags:")
			flag.PrintDefaults()
			return
		} else {
			fmt.Println("\nInvalid choice. Please run the tool again and select 1 or 2.")
			return
		}
	}

	// Launch browser UI if selected
	if *webMode {
		launchWebInterface(*webPort, *noBrowser)
		return
	}

	// Validate files for CLI mode
	if len(files) < 1 {
		fmt.Println("Please supply some input files on the command line. \nExamples:")
		fmt.Println("- Individual JSON files: recovery-tool.exe [-flags] file1.json file2.json …")
		fmt.Println("- ZIP archive containing JSON files: recovery-tool.exe [-flags] backup.zip")
		fmt.Println("- Mixed formats: recovery-tool.exe [-flags] file1.json backup.zip file3.json")
		fmt.Println("\nNOTE: ZIP files must contain only a flat hierarchy of JSON files (no nested directories)")
		fmt.Println("\nOptional flags:")
		flag.PrintDefaults()
		return
	}

	appConfig := config.AppConfig{
		Filenames:      files,
		NonceOverride:  *nonceOverride,
		QuorumOverride: *quorumOverride,
		ExportKSFile:   *exportKSFile,
		PasswordForKS:  *passwordForKS,
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
		
		// Clean up any temporary directories from ZIP extraction
		for _, dir := range appConfig.ZipExtractedDirs {
			os.RemoveAll(dir)
		}
		
		os.Exit(1)
	}
	if vaultsDataFiles == nil {
		fmt.Println("No vaults data files were selected.")
		
		// Clean up any temporary directories from ZIP extraction
		for _, dir := range appConfig.ZipExtractedDirs {
			os.RemoveAll(dir)
		}
		
		os.Exit(0)
	}

	/**
	 * Retrieve vaults information and select a vault
	 */

	_, _, _, vaultsFormInfo, err := runTool(*vaultsDataFiles, nil, nonceOverride, quorumOverride, exportKSFile, passwordForKS)
	if err != nil {
		fmt.Println(ui.ErrorBox(err))
		fmt.Println()
		fmt.Println("Are the words you entered correct? Are you using the newest files?")
		
		// Clean up any temporary directories from ZIP extraction
		for _, dir := range appConfig.ZipExtractedDirs {
			os.RemoveAll(dir)
		}
		
		os.Exit(1)
	}

	var selectedVaultId string
	// If the vault ID is not provided, run the vault picker form
	if *vaultID == "" {
		selectedVaultId, err = ui.RunVaultPickerForm(vaultsFormInfo)
		if err != nil {
			fmt.Println(ui.ErrorBox(err))
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
		fmt.Println()
		fmt.Println("Are the words you entered correct? Are you using the newest files?")
		
		// Clean up any temporary directories from ZIP extraction
		for _, dir := range appConfig.ZipExtractedDirs {
			os.RemoveAll(dir)
		}
		
		os.Exit(1)
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

		// Add wallet import instructions
		fmt.Println("\nWallet Import Instructions:")
		fmt.Println("- XRPL, TAO, SOL: Start this tool with the -web flag to enter the web-based UI recovery")
	} else {
		fmt.Println("\nNo EdDSA/Ed25519 private key found for this older vault.")
	}
	fmt.Printf("\nNote: Some wallet apps may require you to prefix hex strings with 0x to load the key.\n")
	
	// Clean up any temporary directories from ZIP extraction
	for _, dir := range appConfig.ZipExtractedDirs {
		os.RemoveAll(dir)
	}
}

// launchWebInterface starts the http server and optionally opens the browser
func launchWebInterface(port int, noBrowser bool) {
	fmt.Println("Starting browser UI mode...")

	// Create and start the http server
	server, err := web.NewServer(web.ServerConfig{Port: port})
	if err != nil {
		fmt.Printf("Failed to create http server: %v\n", err)
		return
	}

	// Set up a clean shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start the server
	url, err := server.Start()
	if err != nil {
		fmt.Printf("Failed to start http server: %v\n", err)
		return
	}

	fmt.Printf("Browser interface started at: %s\n", url)

	// Open the browser unless nobrowser flag is set
	if !noBrowser {
		fmt.Println("Opening browser...")
		if err := web.OpenBrowser(url); err != nil {
			fmt.Printf("Could not open browser automatically. Please open %s in your browser.\n", url)
		}
	} else {
		fmt.Printf("Browser not launched (--nobrowser flag set). Please open %s in your browser.\n", url)
	}

	fmt.Println("Browser interface is running. Press Ctrl+C to stop.")

	// Wait for interrupt signal
	<-sigChan

	fmt.Println("\nShutting down browser UI...")
	if err := server.Stop(); err != nil {
		fmt.Printf("Error shutting down server: %v\n", err)
	}
}
