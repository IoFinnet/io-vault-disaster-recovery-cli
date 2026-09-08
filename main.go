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
	"path/filepath"
	"strings"
	"syscall"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/bittensor"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/config"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/recoverypipeline"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/solana"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/web"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/wif"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/xrpl"
	"github.com/charmbracelet/lipgloss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

func main() {
	os.Exit(run())
}

// keyPathsFlag collects private key PEM paths from repeated flags and from comma-separated values.
type keyPathsFlag []string

// String is nil-receiver safe: the flag package calls it on a zero value when printing defaults.
func (f *keyPathsFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, ",")
}

// Set accepts a single path or a comma-separated list. Repeated paths are dropped so the same key
// isn't tried twice, and reported as one in the "tried N keys" count.
func (f *keyPathsFlag) Set(value string) error {
	seen := make(map[string]bool, len(*f))
	for _, existing := range *f {
		seen[filepath.Clean(existing)] = true
	}
	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return fmt.Errorf("key path cannot be empty")
		}
		cleaned := filepath.Clean(token)
		if seen[cleaned] {
			continue
		}
		seen[cleaned] = true
		*f = append(*f, token)
	}
	return nil
}

// readPrivateKeys stops at the first unreadable path, naming it in the error. The keys read up to
// that point are still returned, so the caller's clearKeys defer covers them.
func readPrivateKeys(paths []string) ([][]byte, error) {
	keys := make([][]byte, 0, len(paths))
	for _, path := range paths {
		key, err := os.ReadFile(path)
		if err != nil {
			return keys, fmt.Errorf("⚠ unable to read private key file `%s`: %s", path, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// clearKeys zeroes every private key so its bytes don't linger in memory after the run.
func clearKeys(keys [][]byte) {
	for _, k := range keys {
		clear(k)
	}
}

// run returns an exit code instead of calling os.Exit, so deferred cleanup runs on every path.
func run() int {
	vaultID := flag.String("vault-id", "", "(Optional) The vault id to export the keys for.")
	nonceOverride := flag.Int("nonce", -1, "(Optional) Reshare Nonce override for legacy mnemonic-encrypted JSON files. Try it if the tool advises you to do so.")
	requestIDOverride := flag.String("request-id", "", "(Optional) Request id override for Virtual Signer .dr files / v4 JSON exports. Try it if the tool advises you to do so.")
	quorumOverride := flag.Int("threshold", 0, "(Optional) Vault Quorum (Threshold) override. Try it if the tool advises you to do so.")
	passwordForKS := flag.String("password", "", "(Optional) Encryption password for the Ethereum wallet v3 file; use with -export")
	exportKSFile := flag.String("export", "wallet.json", "(Optional) Filename to export a Ethereum wallet v3 JSON to; use with -password.")
	var keyPaths keyPathsFlag
	flag.Var(&keyPaths, "keys", "(Required when recovering from Virtual Signer .dr files) Path(s) to ML-KEM-768 private key PEM files. Repeatable, or comma-separated.")
	flag.Var(&keyPaths, "private-key", "(Alias for -keys) Path to an ML-KEM-768 private key PEM.")

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
			printInputHelp()
			return 0
		} else {
			fmt.Println("\nInvalid choice. Please run the tool again and select 1 or 2.")
			return 0
		}
	}

	// Launch browser UI if selected
	if *webMode {
		launchWebInterface(*webPort, *noBrowser)
		return 0
	}

	// Validate files for CLI mode
	if len(files) < 1 {
		printInputHelp()
		return 0
	}

	appConfig := config.AppConfig{
		Filenames:        files,
		NonceOverride:    *nonceOverride,
		QuorumOverride:   *quorumOverride,
		ExportKSFile:     *exportKSFile,
		PasswordForKS:    *passwordForKS,
		PrivateKeyFiles:  keyPaths,
		ZipExtractedDirs: []string{}, // Initialize empty slice for tracking ZIP dirs
	}

	// Initialize the global config so ui_input can track ZIP dirs
	config.GlobalConfig = appConfig

	defer func() {
		dirsToCleanup := appConfig.ZipExtractedDirs
		for _, dir := range dirsToCleanup {
			if err := os.RemoveAll(dir); err != nil {
				fmt.Println(ui.PlainTextf("⚠ failed to clean up temporary directory %s: %v", dir, err))
				continue
			}
			fmt.Println(ui.PlainTextf("Cleaning up temporary directory: %s", dir))
		}
	}()

	// First validate that files exist and are readable
	if err := ui.ValidateFiles(&appConfig); err != nil {
		fmt.Print(ui.ErrorBox(err))
		return 1
	}

	// Validate the exportKSFile is valid and does not already exist, only when the password is provided.
	// Because -export defaults to wallet.json, avoiding running this block on normal recoveries to avoid errors when wallet.json already exists,
	// even if no -password was supplied (so no export would happen).
	if exportKSFile != nil && len(*exportKSFile) > 0 && passwordForKS != nil && len(*passwordForKS) > 0 {
		err := ui.ValidateExportFilenameForCli(*exportKSFile)
		if err != nil {
			fmt.Print(ui.ErrorBox(err))
			return 1
		}
	}

	/**
	 * Run the steps to get the menmonics
	 */
	// var vaultsDataFiles []VaultsDataFile = make([]VaultsDataFile, 0, len(appConfig.Filenames))
	f := ui.NewMnemonicsForm(appConfig)
	vaultsDataFiles, err := f.Run()
	if err != nil {
		fmt.Println(ui.ErrorBox(err))
		return 1
	}
	if vaultsDataFiles == nil {
		fmt.Println("No vaults data files were selected.")
		return 0
	}

	defer vaultsDataFiles.Zeroize()

	// Read every ML-KEM-768 private key PEM (for .dr files). The paths come from -keys,
	// -private-key, or the interactive prompt above; PrivateKeyFiles reflects all of those.
	privateKeysPEM, err := readPrivateKeys(config.GlobalConfig.PrivateKeyFiles)
	defer clearKeys(privateKeysPEM)
	if err != nil {
		fmt.Print(ui.ErrorBox(err))
		return 1
	}

	/**
	 * Retrieve vaults information and select a vault
	 */

	inputs, err := recoverypipeline.Discover(*vaultsDataFiles, recoverypipeline.ErrorPresentation{})
	if err != nil {
		inputs.Close()
		fmt.Println(ui.ErrorBox(err))
		return 1
	}
	defer inputs.Close()

	_, _, _, vaultsFormInfo, _, err := runTool(inputs, "", *nonceOverride, *nonceOverride > -1, *requestIDOverride, *quorumOverride, *exportKSFile, *passwordForKS, privateKeysPEM)
	if err != nil {
		fmt.Println(ui.ErrorBox(err))
		fmt.Println()
		fmt.Println("Are the words you entered correct? Are you using the newest files?")
		return 1
	}

	var selectedVaultId string
	// If the vault ID is not provided, run the vault picker form
	if *vaultID == "" {
		selectedVaultId, err = ui.RunVaultPickerForm(vaultsFormInfo)
		if err != nil {
			fmt.Println(ui.ErrorBox(err))
			return 1
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
		return 1
	}

	/**
	 * Run the recovery for the chosen vault
	 */
	fmt.Println(
		lipgloss.NewStyle().Bold(true).Render(ui.PlainTextf("RECOVERING VAULT \"%s\" WITH ID %s\n", selectedVault.Name, selectedVault.VaultID)),
	)

	address, ecSK, edSK, _, exportedKsFile, err := runTool(inputs, selectedVault.VaultID, *nonceOverride, *nonceOverride > -1, *requestIDOverride, *quorumOverride, *exportKSFile, *passwordForKS, privateKeysPEM)
	if err != nil {
		fmt.Println(ui.ErrorBox(err))
		fmt.Println()
		fmt.Println("Are the words you entered correct? Are you using the newest files?")
		return 1
	}
	defer func() {
		clear(ecSK)
		clear(edSK)
	}()
	if ecSK == nil {
		// only listing vaults
		return 0
	}

	fmt.Println(ui.SuccessBox())

	fmt.Printf("\nYour vault has been recovered. Make sure this address matches your vault's Ethereum address.\n")
	fmt.Println(ui.Bold(address))

	fmt.Printf("\nHere is your private key for Ethereum and Tron assets. Keep safe and do not share.\n")
	fmt.Println("Recovered ECDSA private key (for MetaMask, Phantom, TronLink): " + ui.Bold(hex.EncodeToString(ecSK)))

	fmt.Printf("\nHere are your private keys for Bitcoin assets. Keep safe and do not share.\n")
	fmt.Println("Recovered testnet WIF (for BTC/Electrum Wallet): " + ui.Bold(wif.ToBitcoinWIF(ecSK, true, true)))
	fmt.Println("Recovered mainnet WIF (for BTC/Electrum Wallet): " + ui.Bold(wif.ToBitcoinWIF(ecSK, false, true)))

	if edSK != nil {
		fmt.Printf("\nHere is your private key for EdDSA based assets. Keep safe and do not share.\n")
		fmt.Println("Recovered EdDSA private key: " + ui.Bold(hex.EncodeToString(edSK)))

		// load the eddsa private key in edSK and output the public key
		_, edPK, err2 := edwards.PrivKeyFromScalar(edSK)
		if err2 != nil {
			panic("ed25519: internal error: setting scalar failed")
		}
		edPKC := edPK.SerializeCompressed()
		fmt.Println("Recovered EdDSA public key: " + ui.Bold(hex.EncodeToString(edPKC)))

		// Generate XRPL-specific formats
		xrplAddress, err := xrpl.DeriveXRPLAddress(edPKC)
		if err == nil {
			fmt.Printf("\nXRP Ledger (XRPL) Information:\n")
			fmt.Println("XRP Address: " + ui.Bold(xrplAddress))
		}

		// Generate Bittensor-specific formats
		bittensorAddress, err := bittensor.GenerateSS58Address(edPKC)
		if err == nil {
			fmt.Printf("\nBittensor Information:\n")
			fmt.Println("Bittensor Address (SS58): " + ui.Bold(bittensorAddress))
		}

		// Generate Solana-specific formats
		solanaAddress, err := solana.DeriveSolanaAddress(edPKC)
		if err == nil {
			fmt.Printf("\nSolana Information:\n")
			fmt.Println("Solana Address: " + ui.Bold(solanaAddress))
		}

		if exportedKsFile != nil {
			fmt.Println("\nWallet v3 file exported to:", ui.Bold(ui.PlainText(*exportedKsFile)))
		}

		// Add wallet import instructions
		fmt.Println("\nWallet Import Instructions:")
		fmt.Println("- XRPL, TAO, SOL: Start this tool with the -web flag to enter the browser UI recovery")
	} else {
		fmt.Println("\nNo EdDSA/Ed25519 private key found for this older vault.")
	}
	fmt.Printf("\nNote: Some wallet apps may require you to prefix hex strings with 0x to load the key.\n")

	return 0
}

// printInputHelp is shown on both no-input paths: the interactive prompt's "command
// line" choice and a bare invocation. One helper so the two cannot drift.
func printInputHelp() {
	fmt.Print(inputHelpText)
	flag.PrintDefaults()
}

const inputHelpText = `Usage: recovery-tool [flags] <file>...

Accepted inputs:
  vault.json           mobile app backup (v5; v4 also needs -threshold)
  share.dr             Virtual Signer share, needs -keys
  signer-backup.zip    Virtual Signer bundle, needs -keys
  backup.zip           legacy ZIP of JSON exports

Bundles, .dr files and mobile backups can be combined:
  recovery-tool -keys key.pem signer-backup.zip extra.dr vault.json

Legacy ZIPs and legacy flat-nonce JSON each need a run of their own.
A bundle zip must have manifest.json at its root; see the README.

Flags:
`

// launchWebInterface starts the http server and optionally opens the browser
func launchWebInterface(port int, noBrowser bool) {
	fmt.Println("Starting browser UI mode...")

	// Create and start the http server
	server, err := web.NewServer(web.ServerConfig{Port: port})
	if err != nil {
		fmt.Println(ui.PlainTextf("Failed to create http server: %v", err))
		return
	}

	// Set up a clean shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start the server
	url, err := server.Start()
	if err != nil {
		fmt.Println(ui.PlainTextf("Failed to start http server: %v", err))
		return
	}

	fmt.Println(ui.PlainTextf("Browser interface started at: %s", url))

	// Open the browser unless nobrowser flag is set
	if !noBrowser {
		fmt.Println("Opening browser...")
		if err := web.OpenBrowser(url); err != nil {
			fmt.Println(ui.PlainTextf("Could not open browser automatically. Please open %s in your browser.", url))
		}
	} else {
		fmt.Println(ui.PlainTextf("Browser not launched (--nobrowser flag set). Please open %s in your browser.", url))
	}

	fmt.Println("Browser interface is running. Press Ctrl+C to stop.")

	// Wait for interrupt signal
	<-sigChan

	fmt.Println("\nShutting down browser UI...")
	if err := server.Stop(); err != nil {
		fmt.Println(ui.PlainTextf("Error shutting down server: %v", err))
	}
}
