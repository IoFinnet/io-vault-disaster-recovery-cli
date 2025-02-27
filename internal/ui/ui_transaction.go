// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

import (
	"github.com/charmbracelet/huh"
)

type TransactionDetails struct {
	Destination  string
	Amount       string
	Endpoint     string // Network endpoint
	TestNet      bool   // For chains that support testnet
	CustomEndpoint bool // Whether user selected a custom endpoint
}

// PromptXRPLTransaction prompts the user for XRPL transaction details
func PromptXRPLTransaction() (TransactionDetails, error) {
	var details TransactionDetails
	var network string

	// Default endpoints
	endpoints := map[string]string{
		"mainnet": "wss://s1.ripple.com",
		"testnet": "wss://testnet.xrpl-labs.com",
	}

	// First, select the network
	networkForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Network").
				Description("Select a network or choose custom endpoint").
				Options(
					huh.NewOption("Mainnet (wss://s1.ripple.com)", "mainnet"),
					huh.NewOption("Testnet (wss://testnet.xrpl-labs.com)", "testnet"),
					huh.NewOption("Custom Endpoint", "custom"),
				).
				Value(&network),
		),
	)

	err := networkForm.Run()
	if err != nil {
		return details, err
	}

	// If custom endpoint is selected, prompt for it
	if network == "custom" {
		customForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Custom Endpoint").
					Description("Enter the WebSocket endpoint URL").
					Placeholder("wss://your-custom-endpoint.com").
					Value(&details.Endpoint),
				huh.NewConfirm().
					Title("Is this a testnet?").
					Value(&details.TestNet),
			),
		)

		err = customForm.Run()
		if err != nil {
			return details, err
		}
		
		details.CustomEndpoint = true
	} else {
		// Use selected network's endpoint
		details.Endpoint = endpoints[network]
		details.TestNet = (network == "testnet")
	}

	// Finally, prompt for transaction details
	transactionForm := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Destination Address").
				Description("Enter the XRP destination address").
				Placeholder("rXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").
				Value(&details.Destination),
			huh.NewInput().
				Title("Amount").
				Description("Enter the amount of XRP to send").
				Placeholder("10.0").
				Value(&details.Amount),
		),
	)

	err = transactionForm.Run()
	if err != nil {
		return details, err
	}

	return details, nil
}

// PromptBittensorTransaction prompts the user for Bittensor transaction details
func PromptBittensorTransaction() (TransactionDetails, error) {
	var details TransactionDetails
	var network string

	// Default endpoints
	endpoints := map[string]string{
		"mainnet": "wss://entrypoint-finney.opentensor.ai:443",
		"testnet": "wss://test.finney.opentensor.ai:443",
	}

	// First, select the network
	networkForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Network").
				Description("Select a network or choose custom endpoint").
				Options(
					huh.NewOption("Mainnet (wss://entrypoint-finney.opentensor.ai:443)", "mainnet"),
					huh.NewOption("Testnet (wss://test.finney.opentensor.ai:443)", "testnet"),
					huh.NewOption("Custom Endpoint", "custom"),
				).
				Value(&network),
		),
	)

	err := networkForm.Run()
	if err != nil {
		return details, err
	}

	// If custom endpoint is selected, prompt for it
	if network == "custom" {
		customForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Custom Endpoint").
					Description("Enter the WebSocket endpoint URL").
					Placeholder("wss://your-custom-endpoint.com").
					Value(&details.Endpoint),
				huh.NewConfirm().
					Title("Is this a testnet?").
					Value(&details.TestNet),
			),
		)

		err = customForm.Run()
		if err != nil {
			return details, err
		}
		
		details.CustomEndpoint = true
	} else {
		// Use selected network's endpoint
		details.Endpoint = endpoints[network]
		details.TestNet = (network == "testnet")
	}

	// Finally, prompt for transaction details
	transactionForm := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Destination Address").
				Description("Enter the Bittensor destination address").
				Placeholder("5XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").
				Value(&details.Destination),
			huh.NewInput().
				Title("Amount").
				Description("Enter the amount of TAO to send").
				Placeholder("1.0").
				Value(&details.Amount),
		),
	)

	err = transactionForm.Run()
	if err != nil {
		return details, err
	}

	return details, nil
}

// PromptSolanaTransaction prompts the user for Solana transaction details
func PromptSolanaTransaction() (TransactionDetails, error) {
	var details TransactionDetails
	var network string

	// Default endpoints
	endpoints := map[string]string{
		"mainnet": "https://api.mainnet-beta.solana.com",
		"testnet": "https://api.testnet.solana.com",
		"devnet":  "https://api.devnet.solana.com",
	}

	// First, select the network
	networkForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Network").
				Description("Select a network or choose custom endpoint").
				Options(
					huh.NewOption("Mainnet (https://api.mainnet-beta.solana.com)", "mainnet"),
					huh.NewOption("Testnet (https://api.testnet.solana.com)", "testnet"),
					huh.NewOption("Devnet (https://api.devnet.solana.com)", "devnet"),
					huh.NewOption("Custom Endpoint", "custom"),
				).
				Value(&network),
		),
	)

	err := networkForm.Run()
	if err != nil {
		return details, err
	}

	// If custom endpoint is selected, prompt for it
	if network == "custom" {
		customForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Custom Endpoint").
					Description("Enter the Solana RPC endpoint URL").
					Placeholder("https://your-custom-endpoint.com").
					Value(&details.Endpoint),
				huh.NewConfirm().
					Title("Is this a testnet?").
					Value(&details.TestNet),
			),
		)

		err = customForm.Run()
		if err != nil {
			return details, err
		}
		
		details.CustomEndpoint = true
	} else {
		// Use selected network's endpoint
		details.Endpoint = endpoints[network]
		details.TestNet = (network == "testnet" || network == "devnet")
	}

	// Finally, prompt for transaction details
	transactionForm := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Destination Address").
				Description("Enter the Solana destination address").
				Placeholder("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").
				Value(&details.Destination),
			huh.NewInput().
				Title("Amount").
				Description("Enter the amount of SOL to send").
				Placeholder("1.0").
				Value(&details.Amount),
		),
	)

	err = transactionForm.Run()
	if err != nil {
		return details, err
	}

	return details, nil
}

// BlockchainChoice represents the user's choice of blockchain
type BlockchainChoice string

const (
	XRPL      BlockchainChoice = "XRPL"
	Bittensor BlockchainChoice = "Bittensor"
	Solana    BlockchainChoice = "Solana"
	Exit      BlockchainChoice = "Exit"
)

// PromptBlockchainSelection prompts the user to select a blockchain for transaction
func PromptBlockchainSelection() (BlockchainChoice, error) {
	var choice string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Blockchain Selection").
				Description("Would you like to proceed with a transaction on one of these blockchains?").
				Options(
					huh.NewOption("XRPL Transaction", string(XRPL)),
					huh.NewOption("Bittensor Transaction", string(Bittensor)),
					huh.NewOption("Solana Transaction", string(Solana)),
					huh.NewOption("Exit without transaction", string(Exit)),
				).
				Value(&choice),
		),
	)

	err := form.Run()
	if err != nil {
		return "", err
	}

	return BlockchainChoice(choice), nil
}
