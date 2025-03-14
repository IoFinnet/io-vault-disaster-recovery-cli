// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

import (
	"github.com/charmbracelet/huh"
)

type TransactionDetails struct {
	Destination string
	Amount      string
	Endpoint    string // For Bittensor
	TestNet     bool   // For chains that support testnet
}

// PromptXRPLTransaction prompts the user for XRPL transaction details
func PromptXRPLTransaction() (TransactionDetails, error) {
	var details TransactionDetails
	var testnet string

	form := huh.NewForm(
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
			huh.NewSelect[string]().
				Title("Network").
				Options(
					huh.NewOption("Mainnet", "mainnet"),
					huh.NewOption("Testnet", "testnet"),
				).
				Value(&testnet),
		),
	)

	err := form.Run()
	if err != nil {
		return details, err
	}

	details.TestNet = (testnet == "testnet")
	return details, nil
}

// PromptBittensorTransaction prompts the user for Bittensor transaction details
func PromptBittensorTransaction() (TransactionDetails, error) {
	var details TransactionDetails
	
	// Set default endpoint
	details.Endpoint = "wss://entrypoint-finney.opentensor.ai:443"

	form := huh.NewForm(
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
			huh.NewInput().
				Title("Endpoint").
				Description("Enter the Bittensor network endpoint").
				Placeholder(details.Endpoint).
				Value(&details.Endpoint),
		),
	)

	return details, form.Run()
}

// PromptSolanaTransaction prompts the user for Solana transaction details
func PromptSolanaTransaction() (TransactionDetails, error) {
	var details TransactionDetails

	form := huh.NewForm(
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

	return details, form.Run()
}
