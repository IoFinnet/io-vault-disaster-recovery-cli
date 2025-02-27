// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package bittensor

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/centrifuge/go-substrate-rpc-client/v4/rpc"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"golang.org/x/crypto/blake2b"
)

// Constants for Bittensor
const (
	SS58Prefix = 42 // Bittensor network prefix
)

// HandleTransaction processes a Bittensor transaction
func HandleTransaction(privateKey []byte, destination, amount, endpoint string) error {
	// Validate inputs
	if err := validateInputs(destination, amount, endpoint); err != nil {
		return err
	}

	// Derive public key from private key
	_, pubKey, err := edwards.PrivKeyFromScalar(privateKey)
	if err != nil {
		return fmt.Errorf("failed to derive public key: %v", err)
	}

	// Display key information
	fmt.Println("\nBittensor Transaction Information:")

	// Get SS58 address from public key
	pubKeyBytes := pubKey.SerializeCompressed()
	ss58Address, err := GenerateSS58Address(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to generate SS58 address: %v", err)
	}
	fmt.Printf("Your Bittensor Address: %s\n", ss58Address)

	// Transaction details
	fmt.Printf("Network Endpoint: %s\n", endpoint)
	fmt.Printf("Destination: %s\n", destination)
	fmt.Printf("Amount: %s TAO\n", amount)

	// Process online vs offline modes
	fmt.Println("\nBittensor transactions require online access to fetch account information and network fees.")
	fmt.Println("Would you like to proceed with the transaction now (online mode)?")
	fmt.Println("If you choose 'No', we'll provide instructions for later use.")

	// Ask user if they want to proceed with online transaction
	var proceed string
	fmt.Print("Proceed with online transaction? (y/n): ")
	fmt.Scanln(&proceed)

	if proceed == "y" || proceed == "Y" {
		return buildAndSubmitBittensorTransaction(privateKey, pubKeyBytes, destination, amount, endpoint)
	}

	// Offline mode instructions
	fmt.Println("\nTo complete this transaction later:")
	fmt.Println("1. Run this tool again with the --bittensor flag when you're ready to connect to the network")
	fmt.Println("2. Use the same private key, destination address, and amount")
	fmt.Println("3. Choose 'Yes' at the online transaction prompt")

	return nil
}

// buildAndSubmitBittensorTransaction builds and submits a Bittensor transaction
func buildAndSubmitBittensorTransaction(privateKey, publicKey []byte, destination, amount, endpoint string) error {
	fmt.Println("\nPreparing transaction...")

	// Connect to Bittensor network
	fmt.Printf("Connecting to Bittensor network at %s...\n", endpoint)
	
	// Create a connection to the Substrate node
	api, err := rpc.NewRPC(context.Background(), endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to Bittensor network: %v", err)
	}
	
	// Generate the SS58 address
	ss58Address, err := GenerateSS58Address(publicKey)
	if err != nil {
		return fmt.Errorf("failed to generate source address: %v", err)
	}
	fmt.Printf("Source address: %s\n", ss58Address)
	
	// Create a key pair for signing
	keyring := signature.KeyringPair{
		URI:       "",
		Address:   ss58Address,
		PublicKey: publicKey,
	}
	
	// Get account info to retrieve nonce
	fmt.Println("Fetching account information...")
	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		return fmt.Errorf("failed to get metadata: %v", err)
	}
	
	// Convert address to AccountID format
	accountID, err := types.NewAccountID(ss58Address)
	if err != nil {
		return fmt.Errorf("failed to create account ID: %v", err)
	}
	
	// Get account info
	var accountInfo types.AccountInfo
	key, err := types.CreateStorageKey(meta, "System", "Account", accountID)
	if err != nil {
		return fmt.Errorf("failed to create storage key: %v", err)
	}
	
	ok, err := api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil || !ok {
		return fmt.Errorf("failed to get account info: %v", err)
	}
	
	// Parse amount (1 TAO = 1_000_000_000 planck)
	amountF, err := parseFloat(amount)
	if err != nil {
		return fmt.Errorf("invalid amount: %v", err)
	}
	
	// Convert TAO to planck (1 TAO = 10^9 planck)
	amountPlanck := types.NewU128(*big.NewInt(int64(amountF * 1_000_000_000)))
	
	// Get latest block hash for the era
	blockHash, err := api.RPC.Chain.GetBlockHashLatest()
	if err != nil {
		return fmt.Errorf("failed to get block hash: %v", err)
	}
	
	// Create a transfer call
	call, err := types.NewCall(meta, "Balances.transfer_keep_alive", types.NewMultiAddressFromAccountID(accountID), amountPlanck)
	if err != nil {
		return fmt.Errorf("failed to create transfer call: %v", err)
	}
	
	// Get the current block for reference
	header, err := api.RPC.Chain.GetHeader(blockHash)
	if err != nil {
		return fmt.Errorf("failed to get header: %v", err)
	}
	
	// Create the extrinsic
	ext := types.NewExtrinsic(call)
	
	// Get runtime version for signing
	rv, err := api.RPC.State.GetRuntimeVersionLatest()
	if err != nil {
		return fmt.Errorf("failed to get runtime version: %v", err)
	}
	
	// Create signing options
	o := types.SignatureOptions{
		BlockHash:          blockHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        blockHash,
		Nonce:              types.NewUCompactFromUInt(uint64(accountInfo.Nonce)),
		SpecVersion:        rv.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: rv.TransactionVersion,
	}
	
	// Display transaction details
	fmt.Println("\nTransaction Details:")
	fmt.Printf("From: %s\n", ss58Address)
	fmt.Printf("To: %s\n", destination)
	fmt.Printf("Amount: %s TAO\n", amount)
	fmt.Printf("Nonce: %d\n", uint64(accountInfo.Nonce))
	
	// Ask for confirmation
	var confirm string
	fmt.Print("\nConfirm transaction? (y/n): ")
	fmt.Scanln(&confirm)
	
	if confirm != "y" && confirm != "Y" {
		fmt.Println("Transaction cancelled.")
		return nil
	}
	
	// Sign the transaction
	fmt.Println("Signing transaction...")
	
	// Create custom signer function for our private key
	err = ext.Sign(keyring, o)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %v", err)
	}
	
	// Submit the transaction
	fmt.Println("Submitting transaction...")
	
	// Send the extrinsic
	sub, err := api.RPC.Author.SubmitAndWatchExtrinsic(ext)
	if err != nil {
		return fmt.Errorf("failed to submit transaction: %v", err)
	}
	defer sub.Unsubscribe()
	
	// Wait for transaction to be included in a block
	timeout := time.After(time.Minute)
	var transactionHash string
	
	for {
		select {
		case status := <-sub.Chan():
			if status.IsInBlock {
				transactionHash = status.AsInBlock.Hex()
				fmt.Printf("Transaction included in block: %s\n", transactionHash)
				goto INCLUDED
			} else if status.IsFinalized {
				transactionHash = status.AsFinalized.Hex()
				fmt.Printf("Transaction finalized in block: %s\n", transactionHash)
				goto INCLUDED
			} else if status.IsDropped || status.IsInvalid || status.IsUsurped {
				return fmt.Errorf("transaction failed: %v", status.Error)
			}
		case <-timeout:
			return fmt.Errorf("transaction timed out after 1 minute")
		}
	}
	
INCLUDED:
	fmt.Println("\nTransaction successful!")
	fmt.Printf("Transaction hash: %s\n", transactionHash)
	fmt.Println("View on Bittensor Explorer: https://taostats.io/transactions/" + transactionHash)
	
	return nil
}

// parseFloat parses a string to a float64
func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

// validateInputs checks if the destination, amount, and endpoint are valid
func validateInputs(destination, amount, endpoint string) error {
	if !isValidSS58Address(destination) {
		return errors.New("invalid Bittensor destination address format")
	}

	if !isValidAmount(amount) {
		return errors.New("invalid amount (must be a positive number)")
	}

	if !strings.HasPrefix(endpoint, "wss://") {
		return errors.New("invalid endpoint (must start with wss://)")
	}

	return nil
}

// isValidSS58Address checks if the address is a valid SS58 address
func isValidSS58Address(address string) bool {
	// Simple validation - in production use a proper SS58 validation
	return len(address) >= 45 && len(address) <= 50
}

// isValidAmount checks if the amount is valid
func isValidAmount(amount string) bool {
	// Simple validation - could be more sophisticated
	return len(amount) > 0 && amount[0] != '-'
}

// GenerateSS58Address generates an SS58 address from a public key
func GenerateSS58Address(pubKey []byte) (string, error) {
	// SS58 address format:
	// 1. Add network prefix (0x2A for Bittensor)
	// 2. Append public key
	// 3. Calculate checksum using Blake2b
	// 4. Append checksum
	// 5. Base58 encode

	// Add network prefix (42 = 0x2A for Bittensor)
	prefixedKey := append([]byte{byte(SS58Prefix)}, pubKey...)

	// Calculate checksum using Blake2b
	hasher, err := blake2b.New(64, nil) // 512 bits
	if err != nil {
		return "", fmt.Errorf("failed to create hasher: %v", err)
	}

	// SS58 uses a special prefix for the checksum
	hasher.Write([]byte("SS58PRE"))
	hasher.Write(prefixedKey)
	checksumHash := hasher.Sum(nil)
	checksum := checksumHash[:2] // First 2 bytes for the checksum

	// Append checksum
	addressBytes := append(prefixedKey, checksum...)

	// Base58 encode
	address := base58.Encode(addressBytes)

	return address, nil
}
