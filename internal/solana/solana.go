// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package solana

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
)

// Constants for Solana
const (
	SolanaAddressLength = 44 // Base58 encoded public key length
)

// HandleTransaction processes a Solana transaction
func HandleTransaction(privateKey []byte, destination, amount string) error {
	// Validate inputs
	if err := validateInputs(destination, amount); err != nil {
		return err
	}

	// Derive public key from private key
	_, pubKey, err := edwards.PrivKeyFromScalar(privateKey)
	if err != nil {
		return fmt.Errorf("failed to derive public key: %v", err)
	}

	// Display key information
	fmt.Println("\nSolana Transaction Information:")

	// Get Solana address from public key
	pubKeyBytes := pubKey.SerializeCompressed()
	solanaAddress, err := DeriveSolanaAddress(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to derive Solana address: %v", err)
	}
	fmt.Printf("Your Solana Address: %s\n", solanaAddress)

	// Transaction details
	fmt.Printf("Destination: %s\n", destination)
	fmt.Printf("Amount: %s SOL\n", amount)

	// Process online vs offline modes
	fmt.Println("\nSolana transactions require online access to fetch account information and network fees.")
	fmt.Println("Would you like to proceed with the transaction now (online mode)?")
	fmt.Println("If you choose 'No', we'll provide instructions for later use.")

	// Ask user if they want to proceed with online transaction
	var proceed string
	fmt.Print("Proceed with online transaction? (y/n): ")
	fmt.Scanln(&proceed)

	if proceed == "y" || proceed == "Y" {
		// Ask for network selection
		fmt.Println("\nSelect Solana network:")
		fmt.Println("1. Mainnet")
		fmt.Println("2. Testnet")
		fmt.Println("3. Devnet")
		
		var networkChoice string
		fmt.Print("Enter choice (1-3): ")
		fmt.Scanln(&networkChoice)
		
		var network string
		switch networkChoice {
		case "1":
			network = "mainnet"
		case "2":
			network = "testnet"
		case "3":
			network = "devnet"
		default:
			network = "mainnet"
		}
		
		return buildAndSubmitSolanaTransaction(privateKey, pubKeyBytes, destination, amount, network)
	}

	// Offline mode instructions
	fmt.Println("\nTo complete this transaction later:")
	fmt.Println("1. Run this tool again with the --solana flag when you're ready to connect to the network")
	fmt.Println("2. Use the same private key, destination address, and amount")
	fmt.Println("3. Choose 'Yes' at the online transaction prompt")

	return nil
}

// buildAndSubmitSolanaTransaction builds and submits a Solana transaction
func buildAndSubmitSolanaTransaction(privateKey, publicKey []byte, destination, amount, network string) error {
	fmt.Println("\nPreparing transaction...")

	// Get the appropriate endpoint for the selected network
	var endpoint string
	switch network {
	case "mainnet":
		endpoint = rpc.MainNetBeta_RPC
	case "testnet":
		endpoint = rpc.TestNet_RPC
	case "devnet":
		endpoint = rpc.DevNet_RPC
	default:
		return fmt.Errorf("invalid network: %s", network)
	}
	
	fmt.Printf("Connecting to Solana %s...\n", network)
	
	// Create a client
	client := rpc.New(endpoint)
	
	// Convert private key to Solana keypair
	fullPrivateKey := mergePrivateKeyWithPublic(privateKey, publicKey)
	
	// Create a keypair from the private key
	keypair, err := solana.PrivateKeyFromBytes(fullPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create keypair: %v", err)
	}
	
	// Get the public key
	fromAddress := keypair.PublicKey()
	fmt.Printf("Source account: %s\n", fromAddress.String())
	
	// Parse destination address
	toAddress, err := solana.PublicKeyFromBase58(destination)
	if err != nil {
		return fmt.Errorf("invalid destination address: %v", err)
	}
	
	// Parse amount
	amountFloat, err := strconv.ParseFloat(amount, 64)
	if err != nil {
		return fmt.Errorf("invalid amount: %v", err)
	}
	// Convert to lamports (1 SOL = 1,000,000,000 lamports)
	lamports := uint64(amountFloat * 1000000000)
	
	// Get recent blockhash for transaction
	fmt.Println("Fetching recent blockhash...")
	recentBlockhash, err := client.GetRecentBlockhash(context.Background(), rpc.CommitmentFinalized)
	if err != nil {
		return fmt.Errorf("failed to get recent blockhash: %v", err)
	}
	
	// Build the transaction
	fmt.Println("Building transaction...")
	transfer := system.NewTransferInstruction(
		lamports,
		fromAddress,    // from
		toAddress,      // to
	).Build()
	
	// Create a new transaction
	tx, err := solana.NewTransaction([]solana.Instruction{transfer}, recentBlockhash.Value.Blockhash, solana.TransactionPayer(fromAddress))
	if err != nil {
		return fmt.Errorf("failed to create transaction: %v", err)
	}
	
	// Display transaction details
	fmt.Println("\nTransaction Details:")
	fmt.Printf("From: %s\n", fromAddress.String())
	fmt.Printf("To: %s\n", destination)
	fmt.Printf("Amount: %s SOL\n", amount)
	fmt.Printf("Network: %s\n", network)
	fmt.Printf("Fee: %d lamports\n", tx.Meta.Fee)
	
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
	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(fromAddress) {
			return &keypair
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %v", err)
	}
	
	// Submit the transaction
	fmt.Println("Submitting transaction...")
	sig, err := client.SendTransaction(context.Background(), tx)
	if err != nil {
		return fmt.Errorf("failed to send transaction: %v", err)
	}
	
	// Waiting for confirmation
	fmt.Println("Waiting for confirmation...")
	
	// Set a timeout for confirmation
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	
	// Poll for confirmation
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// Check if the transaction is confirmed
			resp, err := client.GetSignatureStatus(ctx, sig)
			if err != nil {
				return fmt.Errorf("failed to get signature status: %v", err)
			}
			
			if resp != nil && resp.Value != nil {
				if resp.Value.Confirmations == nil && resp.Value.Confirmation == "confirmed" {
					fmt.Printf("Transaction confirmed in slot %d\n", resp.Value.Slot)
					goto CONFIRMED
				}
			}
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for confirmation, but the transaction may still succeed")
		}
	}
	
CONFIRMED:
	fmt.Println("\nTransaction successful!")
	fmt.Printf("Transaction signature: %s\n", sig.String())
	fmt.Printf("View on Solana Explorer: https://explorer.solana.com/tx/%s?cluster=%s\n", 
		sig.String(), network)
	
	return nil
}

// mergePrivateKeyWithPublic merges the private key with the public key to create a full Ed25519 keypair
func mergePrivateKeyWithPublic(privateKey, publicKey []byte) []byte {
	// Ed25519 keypair is 64 bytes: 32 bytes private key + 32 bytes public key
	return append(privateKey, publicKey...)
}

// validateInputs checks if the destination and amount are valid
func validateInputs(destination, amount string) error {
	if !isValidSolanaAddress(destination) {
		return errors.New("invalid Solana destination address format")
	}

	if !isValidAmount(amount) {
		return errors.New("invalid SOL amount (must be a positive number)")
	}

	return nil
}

// isValidSolanaAddress checks if the address is a valid Solana address
func isValidSolanaAddress(address string) bool {
	// Simple validation - in production use a proper Solana address validation
	return len(address) >= 32 && len(address) <= 44
}

// isValidAmount checks if the amount is valid
func isValidAmount(amount string) bool {
	// Simple validation - could be more sophisticated
	return len(amount) > 0 && amount[0] != '-'
}

// DeriveSolanaAddress derives a Solana address from a public key
// Solana addresses are the Base58 encoding of the public key bytes
func DeriveSolanaAddress(pubKey []byte) (string, error) {
	// Solana addresses are just Base58 encoded public keys
	address := base58.Encode(pubKey)
	return address, nil
}

// GenerateKeyPairString generates a Solana keypair string format
// This format is used by Solana CLI and some wallets
func GenerateKeyPairString(privateKey []byte, publicKey []byte) (string, error) {
	// Solana keypair is [private key bytes (32) + public key bytes (32)]
	keypair := append(privateKey, publicKey...)
	return base64.StdEncoding.EncodeToString(keypair), nil
}
