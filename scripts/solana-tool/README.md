# Solana Recovery Tool

This tool allows you to recover and transfer SOL from a Solana wallet using a private key.

## Prerequisites

- Node.js (v16 or later)
- npm (v7 or later)

## Installation

1. Navigate to this directory:
   ```
   cd scripts/solana-tool
   ```

2. Install dependencies:
   ```
   npm install
   ```

## Usage

1. Run the tool:
   ```
   npm start
   ```

2. Follow the interactive prompts:
   - Select the network (Mainnet, Testnet, or Devnet)
   - Enter your private key (64 hex characters)
   - Check your wallet balance (optional)
   - Enter the destination address
   - Enter the amount of SOL to send
   - Confirm the transaction

## Security Notes

- This tool is designed to be run on a secure, offline computer.
- Never share your private key with anyone.
- The private key is not stored or transmitted anywhere.
