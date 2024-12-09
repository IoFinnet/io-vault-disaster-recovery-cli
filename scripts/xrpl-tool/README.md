# XRP Transfer Tool

A command-line tool for transferring XRP using EdDSA keypairs. This tool
allows you to:
- Import EdDSA keypairs in the scalar format used by the DR tool
- Check wallet balances (optional)
- Create and sign XRP transfer transactions
- Broadcast transactions to the XRPL network (optional)

## Prerequisites

- Node.js 16 or higher
- npm or yarn

## Installation

1. Clone this repository or download the files
2. Install dependencies:
```bash
npm i
```

## Running the Tool

Run the script using tsx:
```bash
npx tsx main.ts
```

## Usage Flow

1. Choose network (testnet/mainnet)
2. Enter your EdDSA keypair:
    - Public key (64 hex chars)
    - Private key (64 hex chars)
3. View your wallet address
4. Optionally check your wallet balance
5. Create a transfer:
    - Enter destination address
    - Enter amount of XRP
6. Review the signed transaction
7. Choose to broadcast now or save for later

## Offline Usage

The tool can work offline except for:

- Balance checking (optional)
- Transaction broadcasting (optional)

If you choose not to broadcast immediately, you'll receive instructions for
broadcasting the signed transaction later using other tools.

## Security Notes

- Your private key is never stored or transmitted
- The tool can be used offline for the most part
- Always verify transaction details before broadcasting
- Use testnet first to familiarize yourself with the tool

## Example Keys Format

Public and private keys should be in raw hex format (64 characters each).
Example:

- Public key:
`0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF`
- Private key:
`0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF`

## Error Handling

The tool includes validation for:

- Key format and length
- XRP amount validity
- Destination address format
- Available balance (if checked)
- Network connectivity issues
