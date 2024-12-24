# Bittensor Disaster Recovery Transfer Tool

A command-line tool for transferring **TAO** (Bittensor) tokens using EdDSA/Ed25519 keypairs. This tool allows you to:
  - Import Ed25519 keypairs in raw hex format for disaster recovery
- Derive the correct Bittensor SS58 wallet address
- Create and sign TAO transfer transactions
- Broadcast transactions to the Bittensor Substrate network

## Prerequisites

- **Node.js 20** or higher
- **npm** or **yarn**

## Installation

1. Clone this repository or download the files.
2. Install dependencies:
  ```bash
   npm install
   ```

## Running the Tool

Run the script using **tsx** (TypeScript Execution):

```bash
npx tsx main.ts
```

## Usage Flow

1. Enter your **EdDSA keypair** in raw hex format:
  - Public key (64 hex characters)
- Private key (64 hex characters)
2. Verify your **derived SS58 address**.
3. Enter transaction details:
  - Destination Bittensor wallet address (SS58 format)
- Amount of TAO to transfer
4. Review the transaction details.
5. Sign and broadcast the transaction to the network.

---

## Example Keys Format

The tool expects your Ed25519 public and private keys in raw hex format (32 bytes each, 64 hex characters total). Example:

  - **Public key**:
`d6c1b2d7c4e47e72d937f64c90bc2e3775d40a8e38c2990c4397dcb1b0d6a512`

- **Private key**:
`32e1f1725190e14500a865a4dae637129d7959025164a9c0f58247c4d00ebd12`

---

## Security Notes

- Your private key is **never stored or transmitted**.
- The tool can run **offline**, except for broadcasting the transaction.
- Always verify the derived wallet address before proceeding.
- Use the **testnet** environment first to ensure the keys and flow are correct.

---

## Network Configuration

You can specify a Bittensor node endpoint for broadcasting transactions:

  - **Mainnet**: `wss://entrypoint-finney.opentensor.ai:443`
- **Testnet**: Replace with the appropriate endpoint.

  You will be prompted to enter the endpoint during execution.

---

## Offline Usage

The tool can be run offline for:
- Keypair recovery and SS58 address derivation.
- Transaction preparation and signing.

**Note**: Broadcasting requires an active connection to the Bittensor Substrate network.

---

## Error Handling

The tool includes validation for:
- Private and public key format (32 bytes / 64 hex characters).
- SS58 address format (Bittensor prefix `42`).
- Valid TAO transfer amounts.
- Network connectivity issues when broadcasting.

  If a mismatch occurs between the derived public key and provided public key, the tool will alert you and stop execution.

---

## Example Workflow

### 1. Run the Tool

  ```bash
npm run start
```

### 2. Enter Keypair

  ```plaintext
Public Key (64 hex chars): d6c1b2d7c4e47e72d937f64c90bc2e3775d40a8e38c2990c4397dcb1b0d6a512
Private Key (64 hex chars): 32e1f1725190e14500a865a4dae637129d7959025164a9c0f58247c4d00ebd12
```

### 3. Verify Derived Address

  ```plaintext
Derived Address (SS58): 5DDRNSii3jUdb4yWot6ZvzeXg3DtUG7vWXQzVJkbVnZKYqUG
```

### 4. Enter Transaction Details & Broadcast

  ```plaintext
Enter the destination address: 5Fexample1234567890addressHere
Enter the amount of TAO to transfer: 1.0
Enter the endpoint (default: wss://entrypoint-finney.opentensor.ai:443): 
```

---

## Troubleshooting

- **Invalid Signature Error**: Ensure that the public key matches the private key. If using an MPC system, verify the keys align correctly.
- **Address Mismatch**: The derived address must match the expected address. Double-check the private key input.
- **Network Issues**: Verify the Substrate endpoint URL and your internet connection.

