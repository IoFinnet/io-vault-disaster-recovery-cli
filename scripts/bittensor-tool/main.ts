import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';
import readlineSync from 'readline-sync';
import { BN } from 'bn.js';
import { blake2AsHex, cryptoWaitReady } from '@polkadot/util-crypto';
import { Signer, SignerPayloadRaw, SignerResult } from '@polkadot/types/types';
import * as ed from '@noble/ed25519';
import { bytesToNumberBE, bytesToNumberLE, numberToBytesLE } from '@noble/curves/abstract/utils';
import { sha512 } from '@noble/hashes/sha512';
import { webcrypto } from 'crypto';

// Constants
const EXIT_KEYWORD = '.exit';
const EXIT_MESSAGE = `Type '${EXIT_KEYWORD}' at any prompt to exit the program`;

// Handle CTRL+C gracefully
process.on('SIGINT', () => {
  console.log('\nProcess terminated by user (CTRL+C)');
  process.exit(0);
});

// Override readlineSync to handle CTRL+C
const originalQuestion = readlineSync.question;
readlineSync.question = function(...args) {
  process.stdin.setRawMode(false);
  const result = originalQuestion.apply(this, args);
  return result;
};

// Constants
const DECIMALS = 9;
const PLANCK = new BN(10).pow(new BN(DECIMALS)); // 1 unit = 10^9 Planck
const SS58_FORMAT = 42; // SS58 address format for the Bittensor network
const DEFAULT_ENDPOINT = 'wss://entrypoint-finney.opentensor.ai:443';

// Assign SHA512 hash function for noble-ed25519 compatibility
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

// Parse command line arguments
const args = process.argv.slice(2);
const commandLineArgs = {
  privateKey: '',
  address: '',
  destination: '',
  amount: '',
  endpoint: DEFAULT_ENDPOINT,
  checkBalance: false,
  confirm: false,
  network: '',
  offline: false,
  nonce: -1
};

for (let i = 0; i < args.length; i++) {
  switch (args[i]) {
    case '--private-key':
    case '-p':
      commandLineArgs.privateKey = args[++i];
      break;
    case '--address':
    case '-a':
      commandLineArgs.address = args[++i];
      break;
    case '--destination':
    case '-d':
      commandLineArgs.destination = args[++i];
      break;
    case '--amount':
    case '-m':
      commandLineArgs.amount = args[++i];
      break;
    case '--endpoint':
    case '-e':
      commandLineArgs.endpoint = args[++i];
      break;
    case '--network':
    case '-n':
      commandLineArgs.network = args[++i];
      break;
    case '--check-balance':
    case '-c':
      commandLineArgs.checkBalance = true;
      break;
    case '--confirm':
    case '-y':
      commandLineArgs.confirm = true;
      break;
    case '--offline':
    case '-o':
      commandLineArgs.offline = true;
      break;
    case '--nonce':
      commandLineArgs.nonce = parseInt(args[++i], 10);
      break;
    case '--help':
    case '-h':
      console.log(`
Usage: node main.js [options]

Options:
  -p, --private-key <key>     Private key (64 hex chars) for transaction signing
  -a, --address <address>     Address to check balance (use this with --check-balance)
  -d, --destination <address> Destination address for transfers
  -m, --amount <amount>       Amount to transfer
  -e, --endpoint <url>        Endpoint URL (default: ${DEFAULT_ENDPOINT})
  -n, --network <network>     Network to use (mainnet, testnet)
  -c, --check-balance         Check wallet balance
  -y, --confirm               Auto-confirm transaction without prompting
  -o, --offline               Use offline mode (for air-gapped environments)
      --nonce <number>        Account nonce for offline signing (default: ask or auto-detect)
  -h, --help                  Show this help message

For balance checks: Use --address and --check-balance
For transfers: Use --private-key, --destination, and --amount
For offline transactions: Add --offline and optionally --nonce
If any required parameter is not provided, you will be prompted for it interactively.
`);
      process.exit(0);
      break;
  }
}

/**
 * Check the balance of a wallet on the Bittensor network using SS58 address.
 * @param address - The SS58 address to check.
 * @param endpoint - The WebSocket endpoint for the Bittensor network.
 */
async function checkBalanceByAddress(address: string, endpoint: string) {
  await cryptoWaitReady();

  console.log("Connecting to the Bittensor network...");
  const provider = new WsProvider(endpoint);
  const api = await ApiPromise.create({ provider });

  try {
    // Get account information
    console.log(`Checking balance for address: ${address}`);
    const accountInfo = await api.query.system.account(address);

    // Extract and display the balance
    const free = accountInfo.data.free.toBigInt();
    const reserved = accountInfo.data.reserved.toBigInt();
    const total = free + reserved;

    // Convert from Planck (smallest unit) to TAO
    const freeBalance = Number(free) / Number(PLANCK);
    const reservedBalance = Number(reserved) / Number(PLANCK);
    const totalBalance = Number(total) / Number(PLANCK);

    console.log("\nBalance Information:");
    console.log(`Free Balance: ${freeBalance.toFixed(9)} TAO`);
    console.log(`Reserved Balance: ${reservedBalance.toFixed(9)} TAO`);
    console.log(`Total Balance: ${totalBalance.toFixed(9)} TAO`);
  } catch (error) {
    console.error("Error fetching balance:", error.message);
  } finally {
    await api.disconnect();
  }
}

/**
 * Check the balance of a wallet on the Bittensor network using private key.
 * @param privateKeyHex - The raw Ed25519 private key in hex format.
 * @param endpoint - The WebSocket endpoint for the Bittensor network.
 */
async function checkBalanceByPrivateKey(privateKeyHex: string, endpoint: string) {
  await cryptoWaitReady();

  console.log("Connecting to the Bittensor network...");
  const provider = new WsProvider(endpoint);
  const api = await ApiPromise.create({ provider });

  console.log("Creating keyring...");
  const keyring = new Keyring({ type: 'ed25519', ss58Format: SS58_FORMAT });

  // Prepare the private key
  let privateKey = Buffer.from(privateKeyHex, 'hex');
  if (privateKey.length !== 32) {
    throw new Error('Private key must be 32 bytes');
  }

  // Derive the public key from the private key
  const publicKey = ed.ExtendedPoint.BASE.multiply(bytesToNumberBE(privateKey)).toRawBytes();
  console.log("Derived Public Key (Hex):", Buffer.from(publicKey).toString('hex'));

  // Add the keypair to the keyring
  const keyPair = keyring.addFromPair({
    publicKey: publicKey,
    secretKey: new Uint8Array(0),
  });

  console.log("Derived Address (SS58):", keyPair.address);

  try {
    // Get account information
    const accountInfo = await api.query.system.account(keyPair.address);

    // Extract and display the balance
    const free = accountInfo.data.free.toBigInt();
    const reserved = accountInfo.data.reserved.toBigInt();
    const total = free + reserved;

    // Convert from Planck (smallest unit) to TAO
    const freeBalance = Number(free) / Number(PLANCK);
    const reservedBalance = Number(reserved) / Number(PLANCK);
    const totalBalance = Number(total) / Number(PLANCK);

    console.log("\nBalance Information:");
    console.log(`Free Balance: ${freeBalance.toFixed(9)} TAO`);
    console.log(`Reserved Balance: ${reservedBalance.toFixed(9)} TAO`);
    console.log(`Total Balance: ${totalBalance.toFixed(9)} TAO`);
  } catch (error) {
    console.error("Error fetching balance:", error.message);
  } finally {
    await api.disconnect();
  }
}

/**
 * Transfers funds on the Bittensor network.
 * @param privateKeyHex - The raw Ed25519 private key in hex format.
 * @param destination - The SS58 destination address.
 * @param amount - The amount to transfer in Planck units.
 * @param endpoint - The WebSocket endpoint for the Bittensor network.
 * @param offlineMode - Whether to operate in offline mode.
 * @param nonceValue - Optional nonce value for offline signing.
 */
async function transferFunds(privateKeyHex: string, destination: string, amount: string, endpoint: string, offlineMode: boolean = false, nonceValue: number = -1) {
  await cryptoWaitReady();

  // Prepare the private key
  let privateKey = Buffer.from(privateKeyHex, 'hex');
  if (privateKey.length !== 32) {
    throw new Error('Private key must be 32 bytes');
  }

  // Derive the public key from the private key
  const publicKey = ed.ExtendedPoint.BASE.multiply(bytesToNumberBE(privateKey)).toRawBytes();
  console.log("Derived Public Key (Hex):", Buffer.from(publicKey).toString('hex'));

  // Create keyring
  console.log("Creating keyring...");
  const keyring = new Keyring({ type: 'ed25519', ss58Format: SS58_FORMAT });

  // Add the keypair to the keyring
  const keyPair = keyring.addFromPair({
    publicKey: publicKey,
    secretKey: new Uint8Array(0),
  });

  console.log("Derived Address (SS58):", keyPair.address);

  // Check if offline mode is explicitly requested or should be prompted
  if (!offlineMode) {
    console.log('Using online mode. Restart with the flag --offline to use offline mode.');
  }

  if (offlineMode) {
    // In offline mode, we need a nonce value
    let nonce = nonceValue;
    if (nonce === -1) {
      // Prompt for nonce since we can't get it from the network
      const nonceInput = readlineSync.question('\nEnter account nonce (required for offline transactions): ');
      if (!nonceInput || isNaN(parseInt(nonceInput, 10))) {
        console.error('\nError: Valid nonce is required for offline transactions.');
        console.log('\nTo get your account nonce:');
        console.log('1. Run this tool with --check-balance on an internet-connected device');
        console.log('2. Or check your account on a Bittensor network explorer');
        process.exit(1);
      }
      nonce = parseInt(nonceInput, 10);
    }

    console.log(`Using nonce: ${nonce}`);
    console.log("\nIn offline mode, your transaction will be prepared but not broadcast.");
    console.log("You will need to take the signed data to an internet-connected machine to broadcast it.");

    try {
      // Connect to network to create a transaction (this will fail in offline mode)
      console.log("\nAttempting to create a transaction template...");
      let txData: any = null;

      try {
        // Try to connect just to get types, but expect this to fail in true offline mode
        const provider = new WsProvider(endpoint);
        const api = await Promise.race([
          ApiPromise.create({ provider }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Connection timeout')), 5000))
        ]);

        // If we got here, we have a network connection
        console.log("Successfully connected to network. Creating transaction...");
        const transfer = api.tx.balances.transferKeepAlive(destination, amount);

        // Get transaction data as hex
        txData = transfer.toHex();
        await api.disconnect();

        console.log("Created transaction template from network connection.");
      } catch (error) {
        console.log("Could not connect to network as expected in offline mode.");
        console.log("For offline transactions, you need the following information from an online source:");
        console.log("1. Your account nonce (provided as: " + nonce + ")");
        console.log("2. Destination address (provided as: " + destination + ")");
        console.log("3. Amount in Planck units (provided as: " + amount + " Planck)");

        console.log("\nThis script cannot construct a raw transaction without network types in fully offline mode.");
        console.log("Please prepare the transaction on an internet-connected machine without broadcasting,");
        console.log("then sign it on your air-gapped machine.");

        return {
          success: false,
          message: "Cannot create transaction in fully offline mode without network connection",
          nonce: nonce
        };
      }

      console.log("\nTransaction details prepared for offline signing:");
      console.log(`From: ${keyPair.address}`);
      console.log(`To: ${destination}`);
      console.log(`Amount: ${new BN(amount).div(PLANCK).toString()} TAO`);
      console.log(`Nonce: ${nonce}`);

      if (txData) {
        console.log("\n========== SIGNED TRANSACTION HEX ==========");
        console.log(txData);
        console.log("==========================================");

        console.log("\nCopy this transaction hex data and save it for broadcasting from an online device.");

        console.log("\nTo broadcast this transaction:");
        console.log("1. Use the Polkadot.js interface: https://polkadot.js.org/apps/#/extrinsics");
        console.log("2. Or use the Bittensor CLI: bt transfer --raw_tx <hex_data>");
        console.log("3. Or use the Substrate CLI: substrate tx submit --raw <hex_data>");
      }

      return {
        success: true,
        message: "Transaction prepared offline successfully",
        txData: txData,
        nonce: nonce
      };
    } catch (error) {
      console.error("Error preparing offline transaction:", error.message);
      return {
        success: false,
        message: error.message,
        nonce: nonce
      };
    }
  } else {
    console.log('Using online mode. Restart with the flag --offline to use offline mode.');

    // Online mode - connect to the network
    console.log("Connecting to the Bittensor network...");
    const provider = new WsProvider(endpoint);

    try {
      const api = await ApiPromise.create({ provider });

      console.log("Creating transfer transaction...");
      const transfer = api.tx.balances.transferKeepAlive(destination, amount);

      // Use provided nonce or auto-detect
      const nonceOptions = nonceValue >= 0 ? { nonce: nonceValue } : { nonce: -1 };

      console.log("Signing and sending transaction...");
      const signer = new CustomSigner(privateKey);
      const hash = await transfer.signAndSend(keyPair.address, { ...nonceOptions, signer });
      console.log(`Transaction sent successfully. Hash: ${hash.toHex()}`);

      await api.disconnect();

      return {
        success: true,
        hash: hash.toHex(),
        message: "Transaction sent successfully"
      };
    } catch (error) {
      console.error("Error during transaction:", error.message);
      console.log("\nIf you are in an environment without network connectivity,");
      console.log("try running with the --offline flag to prepare a transaction for later broadcast.");

      await provider.disconnect();
      throw error;
    }
  }
}

/**
 * Validates if the input string is a valid hex string of the given byte length.
 * @param input - The input string to validate.
 * @param length - The expected byte length.
 * @returns True if the input is a valid hex string; otherwise, false.
 */
function validateHex(input: string, length: number): boolean {
  return input.length === length * 2 && /^[0-9a-fA-F]+$/.test(input);
}

/**
 * Validates if the input is a valid SS58 address.
 * @param address - The SS58 address to validate.
 * @returns True if the address is valid; otherwise, false.
 */
function validateAddress(address: string): boolean {
  return address.length === 48 && /^[1-9A-HJ-NP-Za-km-z]+$/.test(address);
}

/**
 * Validates if the input is a positive numeric amount.
 * @param amount - The input amount.
 * @returns True if the amount is valid; otherwise, false.
 */
function validateAmount(amount: string): boolean {
  const num = Number(amount);
  return !isNaN(num) && num > 0;
}

async function main() {
  // Set title based on mode
  if (commandLineArgs.checkBalance) {
    console.log('Bittensor Balance Check Tool\n');
  } else {
    console.log('Bittensor Transfer Tool\n');
  }

  let privateKey = commandLineArgs.privateKey;
  let address = commandLineArgs.address;
  let destination = commandLineArgs.destination;
  let amount = commandLineArgs.amount;
  let endpoint = commandLineArgs.endpoint;
  let offlineMode = commandLineArgs.offline;
  let nonce = commandLineArgs.nonce;

  // Handle network parameter if provided
  if (commandLineArgs.network) {
    if (commandLineArgs.network === 'mainnet') {
      endpoint = 'wss://entrypoint-finney.opentensor.ai:443';
      console.log('Using mainnet network');
    } else if (commandLineArgs.network === 'testnet') {
      endpoint = 'wss://test.finney.opentensor.ai:443';
      console.log('Using testnet network');
    } else {
      console.error(`Invalid network: ${commandLineArgs.network}. Must be either 'mainnet' or 'testnet'`);
      process.exit(1);
    }
  }

  // If checking balance, prioritize address parameter
  if (commandLineArgs.checkBalance) {
    // If address is not provided but we have a private key, derive the address
    if (!address && privateKey) {
      if (!validateHex(privateKey, 32)) {
        console.error('Invalid private key format. Must be 64 hexadecimal characters.');
        process.exit(1);
      }

      console.log('\nChecking balance using private key...\n');
      try {
        await checkBalanceByPrivateKey(privateKey, endpoint);
        return;
      } catch (error) {
        console.error('Error checking balance:', error.message);
        process.exit(1);
      }
    }

    // If address is provided, validate and use it
    if (address) {
      if (!validateAddress(address)) {
        console.error('Invalid address format. Must be a valid Bittensor address.');
        process.exit(1);
      }

      console.log('\nChecking balance...\n');
      try {
        await checkBalanceByAddress(address, endpoint);
        return;
      } catch (error) {
        console.error('Error checking balance:', error.message);
        process.exit(1);
      }
    }

    // If neither address nor private key is provided, prompt for address
    console.log(EXIT_MESSAGE);
    do {
      const usePrivateKey = readlineSync.keyInYNStrict('Would you like to check balance using a private key? (No for address)');

      if (usePrivateKey) {
        do {
          privateKey = readlineSync.question('Private Key (64 hex chars): ', { hideEchoBack: true });
          if (privateKey === EXIT_KEYWORD) {
            console.log('Exiting program...');
            process.exit(0);
          }
          if (!validateHex(privateKey, 32)) {
            console.log('Invalid private key format. Must be 64 hexadecimal characters.');
          }
        } while (!validateHex(privateKey, 32));

        console.log('\nChecking balance using private key...\n');
        try {
          await checkBalanceByPrivateKey(privateKey, endpoint);
          return;
        } catch (error) {
          console.error('Error checking balance:', error.message);
          process.exit(1);
        }
      } else {
        do {
          address = readlineSync.question('Enter the address to check: ');
          if (address === EXIT_KEYWORD) {
            console.log('Exiting program...');
            process.exit(0);
          }
          if (!validateAddress(address)) {
            console.log('Invalid address format. Must be a valid Bittensor address.');
          }
        } while (!validateAddress(address));

        console.log('\nChecking balance...\n');
        try {
          await checkBalanceByAddress(address, endpoint);
          return;
        } catch (error) {
          console.error('Error checking balance:', error.message);
          process.exit(1);
        }
      }
    } while (false); // Just to allow break

    return;
  }

  // For transfer operations, require private key
  if (!privateKey) {
    console.log(EXIT_MESSAGE);
    do {
      privateKey = readlineSync.question('Private Key (64 hex chars): ', { hideEchoBack: true });
      if (privateKey === EXIT_KEYWORD) {
        console.log('Exiting program...');
        process.exit(0);
      }
      if (!validateHex(privateKey, 32)) {
        console.log('Invalid private key format. Must be 64 hexadecimal characters.');
      }
    } while (!validateHex(privateKey, 32));
  } else if (!validateHex(privateKey, 32)) {
    console.error('Invalid private key format. Must be 64 hexadecimal characters.');
    process.exit(1);
  }

  // If not provided via command line, prompt for destination
  if (!destination) {
    do {
      destination = readlineSync.question('Enter the destination address: ');
      if (destination === EXIT_KEYWORD) {
        console.log('Exiting program...');
        process.exit(0);
      }
      if (!validateAddress(destination)) {
        console.log('Invalid address format. Must be a valid Bittensor address.');
      }
    } while (!validateAddress(destination));
  } else if (!validateAddress(destination)) {
    console.error('Invalid address format. Must be a valid Bittensor address.');
    process.exit(1);
  }

  // If not provided via command line, prompt for amount
  if (!amount) {
    do {
      amount = readlineSync.question('Enter the amount to transfer: ');
      if (amount === EXIT_KEYWORD) {
        console.log('Exiting program...');
        process.exit(0);
      }
      if (!validateAmount(amount)) {
        console.log('Invalid amount. Must be a positive number.');
      }
    } while (!validateAmount(amount));
  } else if (!validateAmount(amount)) {
    console.error('Invalid amount. Must be a positive number.');
    process.exit(1);
  }

  // If not provided via command line, prompt for endpoint
  if (endpoint === DEFAULT_ENDPOINT && !commandLineArgs.endpoint && !commandLineArgs.network) {
    endpoint = readlineSync.question(
      'Enter the endpoint (e.g., wss://entrypoint-finney.opentensor.ai:443): ',
      { defaultInput: DEFAULT_ENDPOINT }
    );
    if (endpoint === EXIT_KEYWORD) {
      console.log('Exiting program...');
      process.exit(0);
    }
  }

  // Check if offline mode is explicitly requested or should be prompted
  if (!offlineMode) {
    offlineMode = readlineSync.keyInYNStrict('Would you like to operate in offline mode? (recommended for secure environments)');
  }

  if (offlineMode) {
    console.log('Running in offline mode - network connection will not be required for transactions');
  }

  // If all parameters are provided via command line, ask for confirmation (unless --confirm flag is used)
  if (commandLineArgs.privateKey && commandLineArgs.destination && commandLineArgs.amount && !commandLineArgs.confirm) {
    console.log('\nTransaction Details:');
    console.log(`Destination: ${destination}`);
    console.log(`Amount: ${amount}`);
    console.log(`Endpoint: ${endpoint}`);
    console.log(`Offline Mode: ${offlineMode ? 'Yes' : 'No'}`);
    if (nonce >= 0) {
      console.log(`Nonce: ${nonce}`);
    }

    const confirm = readlineSync.keyInYNStrict('\nConfirm transaction?');
    if (!confirm) {
      console.log('Transaction cancelled.');
      process.exit(0);
    }
  }

  console.log('\nProcessing your transaction...\n');
  try {
    // Convert amount to Planck units (smallest denomination)
    const amountInPlanck = new BN(Number(amount) * Number(PLANCK));
    const result = await transferFunds(privateKey, destination, amountInPlanck.toString(), endpoint, offlineMode, nonce);

    if (result && result.success) {
      if (offlineMode) {
        console.log('\nTransaction prepared successfully for offline signing.');
        if (result.txData) {
          console.log('You can take this transaction data to broadcast on a connected device.');
        }
      } else {
        console.log('\nTransaction completed successfully!');
        if (result.hash) {
          console.log(`Transaction hash: ${result.hash}`);
        }
      }
    } else if (result) {
      console.error(`\nError: ${result.message}`);
      process.exit(1);
    }
  } catch (error) {
    console.error('Error processing transaction:', error.message);
    process.exit(1);
  }
}

main().catch(console.error);

class CustomSigner implements Signer {
  private privateKey: Uint8Array;

  constructor(privateKey: Uint8Array) {
    this.privateKey = privateKey;
  }

  // this is the interface function of the Signer interface called by Polkadot.js
  public async signRaw({ data }: SignerPayloadRaw): Promise<SignerResult> {
    // eslint-disable-next-line no-async-promise-executor
    return new Promise(async (resolve, reject): Promise<void> => {
      const payloadHex = (data.length > (256 + 1) * 2 ? blake2AsHex(data) : data) as `0x${string}`;
      console.info('Signer Payload:', payloadHex);

      let { signature: signatureHex } = await signWithScalar(payloadHex, Buffer.from(this.privateKey).toString('hex'));
      signatureHex = '00' + signatureHex.slice(0, 128)
      if (signatureHex.length !== 65 * 2) {
        reject(new Error(`Invalid signature, must be hex of the expected length (got: ${signatureHex.length})`));
        return;
      } else {
        resolve({ id: 1, signature: '0x' + signatureHex as `0x{string}` });
      }
    });
  }
}

async function signWithScalar(messageHex: string, privateKeyHex: string): Promise<{ signature: string, publicKey: string }> {
  // Remove '0x' prefix if present from inputs
  messageHex = messageHex.replace(/^0x/, '');
  privateKeyHex = privateKeyHex.replace(/^0x/, '');

  // Convert hex message to Uint8Array
  const message = Buffer.from(messageHex, 'hex');

  // Convert hex private key scalar to Uint8Array
  const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
  const scalar = bytesToNumberBE(privateKeyBytes);
  if (scalar >= ed.CURVE.n) {
    throw new Error('Private key scalar must be less than curve order');
  }

  // Validate private key length (32 bytes for Ed25519)
  if (privateKeyBytes.length !== 32) {
    throw new Error('Private key must be 32 bytes');
  }

  // Calculate public key directly from private key scalar
  const publicKey = ed.ExtendedPoint.BASE.multiply(bytesToNumberBE(privateKeyBytes)).toRawBytes();

  // Note: This nonce generation differs from standard Ed25519, which uses
  // the first half of SHA-512(private_key_seed). We're creating a deterministic
  // nonce from the raw scalar and message instead.
  const nonceInput = new Uint8Array([...privateKeyBytes, ...message]);
  const nonceArrayBuffer = await webcrypto.subtle.digest('SHA-512', nonceInput);
  const nonceArray = new Uint8Array(nonceArrayBuffer);

  // Reduce nonce modulo L (Ed25519 curve order)
  const reducedNonce = bytesToNumberLE(nonceArray) % ed.CURVE.n;

  // Calculate R = k * G
  const R = ed.ExtendedPoint.BASE.multiply(reducedNonce);

  // Calculate S = (r + H(R,A,m) * s) mod L
  const hramInput = new Uint8Array([
    ...R.toRawBytes(),
    ...publicKey,
    ...message
  ]);

  const hArrayBuffer = await webcrypto.subtle.digest('SHA-512', hramInput);
  const h = new Uint8Array(hArrayBuffer);
  const hnum = bytesToNumberLE(h) % ed.CURVE.n;

  const s = bytesToNumberBE(privateKeyBytes);
  const S = (reducedNonce + (hnum * s)) % ed.CURVE.n;

  // Combine R and S to form signature
  const signature = new Uint8Array([
    ...R.toRawBytes(),
    ...numberToBytesLE(S, 32)
  ]);

  // Convert outputs to hex strings
  return {
    signature: bytesToHex(signature),
    publicKey: bytesToHex(publicKey)
  };
}

// Helper function to convert Uint8Array to hex string
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
  .map(b => b.toString(16).padStart(2, '0'))
  .join('');
}
