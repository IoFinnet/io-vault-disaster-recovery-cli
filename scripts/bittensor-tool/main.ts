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
  destination: '',
  amount: '',
  endpoint: DEFAULT_ENDPOINT,
  confirm: false
};

for (let i = 0; i < args.length; i++) {
  switch (args[i]) {
    case '--private-key':
    case '-p':
      commandLineArgs.privateKey = args[++i];
      break;
    case '--destination':
    case '-d':
      commandLineArgs.destination = args[++i];
      break;
    case '--amount':
    case '-a':
      commandLineArgs.amount = args[++i];
      break;
    case '--endpoint':
    case '-e':
      commandLineArgs.endpoint = args[++i];
      break;
    case '--confirm':
    case '-y':
      commandLineArgs.confirm = true;
      break;
    case '--help':
    case '-h':
      console.log(`
Usage: node main.js [options]

Options:
  -p, --private-key <key>     Private key (64 hex chars)
  -d, --destination <address> Destination address
  -a, --amount <amount>       Amount to transfer
  -e, --endpoint <url>        Endpoint URL (default: ${DEFAULT_ENDPOINT})
  -y, --confirm               Auto-confirm transaction without prompting
  -h, --help                  Show this help message
      
If any required parameter is not provided, you will be prompted for it interactively.
`);
      process.exit(0);
      break;
  }
}

/**
 * Transfers funds on the Bittensor network.
 * @param privateKeyHex - The raw Ed25519 private key in hex format.
 * @param destination - The SS58 destination address.
 * @param amount - The amount to transfer in Planck units.
 * @param endpoint - The WebSocket endpoint for the Bittensor network.
 */
async function transferFunds(privateKeyHex: string, destination: string, amount: string, endpoint: string) {
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

  // Only prompt if --confirm flag isn't set
  if (!commandLineArgs.confirm) {
    const wantToTransfer = readlineSync.keyInYNStrict('\nWould you like to proceed with the transaction?');
    if (!wantToTransfer) {
      console.log('Exiting...');
      process.exit(0);
    }
  }

  console.log("Creating transfer transaction...");
  const transfer = api.tx.balances.transferKeepAlive(destination, amount);

  console.log("Signing and sending transaction...");
  const signer = new CustomSigner(privateKey);
  const hash = await transfer.signAndSend(keyPair.address, { nonce: -1, signer });
  console.log(`Transaction sent successfully. Hash: ${hash.toHex()}`);

  await api.disconnect();
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
  console.log('Bittensor Transfer Tool\n');
  
  let privateKey = commandLineArgs.privateKey;
  let destination = commandLineArgs.destination;
  let amount = commandLineArgs.amount;
  let endpoint = commandLineArgs.endpoint;
  
  // If not provided via command line, prompt for private key
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
  if (endpoint === DEFAULT_ENDPOINT && !commandLineArgs.endpoint) {
    endpoint = readlineSync.question(
      'Enter the endpoint (e.g., wss://entrypoint-finney.opentensor.ai:443): ',
      { defaultInput: DEFAULT_ENDPOINT }
    );
    if (endpoint === EXIT_KEYWORD) {
      console.log('Exiting program...');
      process.exit(0);
    }
  }

  // If all parameters are provided via command line, ask for confirmation (unless --confirm flag is used)
  if (commandLineArgs.privateKey && commandLineArgs.destination && commandLineArgs.amount && !commandLineArgs.confirm) {
    console.log('\nTransaction Details:');
    console.log(`Destination: ${destination}`);
    console.log(`Amount: ${amount}`);
    console.log(`Endpoint: ${endpoint}`);
    
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
    await transferFunds(privateKey, destination, amountInPlanck.toString(), endpoint);
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
