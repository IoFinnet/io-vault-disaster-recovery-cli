import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';
import readlineSync from 'readline-sync';
import { BN } from 'bn.js';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// Constants
const DECIMALS = 9;
const PLANCK = new BN(10).pow(new BN(DECIMALS)); // 1 unit = 10^9 Planck
const SS58_FORMAT = 42; // SS58 address format for the Bittensor network

// Assign SHA512 hash function for noble-ed25519 compatibility
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/**
 * Transfers funds on the Bittensor network.
 * @param privateKey - The raw Ed25519 private key in hex format.
 * @param destination - The SS58 destination address.
 * @param amount - The amount to transfer in Planck units.
 * @param endpoint - The WebSocket endpoint for the Bittensor network.
 */
async function transferFunds(privateKey: string, destination: string, amount: string, endpoint: string) {
  console.log("Initializing cryptography...");
  await cryptoWaitReady();

  console.log("Connecting to the Bittensor network...");
  const provider = new WsProvider(endpoint);
  const api = await ApiPromise.create({ provider });

  console.log("Creating keyring...");
  const keyring = new Keyring({ type: 'ed25519', ss58Format: SS58_FORMAT });

  // Prepare the private key
  let privateKeyBytes = Buffer.from(privateKey, 'hex');

  // Derive the public key from the private key
  const derivedPublicKeyBytes = await ed.getPublicKey(privateKeyBytes);

  // Combine private and public keys to create the Ed25519 secret key
  const secretKey = Buffer.concat([privateKeyBytes, Buffer.from(derivedPublicKeyBytes)]);

  // Add the keypair to the keyring
  const keyPair = keyring.addFromPair({
    publicKey: derivedPublicKeyBytes,
    secretKey: secretKey,
  });

  console.log("Derived Address (SS58):", keyPair.address);

  console.log("Creating transfer transaction...");
  const transfer = api.tx.balances.transferKeepAlive(destination, amount);

  console.log("Signing and sending transaction...");
  const hash = await transfer.signAndSend(keyPair, { nonce: -1 });
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

  let privateKey;
  do {
    privateKey = readlineSync.question('Private Key (64 hex chars): ', { hideEchoBack: true });
    if (!validateHex(privateKey, 32)) {
      console.log('Invalid private key format. Must be 64 hexadecimal characters.');
    }
  } while (!validateHex(privateKey, 32));

  let destination;
  do {
    destination = readlineSync.question('Enter the destination address: ');
    if (!validateAddress(destination)) {
      console.log('Invalid address format. Must be a valid Bittensor address.');
    }
  } while (!validateAddress(destination));

  let amount;
  do {
    amount = readlineSync.question('Enter the amount to transfer: ');
    if (!validateAmount(amount)) {
      console.log('Invalid amount. Must be a positive number.');
    }
  } while (!validateAmount(amount));

  const endpoint = readlineSync.question(
    'Enter the endpoint (e.g., wss://entrypoint-finney.opentensor.ai:443): ',
    { defaultInput: 'wss://entrypoint-finney.opentensor.ai:443' }
  );

  console.log('\nProcessing your transaction...\n');
  try {
    // Convert amount to Planck units (smallest denomination)
    const amountInPlanck = new BN(Number(amount) * Number(PLANCK));
    await transferFunds(privateKey, destination, amountInPlanck.toString(), endpoint);
    console.log('Transaction completed successfully.');
  } catch (error) {
    console.error('Error processing transaction:', error.message);
  }
}

main();
