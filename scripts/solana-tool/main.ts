import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, sendAndConfirmTransaction, SystemProgram, Transaction } from '@solana/web3.js';
import readlineSync from 'readline-sync';
import { webcrypto } from 'crypto';
import * as ed from '@noble/ed25519';
import { bytesToNumberBE } from '@noble/curves/abstract/utils';
import { sha512 } from '@noble/hashes/sha512';

// Polyfill for Node.js
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

// Constants
const MAINNET_URL = 'https://api.mainnet-beta.solana.com';
const TESTNET_URL = 'https://api.testnet.solana.com';
const DEVNET_URL = 'https://api.devnet.solana.com';

/**
 * Validates if the input string is a valid hex string of the given byte length.
 * @param key - The input string to validate.
 * @param length - The expected byte length.
 * @returns True if the input is a valid hex string; otherwise, false.
 */
function validateHexKey(key: string, length: number): boolean {
  if (!key.match(/^[0-9a-fA-F]+$/)) {
    return false;
  }
  return key.length === length * 2;
}

/**
 * Validates if the input is a valid Solana address.
 * @param address - The address to validate.
 * @returns True if the address is valid; otherwise, false.
 */
function validateSolanaAddress(address: string): boolean {
  try {
    new PublicKey(address);
    return true;
  } catch (error) {
    return false;
  }
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

/**
 * Creates a Solana keypair from a private key.
 * @param privateKeyHex - The private key in hex format.
 * @returns A Solana keypair.
 */
function createKeypairFromPrivateKey(privateKeyHex: string): Keypair {
  const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');

  // Calculate public key from private key
  const publicKeyBytes = ed.getPublicKey(privateKeyBytes);

  // Create a Solana keypair
  return Keypair.fromSecretKey(
    Uint8Array.from([...privateKeyBytes, ...publicKeyBytes])
  );
}

/**
 * Transfers SOL on the Solana network.
 * @param keypair - The sender's keypair.
 * @param destination - The destination address.
 * @param amount - The amount to transfer in SOL.
 * @param connection - The Solana connection.
 */
async function transferSOL(
  keypair: Keypair,
  destination: string,
  amount: number,
  connection: Connection
): Promise<string> {
  const destinationPubkey = new PublicKey(destination);
  const lamports = amount * LAMPORTS_PER_SOL;

  const transaction = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: keypair.publicKey,
      toPubkey: destinationPubkey,
      lamports,
    })
  );

  // Get the latest blockhash
  const { blockhash } = await connection.getLatestBlockhash();
  transaction.recentBlockhash = blockhash;
  transaction.feePayer = keypair.publicKey;

  // Sign and send the transaction
  const signature = await sendAndConfirmTransaction(
    connection,
    transaction,
    [keypair]
  );

  return signature;
}

async function main() {
  console.log('Solana Transfer Tool\n');

  // Select network
  const networkOptions = ['Mainnet', 'Testnet', 'Devnet'];
  const networkIndex = readlineSync.keyInSelect(networkOptions, 'Which network would you like to use?');

  if (networkIndex === -1) {
    console.log('Exiting...');
    return;
  }

  const networkUrls = [MAINNET_URL, TESTNET_URL, DEVNET_URL];
  const selectedUrl = networkUrls[networkIndex];
  console.log(`Using ${networkOptions[networkIndex]} network: ${selectedUrl}`);

  // Get private key
  let privateKey;
  do {
    privateKey = readlineSync.question('\nPrivate Key (64 hex chars): ', { hideEchoBack: true });
    if (!validateHexKey(privateKey, 32)) {
      console.log('Invalid private key format. Must be 64 hexadecimal characters.');
    }
  } while (!validateHexKey(privateKey, 32));

  try {
    // Create keypair from private key
    const keypair = createKeypairFromPrivateKey(privateKey);
    console.log(`\nDerived Solana Address: ${keypair.publicKey.toString()}`);

    // Connect to Solana network
    const connection = new Connection(selectedUrl, 'confirmed');

    // Check balance
    const checkBalance = readlineSync.keyInYNStrict('\nWould you like to check the wallet balance? (requires network connection)');

    let balance;
    if (checkBalance) {
      try {
        balance = await connection.getBalance(keypair.publicKey);
        console.log(`Balance: ${balance / LAMPORTS_PER_SOL} SOL`);
      } catch (error: any) {
        console.error('Error fetching balance:', error.message);
        console.log('Continuing in offline mode...');
      }
    }

    // Ask if user wants to transfer SOL
    const wantToTransfer = readlineSync.keyInYNStrict('\nWould you like to transfer SOL?');
    if (!wantToTransfer) {
      console.log('Exiting...');
      return;
    }

    // Get destination address
    let destination;
    do {
      destination = readlineSync.question('\nEnter destination address: ');
      if (!validateSolanaAddress(destination)) {
        console.log('Invalid Solana address format.');
      }
    } while (!validateSolanaAddress(destination));

    // Get amount to transfer
    let amount;
    do {
      amount = readlineSync.question('\nEnter amount of SOL to send: ');
      if (!validateAmount(amount)) {
        console.log('Invalid amount. Must be a positive number.');
      } else if (balance !== undefined && Number(amount) > balance / LAMPORTS_PER_SOL) {
        console.log('Amount exceeds available balance.');
        continue;
      }
      break;
    } while (true);

    // Confirm transaction
    console.log('\nTransaction Details:');
    console.log(`From: ${keypair.publicKey.toString()}`);
    console.log(`To: ${destination}`);
    console.log(`Amount: ${amount} SOL`);

    const confirmTransaction = readlineSync.keyInYNStrict('\nConfirm transaction?');
    if (!confirmTransaction) {
      console.log('Transaction cancelled.');
      return;
    }

    // Send transaction
    console.log('\nSending transaction...');
    const signature = await transferSOL(keypair, destination, Number(amount), connection);

    console.log('\nTransaction successful!');
    console.log(`Transaction signature: ${signature}`);
    console.log(`View on Solana Explorer: https://explorer.solana.com/tx/${signature}?cluster=${networkOptions[networkIndex].toLowerCase()}`);
  } catch (error: any) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main().catch(console.error);
// Handle CTRL+C gracefully
process.on('SIGINT', () => {
  console.log('\nProcess terminated by user (CTRL+C)');
  process.exit(0);
});
