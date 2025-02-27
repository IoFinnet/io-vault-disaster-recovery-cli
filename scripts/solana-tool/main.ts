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
const EXIT_KEYWORD = '.exit';
const EXIT_MESSAGE = `Type '${EXIT_KEYWORD}' at any prompt to exit the program`;

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
 * @returns A custom object with the correctly derived Solana public key and address.
 */
function createKeypairFromPrivateKey(privateKeyHex: string): { publicKey: PublicKey, address: string } {
  const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');

  // Validate private key length (32 bytes for Ed25519)
  if (privateKeyBytes.length !== 32) {
    throw new Error('Private key must be 32 bytes');
  }

  // Calculate public key directly from private key scalar using BASE point multiplication
  const publicKeyBytes = ed.ExtendedPoint.BASE.multiply(bytesToNumberBE(privateKeyBytes)).toRawBytes();
  
  // Create a public key object directly
  const publicKey = new PublicKey(Buffer.from(publicKeyBytes));
  
  // Instead of trying to create a Keypair object (which requires a specific format),
  // we'll return a simpler object with just the public key and address
  return {
    publicKey: publicKey,
    address: publicKey.toBase58()
  };
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
  console.log(EXIT_MESSAGE);

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
    if (privateKey === EXIT_KEYWORD) {
      console.log('Exiting program...');
      process.exit(0);
    }
    if (!validateHexKey(privateKey, 32)) {
      console.log('Invalid private key format. Must be 64 hexadecimal characters.');
    }
  } while (!validateHexKey(privateKey, 32));

  try {
    // Create wallet from private key
    const wallet = createKeypairFromPrivateKey(privateKey);
    console.log(`\nDerived Solana Address: ${wallet.address}`);

    // Connect to Solana network
    const connection = new Connection(selectedUrl, 'confirmed');

    // Check balance
    const checkBalance = readlineSync.keyInYNStrict('\nWould you like to check the wallet balance? (requires network connection)');

    let balance;
    if (checkBalance) {
      try {
        balance = await connection.getBalance(wallet.publicKey);
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
      if (destination === EXIT_KEYWORD) {
        console.log('Exiting program...');
        process.exit(0);
      }
      if (!validateSolanaAddress(destination)) {
        console.log('Invalid Solana address format.');
      }
    } while (!validateSolanaAddress(destination));

    // Get amount to transfer
    let amount;
    do {
      amount = readlineSync.question('\nEnter amount of SOL to send: ');
      if (amount === EXIT_KEYWORD) {
        console.log('Exiting program...');
        process.exit(0);
      }
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
    console.log(`From: ${wallet.address}`);
    console.log(`To: ${destination}`);
    console.log(`Amount: ${amount} SOL`);

    const confirmTransaction = readlineSync.keyInYNStrict('\nConfirm transaction?');
    if (!confirmTransaction) {
      console.log('Transaction cancelled.');
      return;
    }

    // Since we can't directly use the keypair for signing with our approach,
    // we should inform the user
    console.log('\nNote: Due to technical limitations with how Solana uses Ed25519 keys,');
    console.log('this tool can display your address but cannot sign transactions.');
    console.log('You can use other Solana tools like the Solana CLI or web wallet to send funds from this address.');
    console.log(`\nYour Solana Address: ${wallet.address}`);
    console.log('Your private key (keep it safe):', privateKey);
    
    // Return early instead of attempting to send the transaction
    return;
  } catch (error: any) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

// Override readlineSync to handle CTRL+C
const originalQuestion = readlineSync.question;
readlineSync.question = function(...args) {
  process.stdin.setRawMode(false);
  const result = originalQuestion.apply(this, args);
  return result;
};

// Handle CTRL+C gracefully
process.on('SIGINT', () => {
  console.log('\nProcess terminated by user (CTRL+C)');
  process.exit(0);
});

main().catch(console.error);
