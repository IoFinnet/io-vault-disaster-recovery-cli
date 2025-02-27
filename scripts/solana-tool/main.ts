import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram, Transaction } from '@solana/web3.js';
import readlineSync from 'readline-sync';
import { webcrypto } from 'crypto';
import * as ed from '@noble/ed25519';
import { bytesToNumberBE, bytesToNumberLE, numberToBytesLE } from '@noble/curves/abstract/utils';
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
  
  // Return object with the public key and address
  return {
    publicKey: publicKey,
    address: publicKey.toBase58()
  };
}


/**
 * Transfers SOL on the Solana network.
 * @param privateKeyHex - The sender's private key in hex format.
 * @param destination - The destination address.
 * @param amount - The amount to transfer in SOL.
 * @param connection - The Solana connection.
 */
async function transferSOL(
  privateKeyHex: string,
  destination: string,
  amount: number,
  connection: Connection
): Promise<string> {
  try {
    // Get wallet from private key using our helper function - this gives us the correct public key
    const wallet = createKeypairFromPrivateKey(privateKeyHex);
    console.log(`Using wallet address: ${wallet.address}`);
    
    // For signing, we'll use the noble-ed25519 library directly
    const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
    
    const destinationPubkey = new PublicKey(destination);
    const lamports = amount * LAMPORTS_PER_SOL;

    // Create a new transaction
    const transaction = new Transaction();
    
    // Get recent blockhash and explicitly set it on the transaction
    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
    transaction.recentBlockhash = blockhash;
    transaction.lastValidBlockHeight = lastValidBlockHeight;
    
    // Set the fee payer to the correct public key
    transaction.feePayer = wallet.publicKey;
    
    // Add the transfer instruction using the correct public key
    transaction.add(
      SystemProgram.transfer({
        fromPubkey: wallet.publicKey,
        toPubkey: destinationPubkey,
        lamports,
      })
    );
    
    // Manually sign the transaction
    // 1. Get the message to sign
    const messageBytes = transaction.serializeMessage();
    console.log('Transaction message length:', messageBytes.length);
    
    // 2. Sign the message with our private key using the same method that works in XRPL
    const { signature } = await signWithScalar(Buffer.from(messageBytes).toString('hex'), privateKeyHex);
    console.log('Signature length:', Buffer.from(signature, 'hex').length);
    
    // 3. Add the signature to the transaction
    transaction.addSignature(wallet.publicKey, Buffer.from(signature, 'hex'));
    
    // Verify the signature
    const isValid = transaction.verifySignatures();
    console.log('Signature verification result:', isValid);
    
    if (!isValid) {
      throw new Error('Transaction signature verification failed');
    }
    
    console.log('Transaction signatures verified successfully');
    
    // Serialize and send the transaction
    const rawTransaction = transaction.serialize();
    console.log('Transaction serialized successfully, length:', rawTransaction.length);
    
    // Send transaction to the network
    console.log('Sending transaction to network...');
    const txid = await connection.sendRawTransaction(rawTransaction, {
      skipPreflight: false,
      preflightCommitment: 'confirmed',
    });
    console.log('Transaction sent, ID:', txid);

    // Wait for confirmation
    console.log('Waiting for confirmation...');
    const confirmation = await connection.confirmTransaction({
      blockhash,
      lastValidBlockHeight,
      signature: txid
    }, 'confirmed');
    
    if (confirmation.value.err) {
      throw new Error(`Transaction failed: ${JSON.stringify(confirmation.value.err)}`);
    }
    
    console.log('Transaction confirmed successfully');
    return txid;
  } catch (error) {
    console.error('Error during transaction:', error);
    throw error;
  }
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
    
    // Broadcast transaction confirmation
    const wantToBroadcast = readlineSync.keyInYNStrict('\nWould you like to broadcast this transaction now?');
    if (wantToBroadcast) {
      console.log('\nSigning and broadcasting transaction...');
      try {
        const signature = await transferSOL(privateKey, destination, Number(amount), connection);
        console.log('\nTransaction successful!');
        console.log(`Transaction signature: ${signature}`);
        
        // Create explorer URL based on network
        const network = networkOptions[networkIndex].toLowerCase();
        const explorerUrl = network === 'mainnet' 
          ? `https://explorer.solana.com/tx/${signature}` 
          : `https://explorer.solana.com/tx/${signature}?cluster=${network}`;
          
        console.log(`Transaction URL: ${explorerUrl}`);
      } catch (error: any) {
        console.error('\nTransaction failed:', error.message);
      }
    } else {
      console.log('\nTransaction not broadcast. You can use the Solana CLI or web wallet to send it later.');
    }
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

/**
 * Signs a message with a private key scalar using Ed25519.
 * Using the exact same implementation as in XRPL tool.
 * @param messageHex - The message to sign in hex format.
 * @param privateKeyHex - The private key in hex format.
 * @returns An object containing the signature and public key in hex format.
 */
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

/**
 * Converts a Uint8Array to a hex string.
 * @param bytes - The Uint8Array to convert.
 * @returns The hex string representation.
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

main().catch(console.error);
