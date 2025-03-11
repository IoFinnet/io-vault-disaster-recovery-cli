import { Client, decode, encode, encodeForSigning, Transaction, verifySignature, Wallet, xrpToDrops } from 'xrpl';
import readlineSync from 'readline-sync';
import { webcrypto } from 'crypto';
import * as ed from '@noble/ed25519';
import { bytesToNumberBE, bytesToNumberLE, numberToBytesLE } from '@noble/curves/abstract/utils';
import { hashSignedTx } from 'xrpl/dist/npm/utils/hashes';
import { sha512 } from '@noble/hashes/sha512';

// Constants
const EXIT_KEYWORD = '.exit';
const EXIT_MESSAGE = `Type '${EXIT_KEYWORD}' at any prompt to exit the program`;

// polyfill for Node.js
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

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

const TESTNET_URL = 'wss://testnet.xrpl-labs.com';
const MAINNET_URL = 'wss://s1.ripple.com';

// Parse command line arguments
const args = process.argv.slice(2);
const commandLineArgs = {
  publicKey: '',
  privateKey: '',
  destination: '',
  amount: '',
  network: '',
  checkBalance: false,
  broadcast: false,
  confirm: false
};

for (let i = 0; i < args.length; i++) {
  switch (args[i]) {
    case '--public-key':
    case '-k':
      commandLineArgs.publicKey = args[++i];
      break;
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
    case '--network':
    case '-n':
      commandLineArgs.network = args[++i]?.toLowerCase();
      break;
    case '--check-balance':
    case '-c':
      commandLineArgs.checkBalance = true;
      break;
    case '--broadcast':
    case '-b':
      commandLineArgs.broadcast = true;
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
  -k, --public-key <key>      Public key (64 hex chars)
  -p, --private-key <key>     Private key (64 hex chars)
  -d, --destination <address> Destination address
  -a, --amount <amount>       Amount of XRP to transfer
  -n, --network <network>     Network to use (mainnet, testnet)
  -c, --check-balance         Check wallet balance before transfer
  -b, --broadcast             Broadcast the transaction
  -y, --confirm               Auto-confirm transaction without prompting
  -h, --help                  Show this help message
      
If any required parameter is not provided, you will be prompted for it interactively.
`);
      process.exit(0);
      break;
  }
}

function validateHexKey(key, length) {
  if (!key.match(/^[0-9a-fA-F]+$/)) {
    return false;
  }
  return key.length === length * 2;
}

function validateXRPAmount(amount) {
  const num = Number(amount);
  return !isNaN(num) && num > 0 && num <= 100000000000;
}

function validateDestinationAddress(address) {
  return address.match(/^r[1-9A-HJ-NP-Za-km-z]{25,34}$/);
}

async function main() {
  console.log('XRP Transfer Tool\n');
  
  // Initialize variables from command line arguments
  let publicKey = commandLineArgs.publicKey;
  let privateKey = commandLineArgs.privateKey;
  let destination = commandLineArgs.destination;
  let amount = commandLineArgs.amount;
  let networkOption = commandLineArgs.network;
  
  // Determine network URL
  let useMainNet = false;
  let rpcUrl = TESTNET_URL;
  
  if (networkOption) {
    if (networkOption === 'mainnet') {
      useMainNet = true;
      rpcUrl = MAINNET_URL;
      console.log('Using mainnet network');
    } else if (networkOption === 'testnet') {
      useMainNet = false;
      rpcUrl = TESTNET_URL;
      console.log('Using testnet network');
    } else {
      console.error(`Invalid network: ${networkOption}. Must be either 'mainnet' or 'testnet'`);
      process.exit(1);
    }
  } else {
    // If network not provided, prompt for it
    console.log(EXIT_MESSAGE);
    useMainNet = readlineSync.keyInYNStrict('Would you like to use mainnet? (No for testnet)');
    rpcUrl = !useMainNet ? TESTNET_URL : MAINNET_URL;
    console.log(`Using ${useMainNet ? 'mainnet' : 'testnet'} network`);
  }

  // If public key and private key not provided, prompt for them
  if (!publicKey || !privateKey) {
    console.log('\nPlease enter your EdDSA keypair from the DR tool (64 bytes each, in hexadecimal):');
  }
  
  // Get and validate public key if not provided
  if (!publicKey) {
    do {
      publicKey = readlineSync.question('Public Key (64 hex chars): ');
      if (publicKey === EXIT_KEYWORD) {
        console.log('Exiting program...');
        process.exit(0);
      }
      if (!validateHexKey(publicKey, 32)) {
        console.log('Invalid public key format. Must be 64 hexadecimal characters.');
      }
    } while (!validateHexKey(publicKey, 32));
  } else if (!validateHexKey(publicKey, 32)) {
    console.error('Invalid public key format. Must be 64 hexadecimal characters.');
    process.exit(1);
  }

  // Get and validate private key if not provided
  if (!privateKey) {
    do {
      privateKey = readlineSync.question('Private Key (64 hex chars): ', {
        hideEchoBack: true
      });
      if (privateKey === EXIT_KEYWORD) {
        console.log('Exiting program...');
        process.exit(0);
      }
      if (!validateHexKey(privateKey, 32)) {
        console.log('Invalid private key format. Must be 64 hexadecimal characters.');
      }
    } while (!validateHexKey(privateKey, 32));
  } else if (!validateHexKey(privateKey, 32)) {
    console.error('Invalid private key format. Must be 64 hexadecimal characters.');
    process.exit(1);
  }

  // Create wallet from keys
  const wallet = new Wallet('ed' + publicKey, 'ed' + privateKey);
  console.log(`\nWallet address: ${wallet.address}`);

  // Check balance if requested or prompt if in interactive mode
  let xrpBalance;
  if (commandLineArgs.checkBalance) {
    try {
      const client = new Client(rpcUrl);
      await client.connect();

      const accountInfo = await client.request({
        command: 'account_info',
        account: wallet.address,
        ledger_index: 'validated'
      });

      xrpBalance = Number(accountInfo.result.account_data.Balance) / 1000000;
      console.log(`Balance: ${xrpBalance} XRP`);

      await client.disconnect();
    } catch (error) {
      console.error('Error fetching balance:', error.message);
      console.log('Continuing in offline mode...');
    }
  } else if (!commandLineArgs.destination || !commandLineArgs.amount) {
    // Only prompt for balance check if in interactive mode
    const checkBalance = readlineSync.keyInYNStrict('\nWould you like to check the wallet balance? (requires network connection)');
    if (checkBalance) {
      try {
        const client = new Client(rpcUrl);
        await client.connect();

        const accountInfo = await client.request({
          command: 'account_info',
          account: wallet.address,
          ledger_index: 'validated'
        });

        xrpBalance = Number(accountInfo.result.account_data.Balance) / 1000000;
        console.log(`Balance: ${xrpBalance} XRP`);

        await client.disconnect();
      } catch (error) {
        console.error('Error fetching balance:', error.message);
        console.log('Continuing in offline mode...');
      }
    }
  }

  // Ask if user wants to transfer XRP if in interactive mode
  if (!destination && !amount) {
    const wantToTransfer = readlineSync.keyInYNStrict('\nWould you like to transfer XRP?');
    if (!wantToTransfer) {
      console.log('Exiting...');
      process.exit(0);
    }
  }

  // Get and validate destination address if not provided
  if (!destination) {
    do {
      destination = readlineSync.question('\nEnter destination address: ');
      if (destination === EXIT_KEYWORD) {
        console.log('Exiting program...');
        process.exit(0);
      }
      if (!validateDestinationAddress(destination)) {
        console.log('Invalid destination address format. Must be a valid XRPL address starting with "r".');
      }
    } while (!validateDestinationAddress(destination));
  } else if (!validateDestinationAddress(destination)) {
    console.error('Invalid destination address format. Must be a valid XRPL address starting with "r".');
    process.exit(1);
  }

  // Get and validate amount if not provided
  if (!amount) {
    do {
      amount = readlineSync.question('\nEnter amount of XRP to send: ');
      if (amount === EXIT_KEYWORD) {
        console.log('Exiting program...');
        process.exit(0);
      }
      if (!validateXRPAmount(amount)) {
        console.log('Invalid amount. Must be a positive number less than 100 billion XRP.');
      } else if (xrpBalance !== undefined && Number(amount) > xrpBalance) {
        console.log('Amount exceeds available balance.');
        continue;
      }
      break;
    } while (true);
  } else if (!validateXRPAmount(amount)) {
    console.error('Invalid amount. Must be a positive number less than 100 billion XRP.');
    process.exit(1);
  } else if (xrpBalance !== undefined && Number(amount) > xrpBalance) {
    console.error('Amount exceeds available balance.');
    process.exit(1);
  }

  // Display transaction details
  console.log('\nTransaction Details:');
  console.log(`From: ${wallet.address}`);
  console.log(`To: ${destination}`);
  console.log(`Amount: ${amount} XRP`);
  console.log(`Network: ${useMainNet ? 'mainnet' : 'testnet'}`);
  
  // Confirm transaction if not auto-broadcasting and not auto-confirming
  if (!commandLineArgs.broadcast && !commandLineArgs.confirm) {
    const confirmTransaction = readlineSync.keyInYNStrict('\nConfirm transaction?');
    if (!confirmTransaction) {
      console.log('Transaction cancelled.');
      return;
    }
  }

  console.log('\nConnecting to the XRP Ledger to prepare transaction. Please ensure you have network connectivity.');
  try {
    const client = new Client(rpcUrl);
    await client.connect();

    // Prepare transaction
    const tx = await client.autofill({
      TransactionType: 'Payment',
      Account: wallet.address,
      Destination: destination,
      Amount: xrpToDrops(amount),
    }) as Transaction;
    tx.SigningPubKey = wallet.publicKey;
    if (tx.LastLedgerSequence) {
      //** Adds 15 minutes worth of ledgers (assuming 4 ledgers per second) to the existing LastLedgerSequence value. */
      tx.LastLedgerSequence = tx.LastLedgerSequence + 15 * 60 * 4;
    }

    // Sign transaction
    const preImageHex = encodeForSigning(tx);
    console.log('Transaction Pre-image:', encodeForSigning(tx));

    const { signature } = await signWithScalar(preImageHex, privateKey);
    tx.TxnSignature = signature;
    console.log('Transaction Details:', tx);

    const encodedTxHex = encode(tx);
    const signedTxHash = hashSignedTx(encodedTxHex);
    console.log('\nSigned transaction hex:');
    console.log(encodedTxHex);

    if (!verifySignature(encodedTxHex, tx.SigningPubKey)) throw new Error('Signature verification failed');

    // Broadcast transaction if requested or if --confirm flag is set
    const wantToBroadcast = commandLineArgs.broadcast || commandLineArgs.confirm || readlineSync.keyInYNStrict('\nWould you like to broadcast this transaction now?');

    if (wantToBroadcast) {
      console.log('\nBroadcasting transaction...');
      const submit = await client.submit(encodedTxHex);
      console.log(`Initial status: ${submit.result.engine_result_message}`);

      if (submit.result.engine_result.includes('SUCCESS')) {
        console.log('\nWaiting for validation...');
        const txResponse = await client.request({
          command: 'tx',
          transaction: signedTxHash,
          binary: false
        });

        if (txResponse.result.validated) {
          console.log('\nTransaction validated!');
          console.log(`Transaction hash: ${signedTxHash}`);
        } else {
          console.log('\nTransaction not yet validated. You can check status later with hash:');
          console.log(signedTxHash);
        }
      } else {
        console.log('\nTransaction failed to submit.');
        console.log(`Error: ${submit.result.engine_result_message}`);
      }
    } else {
      console.log('\nTo broadcast this transaction later:');
      console.log('1. Use the XRPL CLI tool: xrpl submit <tx_blob>');
      console.log('2. Or use any XRPL node\'s RPC interface with the submit method');
    }

    await client.disconnect();
  } catch (error) {
    console.error('Error:', error.data?.error_exception || error.message);
    console.log('Please ensure you have network connectivity to prepare and broadcast the transaction.');
    process.exit(1);
  }
}

main().catch(console.error);

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
