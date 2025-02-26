import { Client, decode, encode, encodeForSigning, Transaction, verifySignature, Wallet, xrpToDrops } from 'xrpl';
import readlineSync from 'readline-sync';
import { webcrypto } from 'crypto';
import * as ed from '@noble/ed25519';
import { bytesToNumberBE, bytesToNumberLE, numberToBytesLE } from '@noble/curves/abstract/utils';
import { hashSignedTx } from 'xrpl/dist/npm/utils/hashes';
import { sha512 } from '@noble/hashes/sha512';

// polyfill for Node.js
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

// Handle CTRL+C gracefully
process.on('SIGINT', () => {
  console.log('\nProcess terminated by user (CTRL+C)');
  process.exit(0);
});

const TESTNET_URL = 'wss://testnet.xrpl-labs.com';
const MAINNET_URL = 'wss://s1.ripple.com';

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

  const useMainNet = readlineSync.keyInYNStrict('Would you like to use mainnet? (No for testnet)');
  const rpcUrl = !useMainNet ? TESTNET_URL : MAINNET_URL;

  console.log('\nPlease enter your EdDSA keypair from the DR tool (64 bytes each, in hexadecimal):');

  let publicKey, privateKey;
  do {
    publicKey = readlineSync.question('Public Key (64 hex chars): ');
    if (!validateHexKey(publicKey, 32)) {
      console.log('Invalid public key format. Must be 64 hexadecimal characters.');
    }
  } while (!validateHexKey(publicKey, 32));

  do {
    privateKey = readlineSync.question('Private Key (64 hex chars): ', {
      hideEchoBack: true
    });
    if (!validateHexKey(privateKey, 32)) {
      console.log('Invalid private key format. Must be 64 hexadecimal characters.');
    }
  } while (!validateHexKey(privateKey, 32));

  const wallet = new Wallet('ed' + publicKey, 'ed' + privateKey);
  console.log(`\nWallet address: ${wallet.address}`);

  const checkBalance = readlineSync.keyInYNStrict('\nWould you like to check the wallet balance? (requires network connection)');

  let xrpBalance;
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

  const wantToTransfer = readlineSync.keyInYNStrict('\nWould you like to transfer XRP?');
  if (!wantToTransfer) {
    console.log('Exiting...');
    return;
  }

  // Get and validate destination address
  let destinationAddress;
  do {
    destinationAddress = readlineSync.question('\nEnter destination address: ');
    if (!validateDestinationAddress(destinationAddress)) {
      console.log('Invalid destination address format. Must be a valid XRPL address starting with "r".');
    }
  } while (!validateDestinationAddress(destinationAddress));

  // Get and validate amount
  let amount;
  do {
    amount = readlineSync.question('\nEnter amount of XRP to send: ');
    if (!validateXRPAmount(amount)) {
      console.log('Invalid amount. Must be a positive number less than 100 billion XRP.');
    } else if (xrpBalance !== undefined && Number(amount) > xrpBalance) {
      console.log('Amount exceeds available balance.');
      continue;
    }
    break;
  } while (true);

  console.log('We must be online to fetch the XRP ledger sequence and fees data. Please ensure you have network connectivity.');
  try {
    const client = new Client(rpcUrl);
    await client.connect();

    // Prepare transaction
    const tx = await client.autofill({
      TransactionType: 'Payment',
      Account: wallet.address,
      Destination: destinationAddress,
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

    const wantToBroadcast = readlineSync.keyInYNStrict('\nWould you like to broadcast this transaction now?');

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
