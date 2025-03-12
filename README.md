# io.finnet Key Recovery Tool for io.vault
![Screenshot](https://github.com/user-attachments/assets/d1ab307a-6059-44d1-828a-be27d0fb9944)

This terminal app recovers the private keys of vaults by combining the shares of each TSS app backup file.

It exports a WIF for Bitcoin key import to Electrum Wallet. It will also create a wallet V3 file for importing to MetaMask, Phantom and other Ethereum wallets.

For other coins and wallets, please see the specific recovery information below or on our [guides page](https://docs.iofinnet.com/docs/disaster-recovery).
You may be required to run another script contained in the [scripts](./scripts) area of this repository.

> [!IMPORTANT]
> This app does not do ANY communication with any external host or service. It does not need an Internet connection at all.
> 
> It is recommended that you run it on a non internet connected ("air gapped") device such as a laptop not connected to any network.
>
> The web interface and transaction tools are designed with a security-first approach:
> - All processing happens locally in your browser or terminal
> - Command-line scripts run transaction operations offline
> - Balance checking can be done using only public addresses
> - Two-step transaction process allows you to disconnect from the internet before executing transactions

## Build from Source

You can build the code from source. Clone the repo, and make sure the latest [Go](http://go.dev) is installed.

Compile from source:

```
$ make
```

Compile individually for Windows, Linux (x86) or Mac (Apple Silicon):

```
$ make build-win
$ make build-linux
$ make build-mac
```

The resulting executable(s) will be in the `bin/` folder. If you are on Mac or Linux, you may have to run `chmod +x bin/*` on the file and accept any security warnings via system settings due to this being an unsigned release. Windows may display a security warning too.

## Download a Binary

If you prefer the convenience of downloading a pre-built binary for your platform, head to the [Releases area](https://github.com/IoFinnet/io-vault-disaster-recovery-cli/releases). We have pre-built binaries for Linux, Windows and Mac.

If you are on Mac or Linux, you may have to run `chmod +x bin/*` on the file and accept any security warnings via system settings due to these being unsigned releases. Windows may display a security warning too.

## Usage

Run the recovery tool.

```
$ ./bin/recovery-tool sandbox/file1.json sandbox/file2.json
```

You can also provide the vault ID you want to recover, this will skip the step of choosing a vault.

```
$ ./bin/recovery-tool -vault-id cl347wz8w00006sx3f1g23p4s sandbox/file1.bin sandbox/file2.bin
```

The tool will try to auto-detect the optimal "reshare nonce" and "threshold/quroum" of the vault you are trying to recover.
However, if you would like to override this behavior, you may specify custom values with `-nonce` and `-threshold` flags respectively.

### Ethereum & Ethereum-Like Recovery

The tool is able to export a wallet v3 JSON file for import into MetaMask. Set the `-password` flag on the command line to export the `wallet.json`, and make sure it's saved somewhere safe.

To import it, open your MetaMask and add an account, then choose the import from file option.

![MetaMask Screenshot](https://github.com/IoFinnet/io-vault-disaster-recovery-cli/assets/1255926/c7be2913-5f63-4bec-b5ff-09c0559d05b3)

### Bitcoin Recovery

The tool exports two WIFs for import into the Electrum Bitcoin wallet: one for mainnet (`bc1` address), and another for testnet (`tb1` address).
Choose the one depending on your vault's environment.

A WIF looks like: L1CujRNEhNfZgTS9b6e3hytTDu7gpUv1kiLx4ETEEhEc8nJcx4QA

You may download Electrum wallet, and follow these steps to import a WIF:

> [!IMPORTANT]
> If you intend to recover a **testnet** key (address with `tb1` prefix), you must run Electrum with the `--testnet` flag from your Terminal:
> On a Mac, this is done as follows:
> `open -n /Applications/Electrum.app --args --testnet`

![Screenshot 2022-11-10 at 23 01 51](https://user-images.githubusercontent.com/1255926/201128017-98226fa6-4729-4581-b4a8-d612d7f37b81.png)

![Screenshot 2022-11-10 at 23 02 00](https://user-images.githubusercontent.com/1255926/201128076-712df60e-bb51-4274-bc26-3f925035bf45.png)

Prefix the WIF string with with `p2wpkh:`, then paste it into the box.

![Screenshot 2022-11-10 at 23 05 03](https://user-images.githubusercontent.com/1255926/201129826-03da8a86-aa1d-4615-a5d0-c31c49818629.png)

Create a password for the wallet.

![Screenshot 2022-11-10 at 23 07 22](https://user-images.githubusercontent.com/1255926/201131143-97039c52-3bff-4ada-9dfb-f8b176db580d.png)

After syncing up the chain (may take a while), Electrum should show your balances, and the private key is recovered.

### Tron Recovery

Please use [TronLink](https://www.tronlink.org) to recover Tron and Tron assets. [Follow this guide](https://support.tronlink.org/hc/en-us/articles/5982285631769-How-to-Import-Your-Account-in-TronLink-Wallet-Extension) and import your vault's private key output by the tool.

## Web Interface

The recovery tool includes a web-based interface that provides a more user-friendly way to work with your recovered keys and blockchain assets. The web interface runs locally in your browser and requires no internet connection.

To use the web interface, run the recovery tool and navigate to the provided local URL (typically http://localhost:8080):

```
$ ./bin/recovery-tool -web
Starting web server on http://localhost:8080
```

The web interface provides:

1. Step-by-step instructions for vault recovery
2. Balance checking functionality for XRP, Solana, and Bittensor networks
3. Command generation for secure transactions
4. Address validation and key management

### Checking Balances

For security, you can check balances using just the public address without exposing your private key:

```
# XRP balance check
scripts/xrpl-tool/npm start -- --address rXXXYourAddressXXX --check-balance --network mainnet

# Solana balance check
scripts/solana-tool/npm start -- --address XXXYourAddressXXX --check-balance --network mainnet

# Bittensor balance check
scripts/bittensor-tool/npm start -- --address XXXYourAddressXXX --check-balance --network mainnet
```

### Transaction Security

For transaction operations, the tool generates commands for you to run in your terminal. This approach provides several security benefits:

1. Private keys never leave your local machine
2. Transaction details are transparent and visible before signing
3. You can run the transaction steps in a completely offline environment until the point of broadcasting the transaction to the chain

### XRP Ledger Recovery & Transactions

We use a specific key format for XRPL. You can use the web interface to generate the appropriate commands, or directly use the XRPL tool:

```
# Check balance
cd scripts/xrpl-tool && npm install
npm start -- --address rXXXYourAddressXXX --check-balance --network mainnet

# Create transaction
npm start -- --private-key YourPrivateKey --public-key YourPublicKey --destination rXXX... --amount 10 --network mainnet
```

### TAO (Bittensor) Recovery & Transactions

For Bittensor, the web interface will provide commands, or you can use the Bittensor tool directly:

```
# Check balance
cd scripts/bittensor-tool && npm install
npm start -- --address XXXYourAddressXXX --check-balance --network mainnet

# Create transaction
npm start -- --private-key YourPrivateKey --destination XXX... --amount 10 --network mainnet
```

You can also use the [Bittensor Wallet](https://bittensor.com/wallet) on mobile to recover TAO assets.

### Solana Recovery & Transactions

For Solana (SOL) recovery and transactions:

```
# Check balance
cd scripts/solana-tool && npm install
npm start -- --address XXXYourAddressXXX --check-balance --network mainnet

# Create transaction
npm start -- --private-key YourPrivateKey --destination XXX... --amount 10 --network mainnet
```

### Others (TON, ATOM, etc.)

Use the EdDSA key output for these chains that use EdDSA (Edwards / Ed25519) keys.
