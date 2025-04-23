# io.finnet Key Recovery Tool for io.vault
![Screenshot](https://github.com/user-attachments/assets/d1ab307a-6059-44d1-828a-be27d0fb9944)

This offline terminal app recovers the private keys of vaults by combining the shares of each io.finnet app backup file.

It exports a WIF for Bitcoin key import to Electrum and will also create a wallet V3 file for importing to MetaMask, Phantom and other Ethereum wallets.

For other coins and wallets, please see the specific recovery information below or on our [guides page](https://docs.iofinnet.com/docs/disaster-recovery).
You may be required to run another script located in the [scripts](./scripts) area of this repository.

> [!IMPORTANT]
> This app does not do ANY communication with any external host or service. It does not need an Internet connection at all.
>
> It is recommended that you run it on a non internet connected ("air gapped") device such as a laptop not connected to any network.
>
> The browser UI and transaction tools are designed with a security-first approach:
> - All processing happens locally in your browser or terminal
> - Command-line scripts run transaction operations offline
> - Balance checking can be done using only public addresses
> - Two-step transaction process allows you to disconnect from the internet before executing transactions

## Build from Source

You can build the code from source. Clone the repo, and make sure the latest [Go](http://go.dev) is installed.

Compile from source:
```bash
make
```

Compile individually for Windows, Mac (Apple Silicon), Linux (x86-64 or ARM64), or FreeBSD (x86-64 or ARM64):
```bash
make build-win
make build-mac
make build-linux-amd64    # for x86-64 Linux
make build-linux-arm64    # for ARM64 Linux
make build-linux          # builds both Linux variants
make build-freebsd-amd64  # for x86-64 FreeBSD
make build-freebsd-arm64  # for ARM64 FreeBSD
make build-freebsd        # builds both FreeBSD variants
```

The resulting executable(s) will be in the `bin/` folder. Windows may display a security warning when running the executable.

## Download a Binary

If you prefer the convenience of downloading a pre-built binary for your platform, head to the [Releases area](https://github.com/IoFinnet/io-vault-disaster-recovery-cli/releases). We have pre-built binaries for:

- **Linux**: x86-64 (amd64) and ARM64 (aarch64)
- **FreeBSD**: x86-64 (amd64) and ARM64 (aarch64)
- **Windows**: x86-64 (amd64)
- **Mac**: ARM64 (Apple Silicon)

All binaries are compressed in versioned `.tar.gz` archives with maximum compression to reduce download size (approximately 50% smaller). The binaries in these archives already have executable permissions set, so no additional `chmod` commands are needed after extraction.

After downloading, extract the binary with:
```bash
tar -xzf recovery-tool-*.tar.gz
```
> [!NOTE]
> On Windows, you should run tar from Command Prompt.

### Security Popups

There are some extra steps to acknowledge security warnings depending on your platform:

#### macOS

Run the following command before you run the tool to remove quarantine attributes:
```bash
xattr -dr com.apple.quarantine recovery-tool*
```

#### Windows

Windows may display a security warning too. Just select "Run anyway" to run it when you see this popup at the next step.

![image](https://github.com/user-attachments/assets/cf010a48-6a2e-462e-99fc-bf916371356d)

You could also do this another way by:

1. Right-clicking the file
2. Selecting Properties
3. At the bottom of the General tab, looking for a "Security" section with "This file came from another computer" message
4. Checking "Unblock" and clicking OK

Alternatively, you may run this command in PowerShell to unblock the file.
```powershell
Unblock-File -Path "recovery-tool.exe"
```

## Usage

Run the recovery tool with your backup JSON files or ZIP archives containing JSON files.
``` bash
./recovery-tool-mac sandbox/file1.json sandbox/file2.json
```

You can also use ZIP archives that contain multiple JSON files:
```bash
./recovery-tool-mac sandbox/backup.zip
```

> [!NOTE]
> When using ZIP files, ensure they contain only a flat hierarchy of JSON files with no nested directories.
> Each ZIP file will be treated as a batch of JSON files, all using the same mnemonic phrase.

You can also provide the vault ID you want to recover, which will skip the step of choosing a vault:
```bash
./recovery-tool-mac -vault-id cl347wz8w00006sx3f1g23p4s sandbox/file1.json sandbox/file2.json
```

Mix and match JSON files and ZIP archives as needed:
```bash
./recovery-tool-mac sandbox/file1.json sandbox/backups.zip sandbox/file3.json
```

Replace `mac` with one of the following depending on your computer's OS and architecture:
- `linux-amd64` - For Linux on x86-64 processors
- `linux-arm64` - For Linux on ARM64 processors (e.g., Raspberry Pi 4, AWS Graviton)
- `freebsd-amd64` - For FreeBSD on x86-64 processors
- `freebsd-arm64` - For FreeBSD on ARM64 processors
- `.exe` - For Windows (just use `recovery-tool.exe`)

> [!NOTE]
> The tool will try to auto-detect the optimal "reshare nonce" and "threshold/quroum" of the vault you are trying to recover.
> However, if you would like to override this behavior, you may specify custom values with `-nonce` and `-threshold` flags respectively.

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

## Browser UI

The recovery tool includes a web-based interface that provides a more user-friendly way to work with your recovered keys and blockchain assets. The browser UI runs locally in your browser and requires no internet connection.

To use the browser UI, run the recovery tool and navigate to the provided local URL (typically http://localhost:8080):

```
$ ./bin/recovery-tool -web
Starting http server on http://localhost:8080
```

The browser UI provides:

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

We use a specific key format for XRPL. You can use the browser UI to generate the appropriate commands, or directly use the XRPL tool:

```
# Check balance
cd scripts/xrpl-tool && npm install
npm start -- --address rXXXYourAddressXXX --check-balance --network mainnet

# Create transaction
npm start -- --private-key YourPrivateKey --public-key YourPublicKey --destination rXXX... --amount 10 --network mainnet
```

### TAO (Bittensor) Recovery & Transactions

For Bittensor, the browser UI will provide commands, or you can use the Bittensor tool directly:

```
# Check balance
cd scripts/bittensor-tool && npm install
npm start -- --address XXXYourAddressXXX --check-balance --network mainnet

# Create transaction
npm start -- --private-key YourPrivateKey --destination XXX... --amount 10 --network mainnet
```

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
