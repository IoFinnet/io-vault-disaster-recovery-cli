# io.finnet Key Recovery Tool for io.vault
[![AGPL-3.0 License][1]][2] [![Go Report Card][5]][6]

![Screenshot](https://github.com/user-attachments/assets/d1ab307a-6059-44d1-828a-be27d0fb9944)

[1]: https://img.shields.io/github/license/iofinnet/io-vault-disaster-recovery-cli
[2]: LICENSE
[5]: https://goreportcard.com/badge/github.com/iofinnet/io-vault-disaster-recovery-cli
[6]: https://goreportcard.com/report/github.com/iofinnet/io-vault-disaster-recovery-cli

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

Run the recovery tool with your backup JSON files, .dr files or ZIP archives containing JSON files or .dr files.
``` bash
./recovery-tool-mac sandbox/file1.json sandbox/file2.json
```

.dr files are files created by Virtual Signers. When referencing .dr files with the recovery tool, provide the path to the private key used by the Virtual Signer for Disaster Recovery files. This is the private part of the public/private ML-KEM-768 key pair
created as the initial step of the Disaster Recovery process.

This project ships sample scripts that call `openssl` to generate that key pair:

| Platform | Script |
| --- | --- |
| macOS / Linux | [`scripts/posix/gen_mlkem768.sh`](scripts/posix/gen_mlkem768.sh) ([docs](scripts/posix/README.md)) |
| Windows | [`scripts/windows/gen_mlkem768.ps1`](scripts/windows/gen_mlkem768.ps1) ([docs](scripts/windows/README.md)) |

Both produce identical output, so a key pair generated on one platform works on the others.

> [!IMPORTANT]
> Key generation requires **OpenSSL 3.5.0 or later** — ML-KEM support was added in OpenSSL 3.5.
> Check with `openssl version`. Both scripts probe for ML-KEM-768 support before generating and
> stop with a clear message if the build is too old. On Windows in particular, the `openssl`
> bundled with Git for Windows is frequently older than 3.5. This requirement applies only to
> generating keys; the recovery tool itself has no OpenSSL dependency.

The private key decrypts every `.dr` file the paired Virtual Signer has ever written — keep it
offline and backed up. `*.pem` is gitignored in this repo so a key cannot be committed by accident.

``` bash
./recovery-tool-mac -private-key sandbox/mlkem768_priv.pem sandbox/file1.json sandbox/019f2838-e9ab-7e0c-8a45-cf8a3ae18e8e.ecdsa.secp256k1.dr sandbox/019f2838-e9ab-7e0c-8a45-cf8a3ae18e8e.eddsa.ed25519.dr
```

You can also use ZIP archives that contain multiple JSON/dr files:
```bash
./recovery-tool-mac sandbox/backup.zip
```

> [!NOTE]
> When using ZIP files, ensure they contain only a flat hierarchy of JSON or .dr files with no nested directories.
> Each ZIP file will be treated as a batch of JSON or .dr files. All JSON must use the same mnemonic phrase and the .dr files must belong to the same vault.

You can also provide the vault ID you want to recover, which will skip the step of choosing a vault:
```bash
./recovery-tool-mac -vault-id "019f2838-e9ab-7e0c-8a45-cf89a63d9169"  -private-key sandbox/mlkem768_priv.pem sandbox/file1.json sandbox/019f2838-e9ab-7e0c-8a45-cf8a3ae18e8e.ecdsa.secp256k1.dr sandbox/019f2838-e9ab-7e0c-8a45-cf8a3ae18e8e.eddsa.ed25519.dr
```

Use multiple ZIP archives:
```bash
./recovery-tool-mac sandbox/backups1.zip sandbox/backups2.zip sandbox/backups3.zip
```

Note: You cannot mix JSON and ZIP files, or .dr and ZIP files in the same command.

Replace `mac` with one of the following depending on your computer's OS and architecture:
- `linux-amd64` - For Linux on x86-64 processors
- `linux-arm64` - For Linux on ARM64 processors (e.g., Raspberry Pi 4, AWS Graviton)
- `freebsd-amd64` - For FreeBSD on x86-64 processors
- `freebsd-arm64` - For FreeBSD on ARM64 processors
- `.exe` - For Windows (just use `recovery-tool.exe`)

> [!NOTE]
> The tool will try to auto-detect the optimal "reshare nonce" and "threshold/quroum" of the vault you are trying to recover.
> However, if you would like to override this behavior, you may specify custom values with `-nonce` and `-threshold` flags respectively.

### .dr file format and version compatibility

Each `.dr` file is a JSON envelope wrapping the encrypted share payload. Alongside the vault and
request metadata, Virtual Signer stamps two fields describing how the payload was produced:

| Field | Current value | Meaning |
| --- | --- | --- |
| `formatVersion` | `1` | Revision of the envelope structure itself |
| `kemSuite` | `ML-KEM-768+AES-256-GCM` | Key encapsulation mechanism and AEAD used for `dataB64` |

The recovery tool checks both **before** attempting decryption. If a file was produced by a newer
Virtual Signer using a suite this build does not implement, you get an explicit message naming the
suite:

```
.dr file declares KEM suite "ML-KEM-1024+AES-256-GCM", but this recovery tool only supports
"ML-KEM-768+AES-256-GCM"; use a recovery tool build matching the Virtual Signer that produced this file
```

rather than a misleading `wrong private key or corrupted file` error. If you see this, you need a
newer recovery tool build — not a different key.

Older `.dr` files written before these fields existed omit them entirely and remain fully
supported; they are read as `formatVersion: 1` with the `ML-KEM-768+AES-256-GCM` suite, which is
the only suite Virtual Signer has ever produced.

> [!NOTE]
> These envelope fields are outside the AES-GCM authentication tag and are therefore
> unauthenticated. They are a compatibility and diagnostic aid — a tampered value can only cause
> the tool to refuse to decrypt, never to decrypt incorrectly. Anything security-relevant (vault
> ID, threshold) is taken from the authenticated payload after decryption.

## Browser UI

The recovery tool includes a browser UI that provides a more user-friendly way to work with your recovered keys and blockchain assets. The browser UI runs locally in your browser and requires no internet connection.

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

## Key Recovery

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

## Scripts for Other Chains

Some other chains require the use of a node.js script which we have included.

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

## HD Address Recovery

The recovery tool supports deriving child keys from recovered master keys using BIP32-style hierarchical deterministic (HD) derivation. This is useful when your vault has multiple derived addresses (e.g., multiple Ethereum accounts, Bitcoin addresses, etc.).

### HD Addresses CSV

The HD addresses CSV file contains information about derived addresses that need their private keys recovered. This file can be exported through:

- **io.finnet API** - Available now for programmatic access
- **io.vault Dashboard** - Coming soon through the web interface

#### CSV Format

The CSV file must contain the following columns:

| Column | Description |
|--------|-------------|
| `address` | A label/identifier for the address |
| `xpub` | The extended public key (xpub) encoding the master public key and chain code |
| `path` | BIP32 derivation path (e.g., `m/44/60/0/0/0` for Ethereum, `m/0` for master key) |
| `algorithm` | Signing algorithm: `ECDSA`, `EDDSA`, or `SCHNORR` |
| `curve` | Elliptic curve: `secp256k1`, `P-256`, or `Edwards25519` |
| `flags` | Reserved for future use (set to `0`) |

Example CSV content:
```csv
address,xpub,path,algorithm,curve,flags
0x...,xpub661MyMwAqRbcF...,m/44/60/0/0/0,ECDSA,secp256k1,0
0x...,xpub661MyMwAqRbcF...,m/44/60/0/0/1,ECDSA,secp256k1,0
0x...,xpub661MyMwAqRbcE...,m/44/144/0/0,EDDSA,Edwards25519,0
bc1...,xpub661MyMwAqRbcF...,m/86/0/0/0/0,SCHNORR,secp256k1,0
```

#### Supported Algorithm/Curve Combinations

| Algorithm | Curve | Use Case |
|-----------|-------|----------|
| ECDSA | secp256k1 | Ethereum, Bitcoin (legacy/segwit), Tron |
| ECDSA | P-256 | Some enterprise applications |
| EDDSA | Edwards25519 | XRP Ledger, Solana, Bittensor |
| SCHNORR | secp256k1 | Bitcoin Taproot |

#### Usage

**CLI Mode:**
```bash
./recovery-tool-mac -addresses-csv hd_addresses.csv file1.json file2.json file3.json
```

**Browser UI Mode:**
Upload the CSV file in the "HD Addresses CSV" field alongside your backup files.

#### Output

The tool generates a `*_recovered.csv` file containing all original columns plus:
- `publickey` - The derived public key (hex-encoded)
- `privatekey` - The derived private key (hex-encoded)

> [!NOTE]
> - Only non-hardened derivation paths are supported (no `'` or `h` suffix)
> - Path `m` returns the master key unchanged (useful for verification)
> - The ECDSA master key is used for both ECDSA and Schnorr derivation
> - The EdDSA master key is used for EdDSA derivation

> [!CAUTION]
> **Input CSV Security**: The input CSV contains extended public keys (xpubs) which allow anyone to view your vault's total balance and transaction history. While it does not contain private keys, you should avoid sharing this file publicly.
>
> **Output CSV Security**: The recovered CSV file contains private keys and must be treated as highly confidential. Only generate this file on an air-gapped machine with no network connection. Never share this file with anyone, ever. Anyone with access to the private keys can steal your funds.
