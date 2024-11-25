# TSS Recovery Tool

This tool recovers the private keys of vaults by
'combining' the secrets of each TSS app backup file.

It exports a WIF for Bitcoin key import to Electrum Wallet.

It will also create a wallet V3 file for importing to MetaMask and other Ethereum wallets.

> ### **Important Notice**
>
> This tool does not do ANY communication with any external host or service. It does not need an Internet connection at all.
>
> It is recommended that you run it on a non internet connected ("air gapped") device such as a laptop not connected to any network.

## Build from Source

You can build the code from source. Clone the repo, and make sure the latest [Go](http://go.dev) is installed.

Compile from source:

```
$ make
```

Compile for Windows, Linux (x86) or Mac (Apple Silicon):

```
$ make build-win
$ make build-linux
$ make build-mac
```

The resulting executable(s) will be in the `bin/` folder.

## Download a Binary

If you prefer the convenience of downloading a pre-built binary for your platform, head to the [Releases area](https://github.com/IoFinnet/io-vault-disaster-recovery-cli/releases). We have pre-built binaries for Linux, Windows and Mac.

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

> **IMPORTANT:** If you intend to recover a **testnet** key (address with `tb1` prefix), you must run Electrum with the `--testnet` flag from your Terminal:
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

### Others (XRPL, SOL, TON, TAO, etc.)

Use the EdDSA key output for these chains that use EdDSA (Edwards / Ed25519) keys.
