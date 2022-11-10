TSS Recovery Tool
=================

This tool is intended to recover the private key of TSS vaults, by
'combining' the secrets of each TSS app backup file.

If you pass `export` and `password` it will generate a keystore file.

## Compiling

Compile for current arch:
```
$ make build
```

Compile for Windows:
```
$ make build-win
```

The resulting executable will be in the `bin/` folder.

## Usage

First you will want to get the vault IDs available in the files:
```
$ ./bin/recovery-tool sandbox/file1.bin sandbox/file2.bin
```

Once you have the vault-ids, supply it to the tool to begin the recovery.
```
$ ./bin/recovery-tool --vault-id cl347wz8w00006sx3f1g23p4s sandbox/file1.bin sandbox/file2.bin
```

### Bitcoin Recovery

The private key that is exported by the tool must be converted to WIF format.

This needs Node.js, then just run the `node` tool to start up the REPL, then use these commands.

```
// private key string looks like: 76f004b19d4ed2d2cfbf5560380276580a1a622cfef0d893b1ade4f23082d6af
// paste it in the placeholder below
> const skHex = '*** PASTE YOUR PRIVATE KEY HEX STRING HERE ***';
> sk = new Buffer(skHex, 'hex')
> wif = require('wif')
// use 239 for testnet, or 128 for mainnet
> wif.encode(239, sk, true)
```

A WIF is produced like: L1CujRNEhNfZgTS9b6e3hytTDu7gpUv1kiLx4ETEEhEc8nJcx4QA

Then download Electrum wallet, and follow the steps to import a WIF.

![Screenshot 2022-11-10 at 23 01 51](https://user-images.githubusercontent.com/1255926/201128017-98226fa6-4729-4581-b4a8-d612d7f37b81.png)

![Screenshot 2022-11-10 at 23 02 00](https://user-images.githubusercontent.com/1255926/201128076-712df60e-bb51-4274-bc26-3f925035bf45.png)

Prefix the WIF string with with `p2wpkh:`, then paste it into the box.

![Screenshot 2022-11-10 at 23 05 03](https://user-images.githubusercontent.com/1255926/201129826-03da8a86-aa1d-4615-a5d0-c31c49818629.png)

Create a password for the wallet.

![Screenshot 2022-11-10 at 23 07 22](https://user-images.githubusercontent.com/1255926/201131143-97039c52-3bff-4ada-9dfb-f8b176db580d.png)

Electrum should now show your balances, and the private key is recovered.
