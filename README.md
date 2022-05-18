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
$ ./bin/recovery-tool sandbox/file1.dat2 sandbox/file2.dat2
```

Once you have the vault-ids, supply it to the tool to begin the recovery.
```
$ ./bin/recovery-tool --vault-id cl347wz8w00006sx3f1g23p4s sandbox/file1.dat2 sandbox/file2.dat2
```

