# gen_mlkem768.ps1 script

Windows equivalent of [`scripts/posix/gen_mlkem768.sh`](../posix/gen_mlkem768.sh). It creates an
ML-KEM-768 key pair for the Virtual Signer Disaster Recovery feature, producing the same two files
in the same formats — a key pair generated on Windows is interchangeable with one generated on
POSIX.

## Requirements

**OpenSSL 3.5.0 or later.** ML-KEM support was added in OpenSSL 3.5, and the `-provparam` flag the
script relies on does not exist in earlier releases. Check your build with:

```powershell
openssl version
```

The `openssl` bundled with Git for Windows is frequently older than 3.5. If the script's capability
probe fails, install a current OpenSSL and make sure it comes before Git's copy in `PATH`. The
script probes for ML-KEM-768 support up front and stops with a clear message rather than letting
OpenSSL fail opaquely.

## Usage

```powershell
 .\gen_mlkem768.ps1 [basename]

 Produces:
   <basename>_priv.pem   (private key, PKCS#8 PEM, RFC 9935 minimal
                          "bare-seed" form: just the 64-byte FIPS 203
                          seed, no OpenSSL-specific CHOICE wrapper)
   <basename>_pub.pem    (public key, PEM, SubjectPublicKeyInfo, raw
                          FIPS 203 "ek" bytes)
```

Default basename is `mlkem768`. The script refuses to overwrite existing output files.

If PowerShell blocks the script under its execution policy, run it for the current session only:

```powershell
powershell -ExecutionPolicy Bypass -File .\gen_mlkem768.ps1
```

## Key handling

`<basename>_pub.pem` is configured on the separate Virtual Signer service, which uses it to encrypt
`.dr` disaster-recovery files. `<basename>_priv.pem` stays with whoever performs recovery: pass its
path to this repo's recovery tool via `-private-key` to decrypt those `.dr` files (see the main
[README](../../README.md#usage)).

The script restricts the private key's ACL to the account that ran it — disabling inheritance and
removing every inherited entry, the Windows counterpart of `chmod 600`. If that step fails (it can
on non-NTFS volumes or in some container images) the script warns loudly and reports
`DEFAULT ACL - SECURE THIS FILE MANUALLY` in its summary; secure the file before using it. The
private key decrypts every `.dr` file the paired Virtual Signer has ever written, so keep it offline
and backed up. `*.pem` is gitignored in this repo so a key cannot be committed by accident.
