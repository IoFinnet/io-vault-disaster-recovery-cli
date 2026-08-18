# gen_mlkem768.sh script

This script creates a ML-KEM-768 key pair. This key pair can be used for the Virtual Signer Disaster Recovery feature.

On Windows, use [`scripts/windows/gen_mlkem768.ps1`](../windows/gen_mlkem768.ps1) instead — it
produces identical output.

## Requirements

**OpenSSL 3.5.0 or later.** ML-KEM support was added in OpenSSL 3.5, and the `-provparam` flag the
script relies on does not exist in earlier releases. Check your build with `openssl version`. The
script probes for ML-KEM-768 support up front and stops with a clear message rather than letting
OpenSSL fail opaquely.

## Usage

```
 Usage:
   ./gen_mlkem768.sh [basename]

 Produces:
   <basename>_priv.pem   (private key, PKCS#8 PEM, RFC 9935 minimal
                          "bare-seed" form: just the 64-byte FIPS 203
                          seed, no OpenSSL-specific CHOICE wrapper)
   <basename>_pub.pem    (public key, PEM, SubjectPublicKeyInfo, raw
                           FIPS 203 "ek" bytes)
```

## Key handling

`<basename>_pub.pem` is configured on the separate Virtual Signer service, which uses it to encrypt `.dr` disaster-recovery files. `<basename>_priv.pem` stays with whoever performs recovery: pass its path to this repo's recovery tool via `-private-key` to decrypt those `.dr` files (see the main [README](../../README.md#usage)).

The script writes the private key with mode 600. It decrypts every `.dr` file the paired Virtual
Signer has ever written, so keep it offline and backed up. `*.pem` is gitignored in this repo so a
key cannot be committed by accident.
