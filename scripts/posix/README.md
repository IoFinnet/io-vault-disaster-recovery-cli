# gen_mlkem768.sh script

This script creates a ML-KEM-768 key pair. This key pair can be used for the Virtual Signer Disaster Recovery feature.

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

`<basename>_pub.pem` is configured on the separate Virtual Signer service, which uses it to encrypt `.dr` disaster-recovery files. `<basename>_priv.pem` stays with whoever performs recovery: pass its path to this repo's recovery tool via `-private-key` to decrypt those `.dr` files (see the main [README](../../README.md#usage)).