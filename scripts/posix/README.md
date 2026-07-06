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

Add the `<basename>_pub.pem` file path to the `DRPKPEMFile` configuration.