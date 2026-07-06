#!/bin/sh
#
# gen_mlkem768.sh
#
# Generates a NIST FIPS 203 ML-KEM-768 key pair using OpenSSL and
# writes them to PEM files.
#
# Requirements: OpenSSL 3.5.0 or later (ML-KEM support was added in
# OpenSSL 3.5). Check with: openssl version
#
# Usage:
#   ./gen_mlkem768.sh [basename]
#
# Produces:
#   <basename>_priv.pem   (private key, PKCS#8 PEM, RFC 9935 minimal
#                          "bare-seed" form: just the 64-byte FIPS 203
#                          seed, no OpenSSL-specific CHOICE wrapper)
#   <basename>_pub.pem    (public key, PEM, SubjectPublicKeyInfo, raw
#                          FIPS 203 "ek" bytes)
#
# This "bare-seed" private key form is interoperable with other RFC
# 9935-compliant tooling (e.g. Go's crypto/mlkem package wrapped in a
# standard PKCS#8 structure), unlike OpenSSL's richer default formats
# which embed extra format-selection tagging of their own.
#
# Default basename is "mlkem768" if not given.

set -eu

ALG="ML-KEM-768"
BASENAME="${1:-mlkem768}"
PRIV_KEY="${BASENAME}_priv.pem"
PUB_KEY="${BASENAME}_pub.pem"

# --- Sanity checks -----------------------------------------------------

if ! command -v openssl >/dev/null 2>&1; then
    echo "Error: openssl not found in PATH." >&2
    exit 1
fi

OPENSSL_VERSION_STR=$(openssl version 2>/dev/null || true)
echo "Using: ${OPENSSL_VERSION_STR}"

# Verify this build of OpenSSL actually knows about ML-KEM-768 before
# attempting to use it, so we can give a clear error message instead of
# an opaque OpenSSL failure.
if ! openssl list -key-managers 2>/dev/null | grep -qi 'ML-KEM-768'; then
    echo "Error: this OpenSSL build does not support ${ALG}." >&2
    echo "ML-KEM support requires OpenSSL 3.5.0 or later." >&2
    exit 1
fi

if [ -e "${PRIV_KEY}" ] || [ -e "${PUB_KEY}" ]; then
    echo "Error: output file(s) already exist:" >&2
    [ -e "${PRIV_KEY}" ] && echo "  ${PRIV_KEY}" >&2
    [ -e "${PUB_KEY}" ] && echo "  ${PUB_KEY}" >&2
    echo "Refusing to overwrite. Remove them or choose a different basename." >&2
    exit 1
fi

# --- Key generation ------------------------------------------------------

# Generate the private key (PKCS#8 PEM).
#
# By default, OpenSSL writes BOTH the 64-byte FIPS 203 seed and the full
# expanded decapsulation key into the file (its "seed-priv"/"both" form),
# which is larger and uses an OpenSSL-specific CHOICE encoding that
# predates the finalized standard.
#
# We instead request the "bare-seed" output format: just the 64-byte
# seed, stored directly as the PKCS#8 privateKey OCTET STRING with no
# extra ASN.1 wrapping. This is the minimal form defined by RFC 9935
# ("Internet X.509 PKI - Algorithm Identifiers for ML-KEM") and is what
# most non-OpenSSL tooling (e.g. Go's crypto/mlkem seed export) expects.
umask 077
openssl genpkey -algorithm "${ALG}" \
    -provparam ml-kem.output_formats=bare-seed \
    -out "${PRIV_KEY}"

# Derive the public key from the private key.
openssl pkey -in "${PRIV_KEY}" -pubout -out "${PUB_KEY}"

# --- Summary -------------------------------------------------------------

chmod 600 "${PRIV_KEY}"
chmod 644 "${PUB_KEY}"

echo "Generated ${ALG} key pair:"
echo "  Private key: ${PRIV_KEY} (mode 600)"
echo "  Public key:  ${PUB_KEY} (mode 644)"
echo
# echo "Private key ASN.1 structure (should show a plain 64-byte OCTET"
# echo "STRING seed, not an OpenSSL CHOICE/SEQUENCE wrapper):"
# openssl asn1parse -in "${PRIV_KEY}"
