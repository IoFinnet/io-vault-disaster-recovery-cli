package wif

import (
	"crypto/sha256"
	"math/big"
)

/******************************************************************************/
/* Base-58 Encode/Decode */
/******************************************************************************/

// b58encode encodes a byte slice b into a base-58 encoded string.
func b58encode(b []byte) (out []byte) {
	/* See https://en.bitcoin.it/wiki/Base58Check_encoding */

	const BITCOIN_BASE58_TABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	/* Convert big endian bytes to big int */
	x := new(big.Int).SetBytes(b)

	/* Initialize */
	r := new(big.Int)
	m := big.NewInt(58)
	zero := big.NewInt(0)
	out = []byte{}

	/* Convert big int to string */
	for x.Cmp(zero) > 0 {
		/* x, r = (x / 58, x % 58) */
		x.QuoRem(x, m, r)
		/* Prepend ASCII character */
		out = append([]byte{BITCOIN_BASE58_TABLE[r.Int64()]}, out...)
	}

	return out
}

/******************************************************************************/
/* Base-58 Check Encode/Decode */
/******************************************************************************/

// b58checkencode encodes version ver and byte slice b into a base-58 check encoded string.
func b58checkencode(ver uint8, b []byte) (out []byte) {
	/* Prepend version */
	bcpy := append([]byte{ver}, b...)

	/* Create a new SHA256 context */
	sha256_h := sha256.New()

	/* SHA256 Hash #1 */
	sha256_h.Reset()
	sha256_h.Write(bcpy)
	hash1 := sha256_h.Sum(nil)

	/* SHA256 Hash #2 */
	sha256_h.Reset()
	sha256_h.Write(hash1)
	hash2 := sha256_h.Sum(nil)

	/* Append first four bytes of hash */
	bcpy = append(bcpy, hash2[0:4]...)

	/* Encode base58 string */
	out = b58encode(bcpy)

	/* For number of leading 0's in bytes, prepend 1 */
	for _, v := range bcpy {
		if v != 0 {
			break
		}
		out = append([]byte{'1'}, out...)
	}

	return out
}
