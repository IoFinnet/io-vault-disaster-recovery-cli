// Copyright (C) 2025 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package hd

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This test cross-checks our secp256k1 HD derivation against an *independent*
// BIP-0032 implementation (btcsuite/hdkeychain, the library production Bitcoin
// wallets use) and carries the result all the way to the Ethereum address a
// wallet would display — answering "does the address a user sees match what
// another wallet would derive?".
//
// It runs through the public DeriveAll seam (xpub parse, path parse, master-key
// selection, hex encoding), not the internal deriveChildKey, so it exercises the
// same code path the CLI/web recovery uses.
//
// Scope: secp256k1 only. hdkeychain is secp256k1-only, and secp256k1 is the only
// curve with a standard, independent BIP-0032 oracle. EdDSA/Ed25519 and P-256
// derivation are non-standard and are NOT covered here — they remain validated
// by the tss-lib reference vectors in derive_tss_test.go.
func TestDerivation_MatchesHDKeychain_Ethereum(t *testing.T) {
	// BIP-0032 Test Vector 1 master (seed 000102030405060708090a0b0c0d0e0f).
	// These are the published spec values; also used by derive_tss_test.go.
	masterSK, _ := hex.DecodeString("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
	chainCode, _ := hex.DecodeString("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")

	// Build the independent oracle's master key. Mainnet xprv version (0x0488ADE4)
	// avoids a chaincfg import; only the chain code + key matter for derivation.
	xprvVersion := []byte{0x04, 0x88, 0xAD, 0xE4}
	master := hdkeychain.NewExtendedKey(xprvVersion, masterSK, chainCode,
		[]byte{0, 0, 0, 0}, 0, 0, true)

	// Anchor the oracle: hdkeychain must reproduce the known BIP-0032 TV1 m/0
	// child public key — the same value derive_tss_test.go pins via tss-lib. This
	// triangulates three independent implementations (hdkeychain == tss-lib ==
	// this tool) before we rely on hdkeychain as the oracle below.
	m0, err := master.Derive(0)
	require.NoError(t, err)
	require.Equal(t, "027c4b09ffb985c298afe7e5813266cbfcb7780b480ac294b0b43dc21f2be3d13c",
		hex.EncodeToString(mustPub(t, m0).SerializeCompressed()),
		"hdkeychain must reproduce the known BIP32 TV1 m/0 child key")

	// Derive the Ethereum account key the way io.vault does server-side:
	// m/44'/60'/0' (hardened). The recovery tool then derives the non-hardened
	// tail (address indices) from this account xpub — so m/44'/60'/0'/0/0 below is
	// the exact path a wallet like MetaMask uses for account 0, address 0.
	account := master
	for _, h := range []uint32{44, 60, 0} {
		var err error
		account, err = account.Derive(hdkeychain.HardenedKeyStart + h)
		require.NoError(t, err)
	}

	accountXpub, err := account.Neuter()
	require.NoError(t, err)
	accountXpubStr := accountXpub.String()

	accountECPriv, err := account.ECPrivKey()
	require.NoError(t, err)
	accountSK := accountECPriv.Serialize()

	// Sanity: the account xpub we hand the tool must encode the public key of the
	// account master key we hand it, or the first HMAC would diverge.
	wantPub, err := computePublicKey(accountSK, AlgorithmECDSA, CurveSecp256k1)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(mustPub(t, account).SerializeCompressed()),
		hex.EncodeToString(wantPub), "account xpub and master key must be consistent")

	deriver, err := NewDeriver(accountSK, nil)
	require.NoError(t, err)

	// Non-hardened tails the tool supports; full path shown for context.
	tails := []struct {
		path     string // relative to the account xpub
		fullPath string // what a wallet uses end-to-end
	}{
		{"m/0/0", "m/44'/60'/0'/0/0"},
		{"m/0/1", "m/44'/60'/0'/0/1"},
		{"m/0/5", "m/44'/60'/0'/0/5"},
		{"m/1/0", "m/44'/60'/0'/1/0"},
	}

	for _, tc := range tails {
		t.Run(tc.fullPath, func(t *testing.T) {
			// Independent oracle: derive the same tail with hdkeychain.
			oracle := account
			indices, err := ParseDerivationPath(tc.path)
			require.NoError(t, err)
			for _, idx := range indices {
				oracle, err = oracle.Derive(idx)
				require.NoError(t, err)
			}
			oraclePub := mustPub(t, oracle)
			wantPK := hex.EncodeToString(oraclePub.SerializeCompressed())
			wantAddr := ethAddress(oraclePub)

			// Tool under test: through the public DeriveAll pipeline.
			out, err := deriver.DeriveAll([]AddressRecord{{
				Address:   tc.fullPath,
				Xpub:      accountXpubStr,
				Path:      tc.path,
				Algorithm: AlgorithmECDSA,
				Curve:     CurveSecp256k1,
			}})
			require.NoError(t, err)
			require.Len(t, out, 1)
			got := out[0]

			// 1) Derived compressed pubkey matches the independent BIP-0032 lib.
			assert.Equal(t, wantPK, got.PublicKey, "child pubkey must match hdkeychain")

			// 2) It must actually derive (not echo the account master key).
			assert.NotEqual(t, hex.EncodeToString(mustPub(t, account).SerializeCompressed()),
				got.PublicKey, "derivation must move off the account key")

			// 3) The Ethereum address a wallet would show matches, computed
			//    independently of the tool from both keys.
			gotPubBytes, err := hex.DecodeString(got.PublicKey)
			require.NoError(t, err)
			gotPub, err := btcec.ParsePubKey(gotPubBytes)
			require.NoError(t, err)
			assert.Equal(t, wantAddr, ethAddress(gotPub), "ETH address must match independent derivation")

			t.Logf("%s -> pubkey=%s eth=%s", tc.fullPath, got.PublicKey, wantAddr)
		})
	}
}

// mustPub returns the secp256k1 public key for an extended key, failing the test
// on error. (hdkeychain's ECPubKey returns an error in this version.)
func mustPub(t *testing.T, k *hdkeychain.ExtendedKey) *btcec.PublicKey {
	t.Helper()
	pub, err := k.ECPubKey()
	require.NoError(t, err)
	return pub
}

// ethAddress computes the Ethereum address for a secp256k1 public key the way any
// wallet does: keccak256(uncompressed X||Y)[12:]. Independent of the tool's own
// address logic (the HD pipeline emits keys, not addresses).
func ethAddress(pub *btcec.PublicKey) string {
	uncompressed := pub.SerializeUncompressed() // 0x04 || X(32) || Y(32)
	h := ethcrypto.Keccak256(uncompressed[1:])
	return "0x" + hex.EncodeToString(h[12:])
}
