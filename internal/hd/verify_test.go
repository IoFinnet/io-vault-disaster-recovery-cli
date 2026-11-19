// Copyright (C) 2025 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package hd

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/bech32"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The same tss-lib vectors as derive_tss_test.go, derived here from the PUBLIC key only.
func TestDerivePublicChild_MatchesTSSVectors(t *testing.T) {
	cases := []struct {
		curve     Curve
		alg       Algorithm
		masterSK  string
		chainCode string
		path      string
		childPK   string
	}{
		{CurveSecp256k1, AlgorithmECDSA, "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
			"873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508", "m/0",
			"027c4b09ffb985c298afe7e5813266cbfcb7780b480ac294b0b43dc21f2be3d13c"},
		{CurveSecp256k1, AlgorithmECDSA, "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
			"873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508", "m/44/0/0",
			"02b41ee4dfdf05264b0eaad3c8e271b973ff225e1e81ab0585b23cad4de0c4a1e6"},
		{CurveSecp256k1, AlgorithmECDSA, "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
			"873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508", "m/44/60/0/0/0",
			"0389988f76588819d77d0a639a962fee68e94441878d01121d65c602f28d5e17a4"},
		{CurveEdwards25519, AlgorithmEDDSA, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "m/0",
			"f0668f57fe91dd5ef7c83ef38754831e37116aedcaaaeb248e3c90005e6ea51c"},
		{CurveEdwards25519, AlgorithmEDDSA, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "m/44/501/0/0",
			"9531744deb5d0128ad55a3bc544dc89e6bf6e2ea359f56eaae604fc4eb2536ff"},
	}
	for _, tc := range cases {
		t.Run(string(tc.curve)+" "+tc.path, func(t *testing.T) {
			sk, _ := hex.DecodeString(tc.masterSK)
			chainCode, _ := hex.DecodeString(tc.chainCode)
			parentPub, err := computePublicKey(sk, tc.alg, tc.curve)
			require.NoError(t, err)
			indices, err := ParseDerivationPath(tc.path)
			require.NoError(t, err)

			childPub, err := DerivePublicChild(parentPub, chainCode, indices, tc.curve)
			require.NoError(t, err)
			assert.Equal(t, tc.childPK, hex.EncodeToString(childPub))
		})
	}
}

// Public derivation must agree with the private derivation the recovery path uses, for any key.
func TestDerivePublicChild_MatchesPrivateDerivation(t *testing.T) {
	paths := []string{"m", "m/0", "m/1/2", "m/44/60/0/0/7", "m/44/501/0/0", "m/2147483647"}
	for _, c := range []struct {
		curve Curve
		alg   Algorithm
	}{{CurveSecp256k1, AlgorithmECDSA}, {CurveEdwards25519, AlgorithmEDDSA}} {
		for i := 0; i < 8; i++ {
			sk := make([]byte, 32)
			chainCode := make([]byte, 32)
			_, err := rand.Read(sk)
			require.NoError(t, err)
			_, err = rand.Read(chainCode)
			require.NoError(t, err)
			if c.curve == CurveSecp256k1 {
				sk[0] &= 0x7f // stay below the secp256k1 order
			}

			parentPub, err := computePublicKey(sk, c.alg, c.curve)
			require.NoError(t, err)
			for _, path := range paths {
				indices, err := ParseDerivationPath(path)
				require.NoError(t, err)
				_, wantPub, err := deriveChildKey(sk, chainCode, parentPub, indices, c.alg, c.curve)
				require.NoError(t, err)
				gotPub, err := DerivePublicChild(parentPub, chainCode, indices, c.curve)
				require.NoError(t, err)
				assert.Equal(t, hex.EncodeToString(wantPub), hex.EncodeToString(gotPub), "%s %s", c.curve, path)
			}
		}
	}
}

func TestDerivePublicChild_RejectsHardened(t *testing.T) {
	sk, _ := hex.DecodeString("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
	pub, err := computePublicKey(sk, AlgorithmECDSA, CurveSecp256k1)
	require.NoError(t, err)
	_, err = DerivePublicChild(pub, make([]byte, 32), []uint32{0x80000000}, CurveSecp256k1)
	assert.ErrorIs(t, err, ErrHardenedDerivation)
}

func TestAddressesForPublicKey_Secp256k1(t *testing.T) {
	// BIP32 test vector 1 master key: its P2PKH address is a published value.
	sk, _ := hex.DecodeString("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
	pub, err := computePublicKey(sk, AlgorithmECDSA, CurveSecp256k1)
	require.NoError(t, err)
	addrs := addressMap(AddressesForPublicKey(pub, CurveSecp256k1))

	assert.Equal(t, "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma", addrs[ChainBitcoinLegacy])

	// Ethereum, cross-checked with go-ethereum's own derivation from the private key.
	key, err := ethcrypto.ToECDSA(sk)
	require.NoError(t, err)
	assert.Equal(t, ethcrypto.PubkeyToAddress(key.PublicKey).Hex(), addrs[ChainEthereum])

	// Bech32 P2WPKH must decode back to witness v0 over the same hash160 as the legacy address.
	hrp, data, err := bech32.Decode(addrs[ChainBitcoin])
	require.NoError(t, err)
	assert.Equal(t, "bc", hrp)
	assert.Equal(t, byte(0), data[0])
	program, err := bech32.ConvertBits(data[1:], 5, 8, false)
	require.NoError(t, err)
	assert.Equal(t, "3442193e1bb70916e914552172cd4e2dbc9df811", hex.EncodeToString(program))
	assert.True(t, strings.HasPrefix(addrs[ChainBitcoinTestnet], "tb1q"))
	assert.True(t, strings.HasPrefix(addrs[ChainTron], "T"))
}

func TestAddressesForPublicKey_Edwards25519(t *testing.T) {
	pub, _ := hex.DecodeString("f0668f57fe91dd5ef7c83ef38754831e37116aedcaaaeb248e3c90005e6ea51c")
	addrs := addressMap(AddressesForPublicKey(pub, CurveEdwards25519))
	assert.NotEmpty(t, addrs[ChainSolana])
	assert.True(t, strings.HasPrefix(addrs[ChainXRPL], "r"))
	assert.True(t, strings.HasPrefix(addrs[ChainBittensor], "5"))
}

func TestCheckRecords(t *testing.T) {
	sk, _ := hex.DecodeString("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
	masterPub, err := computePublicKey(sk, AlgorithmECDSA, CurveSecp256k1)
	require.NoError(t, err)
	parsed, err := ParseXpub(testXpubECDSA, CurveSecp256k1)
	require.NoError(t, err)
	require.Equal(t, masterPub, parsed.PublicKey, "fixture xpub must carry the BIP32 vector 1 master key")

	// The expected address comes from the PRIVATE derivation, so the check is independent.
	indices, _ := ParseDerivationPath("m/44/60/0/0/0")
	childSK, _, err := deriveChildKey(sk, parsed.ChainCode, parsed.PublicKey, indices, AlgorithmECDSA, CurveSecp256k1)
	require.NoError(t, err)
	childKey, err := ethcrypto.ToECDSA(childSK)
	require.NoError(t, err)
	childETH := ethcrypto.PubkeyToAddress(childKey.PublicKey).Hex()

	rec := func(address, path string) AddressRecord {
		return AddressRecord{Address: address, Xpub: testXpubECDSA, Path: path, Algorithm: AlgorithmECDSA, Curve: CurveSecp256k1}
	}
	keys := []VaultKey{
		{VaultID: "other-vault", Curve: CurveEdwards25519, PublicKey: masterPub[1:]},
		{VaultID: "vault-1", Curve: CurveSecp256k1, PublicKey: masterPub},
	}
	checks := CheckRecords([]AddressRecord{
		rec(strings.ToLower(childETH), "m/44/60/0/0/0"),
		rec("treasury hot wallet", "m/44/60/0/0/0"),
		rec(childETH, "m/44/60/0/0/1"),
		rec(childETH, "m/44'/60/0"),
		{Address: "x", Xpub: "not-an-xpub", Path: "m/0", Algorithm: AlgorithmECDSA, Curve: CurveSecp256k1},
	}, keys)
	require.Len(t, checks, 5)

	assert.Equal(t, CheckMatch, checks[0].Status, checks[0].Message)
	assert.Equal(t, "vault-1", checks[0].VaultID)
	require.NotNil(t, checks[0].Matched)
	assert.Equal(t, ChainEthereum, checks[0].Matched.Chain)

	assert.Equal(t, CheckLabel, checks[1].Status)
	assert.Equal(t, childETH, checks[1].PreferredAddress().Address)

	assert.Equal(t, CheckMismatch, checks[2].Status)
	assert.Equal(t, ChainEthereum, checks[2].PreferredAddress().Chain, "a mismatch shows the derived address of the same chain")

	assert.Equal(t, CheckInvalid, checks[3].Status)
	assert.Contains(t, checks[3].Message, "Hardened")
	assert.Equal(t, CheckInvalid, checks[4].Status)

	// The same records without the vault's key: nothing can be confirmed.
	none := CheckRecords([]AddressRecord{rec(childETH, "m/44/60/0/0/0")}, keys[:1])
	assert.Equal(t, CheckNoVault, none[0].Status)
	assert.Empty(t, none[0].VaultID)
}

// Address case: 0x/0X hex both count as Ethereum addresses, and bech32 accepts all-lower or
// all-upper but never mixed case (BIP 173).
func TestCheckRecords_AddressCase(t *testing.T) {
	parsed, err := ParseXpub(testXpubECDSA, CurveSecp256k1)
	require.NoError(t, err)
	const path = "m/44/60/0/0/0"
	indices, err := ParseDerivationPath(path)
	require.NoError(t, err)
	childPK, err := DerivePublicChild(parsed.PublicKey, parsed.ChainCode, indices, CurveSecp256k1)
	require.NoError(t, err)
	derived := addressMap(AddressesForPublicKey(childPK, CurveSecp256k1))
	eth, btc := derived[ChainEthereum], derived[ChainBitcoin]
	require.True(t, strings.HasPrefix(btc, "bc1"))

	rec := func(address string) AddressRecord {
		return AddressRecord{Address: address, Xpub: testXpubECDSA, Path: path, Algorithm: AlgorithmECDSA, Curve: CurveSecp256k1}
	}
	keys := []VaultKey{{VaultID: "vault-1", Curve: CurveSecp256k1, PublicKey: parsed.PublicKey}}
	checks := CheckRecords([]AddressRecord{
		rec("0X" + eth[2:]),
		rec("0X" + strings.Repeat("ab", 20)),
		rec(btc),
		rec(strings.ToUpper(btc)),
		rec("B" + btc[1:]),
	}, keys)
	require.Len(t, checks, 5)

	assert.Equal(t, CheckMatch, checks[0].Status, checks[0].Message)
	assert.Equal(t, CheckMismatch, checks[1].Status, "a different 0X address is a mismatch, not a label")
	assert.Equal(t, ChainEthereum, checks[1].PreferredAddress().Chain)
	assert.Equal(t, CheckMatch, checks[2].Status, checks[2].Message)
	assert.Equal(t, CheckMatch, checks[3].Status, checks[3].Message)
	assert.Equal(t, CheckMismatch, checks[4].Status, "mixed-case bech32 is not a valid address")
	assert.Contains(t, checks[4].Message, "BIP 173")
}

func TestAddressFamily(t *testing.T) {
	cases := map[string]string{
		"0x52908400098527886E0F7030069857D2E4169EE7": ChainEthereum,
		"0X52908400098527886E0F7030069857D2E4169EE7": ChainEthereum,
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": ChainBitcoin,
		"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx": ChainBitcoinTestnet,
		"15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma":         ChainBitcoinLegacy, // BIP32 test vector 1
		"TAbcdefghijkmnopqrstuvwxyz12345678":         ChainTron,          // synthetic, format only
		"rExampLeXrpLedgerAddress2222":               ChainXRPL,          // synthetic, format only
		"ecdsa_secp256k1_1":                          "",
		"treasury hot wallet":                        "",
	}
	for address, want := range cases {
		assert.Equal(t, want, addressFamily(address), address)
	}
}

func addressMap(list []ChainAddress) map[string]string {
	out := make(map[string]string, len(list))
	for _, a := range list {
		out[a.Chain] = a.Address
	}
	return out
}
