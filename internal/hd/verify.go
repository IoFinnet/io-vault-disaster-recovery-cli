// Copyright (C) 2025 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package hd

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/bittensor"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/solana"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/xrpl"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // RIPEMD-160 is part of the Bitcoin address format
	"golang.org/x/crypto/sha3"
)

// This file checks HD address records against a vault's PUBLIC keys only. Derivation in this tool
// is non-hardened (see ParseDerivationPath), so every child public key follows from the parent
// public key and chain code in the xpub: child = parent + IL·G. That lets the verify flow confirm
// an HD address belongs to a vault in the backup, and that its address is reproducible at its
// path, without ever reconstructing a private key.

// VaultKey is one public key a vault's decrypted shares state. PublicKey uses the same encoding
// as ParsedXpub.PublicKey: 33-byte compressed for secp256k1, 32-byte Ed25519 for Edwards25519.
type VaultKey struct {
	VaultID   string
	Curve     Curve
	PublicKey []byte
}

// CheckStatus is the outcome of checking one HD address record.
type CheckStatus string

const (
	// CheckMatch: the xpub belongs to a vault in the backup and the record's address is one of the
	// addresses derived from the child public key at its path.
	CheckMatch CheckStatus = "match"
	// CheckLabel: the xpub belongs to a vault in the backup, but the record's address column is a
	// label rather than an address, so only the derived addresses can be shown.
	CheckLabel CheckStatus = "label"
	// CheckMismatch: the xpub belongs to a vault in the backup, but the record's address is not
	// what its path derives. Recovering would produce keys for a different address.
	CheckMismatch CheckStatus = "mismatch"
	// CheckNoVault: no vault in the checked files has the xpub's public key.
	CheckNoVault CheckStatus = "no-vault"
	// CheckInvalid: the record cannot be derived (bad xpub, hardened or malformed path).
	CheckInvalid CheckStatus = "invalid"
)

// ChainAddress is an address derived for one chain family.
type ChainAddress struct {
	Chain   string
	Address string
}

// RecordCheck is the result for one HD address record. It holds public data only.
type RecordCheck struct {
	Record           AddressRecord
	Status           CheckStatus
	VaultID          string         // vault whose public key the xpub carries; empty for no-vault/invalid
	DerivedPublicKey string         // hex child public key; empty when it could not be derived
	Derived          []ChainAddress // addresses for the child public key
	Matched          *ChainAddress  // the derived address equal to Record.Address, for CheckMatch
	Message          string
}

// PreferredAddress is the derived address most relevant to the record: the matched one, else the
// one in the same format as the record's address, else the curve's default chain.
func (c RecordCheck) PreferredAddress() *ChainAddress {
	if c.Matched != nil {
		return c.Matched
	}
	if len(c.Derived) == 0 {
		return nil
	}
	if family := addressFamily(c.Record.Address); family != "" {
		for i := range c.Derived {
			if c.Derived[i].Chain == family {
				return &c.Derived[i]
			}
		}
	}
	return &c.Derived[0]
}

// CheckRecords checks every record against the vault public keys. A record whose xpub key matches
// none of keys is CheckNoVault; the rest are derived publicly and compared with their address.
func CheckRecords(records []AddressRecord, keys []VaultKey) []RecordCheck {
	out := make([]RecordCheck, 0, len(records))
	for _, rec := range records {
		out = append(out, checkRecord(rec, keys))
	}
	return out
}

func checkRecord(rec AddressRecord, keys []VaultKey) RecordCheck {
	result := RecordCheck{Record: rec}
	fail := func(status CheckStatus, msg string) RecordCheck {
		result.Status = status
		result.Message = msg
		return result
	}

	if err := ValidateAlgorithmCurve(rec.Algorithm, rec.Curve); err != nil {
		return fail(CheckInvalid, fmt.Sprintf("Unsupported algorithm and curve: %s/%s.", rec.Algorithm, rec.Curve))
	}
	parsed, err := ParseXpub(rec.Xpub, rec.Curve)
	if err != nil {
		return fail(CheckInvalid, "The xpub could not be read: "+err.Error()+".")
	}
	indices, err := ParseDerivationPath(rec.Path)
	if err != nil {
		if errors.Is(err, ErrHardenedDerivation) {
			return fail(CheckInvalid, "Hardened paths can't be derived by this tool.")
		}
		return fail(CheckInvalid, "The derivation path is not valid: "+err.Error()+".")
	}

	for _, k := range keys {
		if k.Curve == rec.Curve && bytes.Equal(k.PublicKey, parsed.PublicKey) {
			result.VaultID = k.VaultID
			break
		}
	}
	if result.VaultID == "" {
		return fail(CheckNoVault, "No vault in these files has this xpub's public key. Add the vault's backups, or unlock its files.")
	}

	childPK, err := DerivePublicChild(parsed.PublicKey, parsed.ChainCode, indices, rec.Curve)
	if err != nil {
		return fail(CheckInvalid, "The child key could not be derived: "+err.Error()+".")
	}
	result.DerivedPublicKey = hex.EncodeToString(childPK)
	result.Derived = AddressesForPublicKey(childPK, rec.Curve)

	for i := range result.Derived {
		if sameAddress(result.Derived[i].Address, rec.Address) {
			result.Matched = &result.Derived[i]
			result.Status = CheckMatch
			return result
		}
	}
	if addressFamily(rec.Address) == "" {
		result.Status = CheckLabel
		result.Message = "The address column holds a label, not an address, so only the derived addresses can be shown."
		return result
	}
	result.Status = CheckMismatch
	result.Message = "This address is not the one its path derives from the vault's key. Check the path and xpub in the CSV."
	if isMixedCaseBech32(rec.Address) {
		result.Message = "This Bitcoin address mixes upper and lower case, which is not a valid address (BIP 173). Check the address in the CSV."
	}
	return result
}

// DerivePublicChild derives the child public key along a non-hardened path from a parent public
// key and chain code. It is the public counterpart of deriveChildKey: for every index,
// IL = HMAC-SHA512(chainCode, parentPub || index)[:32] and child = parent + IL·G, with IL read the
// same way the private derivation adds it (big-endian for secp256k1, little-endian mod N for
// Edwards25519). The result uses the same encoding as computePublicKey.
func DerivePublicChild(parentPub, chainCode []byte, indices []uint32, curve Curve) ([]byte, error) {
	currentPub := bytes.Clone(parentPub)
	currentChainCode := bytes.Clone(chainCode)

	for _, index := range indices {
		if index >= 0x80000000 {
			return nil, ErrHardenedDerivation
		}
		data := make([]byte, len(currentPub)+4)
		copy(data, currentPub)
		binary.BigEndian.PutUint32(data[len(currentPub):], index)

		mac := hmac.New(sha512.New, currentChainCode)
		mac.Write(data)
		I := mac.Sum(nil)
		IL, IR := I[:32], I[32:]

		var err error
		switch curve {
		case CurveSecp256k1:
			currentPub, err = addSecp256k1(currentPub, IL)
		case CurveEdwards25519:
			currentPub, err = addEdwards25519(currentPub, IL)
		default:
			return nil, ErrUnsupportedCurve
		}
		if err != nil {
			return nil, err
		}
		currentChainCode = IR
	}
	return currentPub, nil
}

// addSecp256k1 returns parent + (IL mod n)·G as a compressed key, mirroring the private step
// child_sk = (parent_sk + IL) mod n.
func addSecp256k1(parent, IL []byte) ([]byte, error) {
	parentKey, err := secp256k1.ParsePubKey(parent)
	if err != nil {
		return nil, fmt.Errorf("invalid secp256k1 public key: %w", err)
	}
	var delta secp256k1.ModNScalar
	delta.SetByteSlice(IL) // reduces mod n

	var parentJ, deltaG, sum secp256k1.JacobianPoint
	parentKey.AsJacobian(&parentJ)
	secp256k1.ScalarBaseMultNonConst(&delta, &deltaG)
	secp256k1.AddNonConst(&parentJ, &deltaG, &sum)
	sum.ToAffine()
	if sum.X.IsZero() && sum.Y.IsZero() {
		return nil, errors.New("derived point at infinity")
	}
	return secp256k1.NewPublicKey(&sum.X, &sum.Y).SerializeCompressed(), nil
}

// addEdwards25519 returns parent + delta·G as a 32-byte Ed25519 key, where delta is IL read as a
// little-endian scalar mod N, mirroring the private step in deriveChildKey.
func addEdwards25519(parent, IL []byte) ([]byte, error) {
	parentKey, err := edwards.ParsePubKey(parent)
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 public key: %w", err)
	}
	curve := edwards.Edwards()

	reversed := make([]byte, len(IL))
	for i := range IL {
		reversed[len(IL)-1-i] = IL[i]
	}
	delta := new(big.Int).SetBytes(reversed)
	delta.Mod(delta, curve.N)
	if delta.Sign() == 0 {
		return bytes.Clone(parent), nil
	}

	dx, dy := curve.ScalarBaseMult(delta.Bytes())
	x, y := curve.Add(parentKey.X, parentKey.Y, dx, dy)
	return edwards.NewPublicKey(x, y).Serialize(), nil
}

// AddressesForPublicKey lists the addresses a child public key has on the chains this tool knows,
// in a stable order with the curve's most common chain first.
func AddressesForPublicKey(pub []byte, curve Curve) []ChainAddress {
	var out []ChainAddress
	add := func(chain, address string, err error) {
		if err == nil && address != "" {
			out = append(out, ChainAddress{Chain: chain, Address: address})
		}
	}

	switch curve {
	case CurveSecp256k1:
		key, err := secp256k1.ParsePubKey(pub)
		if err != nil {
			return nil
		}
		uncompressed := key.SerializeUncompressed()
		h := sha3.NewLegacyKeccak256()
		h.Write(uncompressed[1:])
		keccak := h.Sum(nil)[12:]
		add(ChainEthereum, common.BytesToAddress(keccak).Hex(), nil)

		compressed := key.SerializeCompressed()
		hash160 := ripemd(sha256Sum(compressed))
		mainnet, err := segwitAddress("bc", hash160)
		add(ChainBitcoin, mainnet, err)
		testnet, err := segwitAddress("tb", hash160)
		add(ChainBitcoinTestnet, testnet, err)
		add(ChainBitcoinLegacy, base58.CheckEncode(hash160, 0x00), nil)
		add(ChainTron, base58.CheckEncode(keccak, 0x41), nil)

	case CurveEdwards25519:
		address, err := solana.DeriveSolanaAddress(pub)
		add(ChainSolana, address, err)
		address, err = xrpl.DeriveXRPLAddress(pub)
		add(ChainXRPL, address, err)
		address, err = bittensor.GenerateSS58Address(pub)
		add(ChainBittensor, address, err)
	}
	return out
}

// Chain names used in ChainAddress.Chain.
const (
	ChainEthereum       = "Ethereum"
	ChainBitcoin        = "Bitcoin"
	ChainBitcoinTestnet = "Bitcoin testnet"
	ChainBitcoinLegacy  = "Bitcoin (legacy)"
	ChainTron           = "Tron"
	ChainSolana         = "Solana"
	ChainXRPL           = "XRP Ledger"
	ChainBittensor      = "Bittensor"
)

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func ripemd(b []byte) []byte {
	h := ripemd160.New()
	h.Write(b)
	return h.Sum(nil)
}

// segwitAddress encodes a version-0 witness public key hash (P2WPKH) address.
func segwitAddress(hrp string, hash160 []byte) (string, error) {
	program, err := bech32.ConvertBits(hash160, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(hrp, append([]byte{0x00}, program...))
}

// sameAddress compares addresses, ignoring case only where the format is case-insensitive
// (0x hex and bech32). A bech32 address must be all lower or all upper case (BIP 173), so a
// mixed-case one never matches.
func sameAddress(derived, given string) bool {
	given = strings.TrimSpace(given)
	if given == "" {
		return false
	}
	lower := strings.ToLower(given)
	if strings.HasPrefix(lower, "bc1") || strings.HasPrefix(lower, "tb1") {
		return !isMixedCaseBech32(given) && strings.EqualFold(derived, given)
	}
	if strings.HasPrefix(lower, "0x") {
		return strings.EqualFold(derived, given)
	}
	return derived == given
}

// isMixedCaseBech32 reports whether a bc1/tb1 address mixes upper and lower case letters.
func isMixedCaseBech32(address string) bool {
	a := strings.TrimSpace(address)
	lower := strings.ToLower(a)
	if !strings.HasPrefix(lower, "bc1") && !strings.HasPrefix(lower, "tb1") {
		return false
	}
	return a != lower && a != strings.ToUpper(a)
}

var (
	// Both 0x and 0X prefixes are recognised, as sameAddress accepts either.
	evmAddressPattern    = regexp.MustCompile(`^0[xX][0-9a-fA-F]{40}$`)
	bech32AddressPattern = regexp.MustCompile(`^(?i)(bc1|tb1)[02-9ac-hj-np-z]{8,87}$`)
	tronAddressPattern   = regexp.MustCompile(`^T[1-9A-HJ-NP-Za-km-z]{33}$`)
	xrplAddressPattern   = regexp.MustCompile(`^r[1-9A-HJ-NP-Za-km-z]{24,34}$`)
	ss58AddressPattern   = regexp.MustCompile(`^5[1-9A-HJ-NP-Za-km-z]{47}$`)
	legacyBTCPattern     = regexp.MustCompile(`^[13][1-9A-HJ-NP-Za-km-z]{25,34}$`)
	solanaAddressPattern = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`)
)

// addressFamily guesses which chain an address column value belongs to, or "" when it does not
// look like an address at all (a label). The order matters: narrower formats are tried first.
func addressFamily(address string) string {
	a := strings.TrimSpace(address)
	switch {
	case evmAddressPattern.MatchString(a):
		return ChainEthereum
	case bech32AddressPattern.MatchString(a):
		if strings.HasPrefix(strings.ToLower(a), "tb1") {
			return ChainBitcoinTestnet
		}
		return ChainBitcoin
	case tronAddressPattern.MatchString(a):
		return ChainTron
	case xrplAddressPattern.MatchString(a):
		return ChainXRPL
	case ss58AddressPattern.MatchString(a):
		return ChainBittensor
	case legacyBTCPattern.MatchString(a):
		return ChainBitcoinLegacy
	case solanaAddressPattern.MatchString(a):
		return ChainSolana
	default:
		return ""
	}
}
