// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/fileutils"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/recoverypipeline"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"
)

func runTool(vaultsDataFile []ui.VaultsDataFile, vaultID *string, nonceOverride *int, requestIDOverride *string, quorumOverride *int, exportKSFile, passwordForKS *string, privateKeyPEM []byte) (
	address string, ecdsaSK, eddsaSK []byte, orderedVaults []ui.VaultPickerItem, exportedKsFile *string, welp error) {

	if nonceOverride != nil && *nonceOverride > -1 {
		fmt.Printf("\n⚠ Using reshare nonce override: %d. Be sure to set the threshold of the vault at this reshare point with -threshold, or recovery will produce incorrect data.\n", *nonceOverride)
	}
	if requestIDOverride != nil && *requestIDOverride != "" {
		fmt.Printf("\n⚠ Using request id override: %s. Be sure to set the threshold of the vault at this reshare point with -threshold, or recovery will produce incorrect data.\n", *requestIDOverride)
	}
	if quorumOverride != nil && *quorumOverride > 0 {
		fmt.Printf("\n⚠ Using vault quorum override: %d.\n", *quorumOverride)
	}
	if (nonceOverride != nil && *nonceOverride > -1) || (requestIDOverride != nil && *requestIDOverride != "") || (quorumOverride != nil && *quorumOverride > 0) {
		println()
	}

	res, err := recoverypipeline.Prepare(vaultsDataFile, vaultID, nonceOverride, requestIDOverride, privateKeyPEM, recoverypipeline.ErrorPresentation{})
	if err != nil {
		if errors.Is(err, recoverypipeline.ErrPrivateKeyRequired) {
			welp = fmt.Errorf("%s; use -private-key to supply the ML-KEM-768 private key PEM", err)
			return
		}
		welp = err
		return
	}
	orderedVaults = res.OrderedVaults

	justListingVaults := vaultID == nil || *vaultID == ""
	if justListingVaults {
		return "", nil, nil, orderedVaults, nil, nil
	}

	clearVaults := res.Vaults
	vaultAllSharesECDSA, vaultAllSharesEDDSA := res.SharesECDSA, res.SharesEdDSA
	vaultHasEDDSA := res.HasEdDSA
	mobileVaults, mobileFileThreshold := res.MobileVaults, res.MobileFileThreshold

	println()
	if _, ok := vaultAllSharesECDSA[*vaultID]; !ok {
		welp = fmt.Errorf("⚠ provided files do not contain data for vault `%s` with the expected reshare nonce", *vaultID)
		return
	}
	if vaultHasEDDSA[*vaultID] && len(vaultAllSharesEDDSA[*vaultID]) != len(vaultAllSharesECDSA[*vaultID]) {
		welp = fmt.Errorf("⚠ count of EDDSA shares %d != count of ECDSA shares %d for vault `%s`",
			len(vaultAllSharesEDDSA[*vaultID]), len(vaultAllSharesECDSA[*vaultID]), *vaultID)
		return
	}

	// Strict per-epoch threshold for mobile vaults: a mobile vault's quorum must come from its own
	// file (v5) or the -threshold flag — never from a .dr file that happens to cover the same vault.
	// A legacy v4 mobile file carries no threshold, so require the flag rather than silently reusing
	// a .dr-derived Quroum.
	if mobileVaults[*vaultID] && !mobileFileThreshold[*vaultID] && (quorumOverride == nil || *quorumOverride <= 0) {
		welp = fmt.Errorf("⚠ vault %s: mobile backup carries no threshold (re-export with an updated app for v5, or pass -threshold)", *vaultID)
		return
	}
	tPlus1 := clearVaults[*vaultID].Quroum
	if quorumOverride != nil && *quorumOverride > 0 {
		tPlus1 = *quorumOverride
	}
	if tPlus1 < 1 {
		welp = fmt.Errorf("⚠ vault %s: no threshold available for reconstruction (pass -threshold)", *vaultID)
		return
	}
	vssSharesECDSA := make(vss.Shares, len(vaultAllSharesECDSA[*vaultID]))
	vssSharesEDDSA := make(vss.Shares, len(vaultAllSharesEDDSA[*vaultID]))
	if len(vaultAllSharesECDSA[*vaultID]) < tPlus1 {
		welp = fmt.Errorf("⚠ not enough shares. are you using the newest files? (need %d, have %d)",
			tPlus1, len(vaultAllSharesECDSA[*vaultID]))
		return
	}
	var share0ECDSAPubKey, share0EDDSAPubKey *crypto.ECPoint
	for i, el := range vaultAllSharesECDSA[*vaultID] {
		vssSharesECDSA[i] = &vss.Share{
			Threshold: tPlus1 - 1,
			ID:        el.ShareID,
			Share:     el.Xi,
		}
		if i == 0 {
			share0ECDSAPubKey = el.ECDSAPub
		}
	}
	if vaultHasEDDSA[*vaultID] {
		for i, el := range vaultAllSharesEDDSA[*vaultID] {
			vssSharesEDDSA[i] = &vss.Share{
				Threshold: tPlus1 - 1,
				ID:        el.ShareID,
				Share:     el.Xi,
			}
			if i == 0 {
				share0EDDSAPubKey = el.EDDSAPub
			}
		}
	}

	// Re-construct the secret keys
	var ecdsaSKI, eddsaSKI *big.Int
	if ecdsaSKI, welp = vssSharesECDSA.ReConstruct(tss.S256()); welp != nil {
		return
	}
	if vaultHasEDDSA[*vaultID] {
		if eddsaSKI, welp = vssSharesEDDSA.ReConstruct(tss.Edwards()); welp != nil {
			return
		}
		eddsaSK = leftPadTo32Bytes(eddsaSKI)
		eddsaSKI.SetInt64(0)
	}
	ecdsaSK = leftPadTo32Bytes(ecdsaSKI)
	ecdsaSKI.SetInt64(0)

	// ensure the ECDSA PK matches our expected share 0 PK
	scl := secp256k1.ModNScalar{}
	scl.SetByteSlice(ecdsaSK)
	privKey := secp256k1.NewPrivateKey(&scl)
	pk := privKey.PubKey()
	if !pk.ToECDSA().Equal(share0ECDSAPubKey.ToBtcecPubKey().ToECDSA()) {
		welp = fmt.Errorf("⚠ recovered ECDSA public key did not match the expected share 0 public key! did you input the right threshold?")
		return
	}

	// if applicable, ensure the EDDSA PK matches our expected share 0 PK
	if vaultHasEDDSA[*vaultID] {
		_, edPK, err := edwards.PrivKeyFromScalar(eddsaSK)
		if err != nil {
			welp = err
			return
		}
		edPKPt, err := crypto.NewECPoint(tss.Edwards(), edPK.X, edPK.Y)
		if err != nil {
			welp = err
			return
		}
		if !edPKPt.Equals(share0EDDSAPubKey) {
			welp = fmt.Errorf("⚠ recovered EdDSA public key did not match the expected share 0 public key! did you input the right threshold?")
			return
		}
	}

	// encode Ethereum address for human sanity check
	if _, address, welp = getTSSPubKeyForEthereum(pk.X(), pk.Y()); welp != nil {
		return
	}

	// write out keystore file
	if exportKSFile != nil && len(*exportKSFile) > 0 {
		if passwordForKS == nil || len(*passwordForKS) == 0 {
			fmt.Println(ui.PlainTextf("NOTE: -password flag is required to export wallet v3 file `%s`. A wallet v3 file will not be created this time.\n", *exportKSFile))
			return
		}
		ksUuid, err2 := uuid.NewRandom()
		if err2 != nil {
			welp = fmt.Errorf("⚠ could not create random uuid: %v", err2)
			return
		}
		key := &keystore.Key{
			Id:         ksUuid,
			Address:    common.HexToAddress(address),
			PrivateKey: privKey.ToECDSA(),
		}
		keyfile, err2 := keystore.EncryptKey(key, *passwordForKS, keystore.StandardScryptN, keystore.StandardScryptP)
		if err2 != nil {
			welp = fmt.Errorf("⚠ could not create the wallet v3 file json %s: %v", *exportKSFile, err2)
			return
		}
		if err := fileutils.WriteToNewFile(*exportKSFile, keyfile, fileutils.PermissionOwnerRW); err != nil {
			welp = fmt.Errorf("⚠ could not write the wallet v3 file %s: %v", *exportKSFile, err)
			return
		}
		exportedKsFile = exportKSFile
		fmt.Println(ui.PlainTextf("\nWrote a MetaMask wallet v3 (for ECDSA key only) to: %s\n", *exportKSFile))
	}
	return address, ecdsaSK, eddsaSK, orderedVaults, exportedKsFile, nil
}

func getTSSPubKeyForEthereum(x, y *big.Int) (*secp256k1.PublicKey, string, error) {
	if x == nil || y == nil {
		return nil, "", errors.New("invalid public key coordinates")
	}
	pubKey, err := secp256k1.ParsePubKey(append([]byte{0x04}, append(x.Bytes(), y.Bytes()...)...))
	if err != nil {
		return nil, "", err
	}
	var pubKeyBz [65]byte
	copy(pubKeyBz[:], pubKey.SerializeUncompressed())

	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubKeyBz[1:])
	sum := hash.Sum(nil)
	addr := fmt.Sprintf("0x%s", hex.EncodeToString(sum[len(sum)-20:]))

	// render the address in "checksum" format (mix of uppercase and lowercase chars)
	addr = common.HexToAddress(addr).Hex()
	return pubKey, addr, nil
}

// leftPadTo32Bytes pads the byte representation of a big.Int to 32 bytes with leading zeros.
func leftPadTo32Bytes(i *big.Int) []byte {
	padded := make([]byte, 32)
	if i == nil {
		return padded
	}
	bytes := i.Bytes()
	if len(bytes) >= 32 {
		return bytes
	}
	copy(padded[32-len(bytes):], bytes)
	return padded
}
