// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/data"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/vss"
	ecdsa_keygen "github.com/binance-chain/tss-lib/ecdsa/keygen"
	eddsa_keygen "github.com/binance-chain/tss-lib/eddsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	errors2 "github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/sha3"
)

func runTool(vaultsDataFile []ui.VaultsDataFile, vaultID *string, nonceOverride, quorumOverride *int, exportKSFile, passwordForKS *string) (
	address string, ecdsaSK, eddsaSK []byte, orderedVaults []ui.VaultPickerItem, welp error) {

	if nonceOverride != nil && *nonceOverride > -1 {
		fmt.Printf("\n⚠ Using reshare nonce override: %d. Be sure to set the threshold of the vault at this reshare point with -threshold, or recovery will produce incorrect data.\n", *nonceOverride)
	}
	if quorumOverride != nil && *quorumOverride > 0 {
		fmt.Printf("\n⚠ Using vault quorum override: %d.\n", *quorumOverride)
	}
	if (nonceOverride != nil && *nonceOverride > -1) || (quorumOverride != nil && *quorumOverride > 0) {
		println()
	}

	justListingVaults := vaultID == nil || *vaultID == ""

	// Internal & returned data structures
	clearVaults := make(ClearVaultMap, len(vaultsDataFile)*16)
	vaultAllSharesECDSA := make(VaultAllSharesECDSA, len(vaultsDataFile)*16) // headroom
	vaultAllSharesEDDSA := make(VaultAllSharesEdDSA, len(vaultsDataFile)*16)
	vaultHasEDDSA := make(map[string]bool, len(vaultsDataFile)*16)
	vaultLastNonces := make(map[string]int, len(vaultsDataFile)*16)

	// // Do the main routine
	for _, file := range vaultsDataFile {
		saveData := new(SavedData)

		content, err := os.ReadFile(file.File)
		if err != nil {
			welp = fmt.Errorf("⚠ file to read from file(%s): %s", file, err)
			return
		}
		if err := json.Unmarshal(content, saveData); err != nil {
			welp = errors2.Wrapf(err, "⚠ invalid saveData format - is this an old backup file? (code: 1)")
			return
		}

		// phrase -> key
		aesKey32, err := bip39.EntropyFromMnemonic(file.Mnemonics)
		if err != nil {
			welp = fmt.Errorf("⚠ failed to generate key from mnemonic, are your words correct? %s", err)
			return
		}

		// decrypt the vaults into clear vaults
		for vID, resharesMap := range saveData.Vaults {
			// only look at the vault we're interested in, if one was supplied
			if !justListingVaults && vID != *vaultID {
				continue
			}

			// take the highest reshareNonce we have saved (best effort)
			lastReshareNonce := -1
			for nonce := range resharesMap {
				// support the -nonce flag to override the last reshare nonce we use
				if !justListingVaults && nonceOverride != nil && *nonceOverride > -1 && *nonceOverride != nonce {
					continue
				}
				if nonce > lastReshareNonce {
					lastReshareNonce = nonce
				}
			}
			if lastReshareNonce == -1 {
				//welp = fmt.Errorf("⚠ no share data found for vault `%s` in save file", vID)
				continue // not a show stopper
			}
			if glbLastReShareNonce, ok := vaultLastNonces[vID]; ok && glbLastReShareNonce != lastReshareNonce {
				fmt.Printf("\n⚠ Non matching reshare nonce for vault `%s`. You may have to specify prior reshare config with -nonce and -threshold when recovering that vault.\n", vID)
				if lastReshareNonce-1 >= 0 {
					fmt.Printf("⚠ If you have problems recovering that vault, you could try: -vault-id %s -nonce %d -threshold x. Replace x with previous vault threshold.\n", vID, lastReshareNonce-1)
				} else {
					println()
				}
			}
			vaultLastNonces[vID] = lastReshareNonce
			cipheredVault := resharesMap[lastReshareNonce]

			// DECRYPT
			aesNonce, err := hex.DecodeString(cipheredVault.CipherParams.IV)
			if err != nil {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (on nonce decode)", vID, err)
				return
			}
			aesTag, err := hex.DecodeString(cipheredVault.CipherParams.Tag)
			if err != nil {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (on tag decode)", vID, err)
				return
			}
			aesCT, err := base64.StdEncoding.DecodeString(cipheredVault.CipherTextB64)
			if err != nil {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (on ciphertext decode)", vID, err)
				return
			}

			// init AES-GCM cipher
			aesBlk, err := aes.NewCipher(aesKey32)
			if err != nil {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (on cipher init 1)", vID, err)
				return
			}
			aesGCM, err := cipher.NewGCM(aesBlk)
			if err != nil {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (on cipher init 2)", vID, err)
				return
			}

			// append the tag to the ciphertext, which is what golang's GCM implementation expects
			aesCT = append(aesCT, aesTag...)
			plainload, err := aesGCM.Open(nil, aesNonce, aesCT, nil)
			if err != nil {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (on decrypt)", vID, err)
				return
			}
			expHash := sha512.Sum512(plainload)
			if hex.EncodeToString(expHash[:]) != cipheredVault.Hash {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (hash mismatch)", vID, err)
				return
			}

			// decode vault from json
			clearVaults[vID] = new(ClearVault)
			if err = json.Unmarshal(plainload, clearVaults[vID]); err != nil {
				welp = errors2.Wrapf(err, "invalid saveData format - is this an old backup file? (code: 3)")
				return
			}
			clearVaults[vID].LastReShareNonce = lastReshareNonce

			// rack up the shares
			sharesECDSA, sharesEDDSA := clearVaults[vID].SharesLegacy, ([]string)(nil)
			if sharesECDSA == nil {
				for _, curve := range clearVaults[vID].Curves {
					if strings.ToUpper(curve.Algorithm) == "ECDSA" {
						sharesECDSA = curve.Shares
						//fmt.Printf("Processing new vault \"%s\" (ECDSA) (%s).\n", clearVaults[vID].Name, vID)
					} else if strings.ToUpper(curve.Algorithm) == "EDDSA" {
						sharesEDDSA = curve.Shares
						//fmt.Printf("Processing new vault \"%s\" (EdDSA) (%s).\n", clearVaults[vID].Name, vID)
					}
				}
			} else {
				// fmt.Printf("Processing legacy vault \"%s\" (%s).\n", clearVaults[vID].Name, vID)
			}

			// Build up shares lists
			// - Ensure that ECDSA shares were found.
			// - EdDSA shares may not be set for a legacy vault, so we won't catch that as a blocking issue
			vaultSharesECDSA, vaultSharesEDDSA := make([]*ecdsa_keygen.LocalPartySaveData, 0), make([]*eddsa_keygen.LocalPartySaveData, 0)
			// ECDSA
			if sharesECDSA == nil {
				welp = fmt.Errorf("no legacy or new shares found for vault %s %s", vID, clearVaults[vID].Name)
				return
			}
			if vaultSharesECDSA, welp = inflateSharesForCurve[ecdsa_keygen.LocalPartySaveData](sharesECDSA, justListingVaults); welp != nil {
				return
			}
			if _, ok := vaultAllSharesECDSA[vID]; !ok {
				vaultAllSharesECDSA[vID] = make([]*ecdsa_keygen.LocalPartySaveData, 0, len(sharesECDSA))
			}
			vaultAllSharesECDSA[vID] = append(vaultAllSharesECDSA[vID], vaultSharesECDSA...)
			// / ECDSA
			// EDDSA
			if sharesEDDSA != nil {
				if vaultSharesEDDSA, welp = inflateSharesForCurve[eddsa_keygen.LocalPartySaveData](sharesEDDSA, justListingVaults); welp != nil {
					return
				}
				if _, ok := vaultAllSharesEDDSA[vID]; !ok {
					vaultAllSharesEDDSA[vID] = make([]*eddsa_keygen.LocalPartySaveData, 0, len(sharesEDDSA))
					vaultHasEDDSA[vID] = true
				}
				vaultAllSharesEDDSA[vID] = append(vaultAllSharesEDDSA[vID], vaultSharesEDDSA...)
			}
			// / EDDSA
		}

		clear(aesKey32)
	}

	// populate vault IDs
	vaultIDs := make([]string, 0, len(vaultsDataFile)*16)
	for vID := range clearVaults {
		vaultIDs = append(vaultIDs, vID)
	}
	sort.Strings(vaultIDs)

	// Create the list of ordered vaults from the ordered vault IDs
	orderedVaults = make([]ui.VaultPickerItem, 0, len(vaultIDs))
	for _, vID := range vaultIDs {
		vault := clearVaults[vID]
		vaultFormData := ui.VaultPickerItem{VaultID: vID, Name: vault.Name, Quorum: vault.Quroum, NumberOfShares: len(vaultAllSharesECDSA[vID])}
		orderedVaults = append(orderedVaults, vaultFormData)
	}

	// Just list the ID's and names?
	if justListingVaults {
		return "", nil, nil, orderedVaults, nil
	}

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

	tPlus1 := clearVaults[*vaultID].Quroum
	if quorumOverride != nil && *quorumOverride > 0 {
		tPlus1 = *quorumOverride
	}
	vssSharesECDSA := make(vss.Shares, len(vaultAllSharesECDSA[*vaultID]))
	vssSharesEDDSA := make(vss.Shares, len(vaultAllSharesEDDSA[*vaultID]))
	if len(vaultAllSharesECDSA[*vaultID]) < tPlus1 {
		welp = fmt.Errorf("⚠ not enough shares to recover the key for vault %s (need %d, have %d)", *vaultID, tPlus1, len(vaultAllSharesECDSA[*vaultID]))
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
			fmt.Printf("NOTE: -password flag is required to export wallet v3 file `%s`. A wallet v3 file will not be created this time.\n\n", *exportKSFile)
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
			welp = fmt.Errorf("⚠ could not create the wallet v3 file json: %v", err2)
			return
		}

		if welp = os.WriteFile(*exportKSFile, keyfile, os.ModePerm); welp != nil {
			return
		}
		fmt.Printf("\nWrote a MetaMask wallet v3 (for ECDSA key only) to: %s.\n\n", *exportKSFile)
	}
	return address, ecdsaSK, eddsaSK, orderedVaults, nil
}

func inflateSharesForCurve[T SaveData](shares []string, justListingVaults bool) ([]*T, error) {
	shareDatas := make([]*T, len(shares))
	for j, strShare := range shares {
		// handle compressed "V2" format (ECDSA)
		hadPrefix := strings.HasPrefix(strShare, v2MagicPrefix)
		if hadPrefix {
			strShare = strings.TrimPrefix(strShare, v2MagicPrefix)
			expShareID, b64Part, found := strings.Cut(strShare, "_")
			if !found {
				err := errors.New("failed to split on share ID delim in V2 save data")
				return nil, err
			}
			deflated, err := base64.StdEncoding.DecodeString(b64Part)
			if err != nil {
				err2 := errors2.Wrapf(err, "failed to decode base64 part of V2 save data")
				return nil, err2
			}
			inflated, err := data.InflateSaveDataJSON(deflated)
			if err != nil {
				return nil, err
			}
			// shareID integrity check
			abridgedData := new(struct {
				ShareID *big.Int `json:"shareID"`
			})
			if err = json.Unmarshal(inflated, abridgedData); err != nil {
				err2 := errors2.Wrapf(err, "invalid data format - is this an old backup file? (code: 4)")
				return nil, err2
			}
			if abridgedData.ShareID.String() != expShareID {
				err = fmt.Errorf("share ID mismatch in V2 save data with ShareID %s", abridgedData.ShareID)
				return nil, err
			}
			strShare = string(inflated)

			// log deflated vs inflated sizes in KB
			if !justListingVaults {
				fmt.Printf("Processing V2 share %s.\t %.1f KB → %.1f KB\n",
					abridgedData.ShareID, float64(len(deflated))/1024, float64(len(inflated))/1024)
			}
		}
		// proceed with regular json unmarshal
		shareData := new(T)
		if err := json.Unmarshal([]byte(strShare), shareData); err != nil {
			err2 := errors2.Wrapf(err, "invalid data format - is this an old backup file? (code: 4)")
			return nil, err2
		}
		shareDatas[j] = shareData
	}
	return shareDatas, nil
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
