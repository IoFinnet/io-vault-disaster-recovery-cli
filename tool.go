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
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/data"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/dr"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/fileutils"
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

	justListingVaults := vaultID == nil || *vaultID == ""

	// Internal & returned data structures
	clearVaults := make(ClearVaultMap, len(vaultsDataFile)*16)
	vaultAllSharesECDSA := make(VaultAllSharesECDSA, len(vaultsDataFile)*16) // headroom
	vaultAllSharesEDDSA := make(VaultAllSharesEdDSA, len(vaultsDataFile)*16)
	vaultHasEDDSA := make(map[string]bool, len(vaultsDataFile)*16)
	// vaultLastLegacyNonces tracks disagreement across legacy flat-nonce JSON files only (a
	// nonce is never comparable to a request id, so it can't share a tracker with the below).
	vaultLastLegacyNonces := make(map[string]int, len(vaultsDataFile)*16)
	// vaultLastRequestIDs tracks disagreement across v4 JSON entries and the .dr chain's resolved
	// head for a vault, regardless of which of those two sources produced the value.
	vaultLastRequestIDs := make(map[string]string, len(vaultsDataFile)*16)
	// mobileVaults marks vaults that received shares from a v4/v5 mobile export; mobileFileThreshold
	// marks those whose mobile file actually carried a threshold (v5). Together they enforce the
	// rule that a mobile vault's threshold comes from its own file or the -threshold flag — NEVER
	// borrowed from a .dr file (checked at reconstruction).
	mobileVaults := make(map[string]bool, len(vaultsDataFile)*16)
	mobileFileThreshold := make(map[string]bool, len(vaultsDataFile)*16)
	// .dr files carry a previousRequestId chain pointer (unlike the legacy mnemonic-encrypted
	// JSON below, one .dr file is one device's shares for one specific epoch, keyed by
	// RequestId), so they're grouped by vault+requestId here and folded in below once every input
	// file has been seen, walking the chain to find each vault's current epoch.
	drSharesByVaultRequestID := make(map[string]map[string]*drVaultShares, len(vaultsDataFile))

	// // Do the main routine
	for _, file := range vaultsDataFile {
		if strings.EqualFold(filepath.Ext(file.File), ".dr") {
			if err := processDRFile(file.File, privateKeyPEM, vaultID, justListingVaults, drSharesByVaultRequestID); err != nil {
				welp = err
				return
			}
			continue
		}

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
		for vID, entry := range saveData.Vaults {
			// only look at the vault we're interested in, if one was supplied
			if !justListingVaults && vID != *vaultID {
				continue
			}

			var cipheredVault CipheredVault
			var lastRequestID string
			if entry.IsLegacy {
				// take the highest reshareNonce we have saved (best effort)
				nonces := make(map[int]bool, len(entry.LegacyByNonce))
				for nonce := range entry.LegacyByNonce {
					nonces[nonce] = true
				}
				lastReshareNonce := pickLastLegacyNonce(nonces, vID, clearVaults, nonceOverride, justListingVaults, vaultLastLegacyNonces)
				if lastReshareNonce == -1 {
					//welp = fmt.Errorf("⚠ no share data found for vault `%s` in save file", vID)
					continue // not a show stopper
				}
				cipheredVault = entry.LegacyByNonce[lastReshareNonce]
				lastRequestID = strconv.Itoa(lastReshareNonce)
			} else {
				// The exporter directly names the current request id; honor -request-id if it
				// asks for a different one this file doesn't have (not a show stopper - this
				// file simply doesn't contribute to this vault).
				requestID := entry.CurrentRequestID
				if !justListingVaults && requestIDOverride != nil && *requestIDOverride != "" {
					requestID = *requestIDOverride
				}
				cv, ok := entry.Requests[requestID]
				if !ok {
					continue // not a show stopper
				}
				cipheredVault = cv
				lastRequestID = requestID
				if welp = rejectOnRequestIDDisagreement(vID, lastRequestID, clearVaults, vaultLastRequestIDs); welp != nil {
					return
				}
			}

			// DECRYPT
			// iv/tag are hex in legacy exports and base64 in current ones; decode by
			// field length so either era recovers. See data.DecodeGcmField.
			aesNonce, err := data.DecodeGcmField(cipheredVault.CipherParams.IV, data.GcmIVBytes)
			if err != nil {
				welp = errors2.Errorf("⚠ failed to decrypt vault %s: %s (on nonce decode)", vID, err)
				return
			}
			aesTag, err := data.DecodeGcmField(cipheredVault.CipherParams.Tag, data.GcmTagBytes)
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

			if entry.IsLegacy {
				// Legacy flat-nonce JSON: the decrypted payload is a ClearVault object carrying the
				// vault name, threshold, and its shares as tss-lib "V2" JSON strings.
				clearVaults[vID] = new(ClearVault)
				if err = json.Unmarshal(plainload, clearVaults[vID]); err != nil {
					welp = errors2.Wrapf(err, "invalid saveData format - is this an old backup file? (code: 3)")
					return
				}
				clearVaults[vID].LastRequestID = lastRequestID

				// rack up the shares
				sharesECDSA, sharesEDDSA := clearVaults[vID].SharesLegacy, ([]string)(nil)
				if sharesECDSA == nil {
					for _, curve := range clearVaults[vID].Curves {
						if strings.ToUpper(curve.Algorithm) == "ECDSA" {
							sharesECDSA = curve.Shares
						} else if strings.ToUpper(curve.Algorithm) == "EDDSA" {
							sharesEDDSA = curve.Shares
						}
					}
				}

				// Build up shares lists
				// - Ensure that ECDSA shares were found.
				// - EdDSA shares may not be set for a legacy vault, so we won't catch that as a blocking issue
				var vaultSharesECDSA []*ecdsa_keygen.LocalPartySaveData
				var vaultSharesEDDSA []*eddsa_keygen.LocalPartySaveData
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
			} else {
				// v4/v5 mobile export: the decrypted payload is a mobile share payload — the v5
				// object {threshold, shares} or the legacy v4 bare shares array. Its opaque share
				// bytes decode to the SAME tss-lib save data as a .dr file, so they merge into the
				// same reconstruction. See dr.ParseMobileSharePayload.
				parsedMobile, err := dr.ParseMobileSharePayload(plainload)
				if err != nil {
					welp = errors2.Wrapf(err, "invalid saveData format - is this an old backup file? (code: 3)")
					return
				}
				if parsedMobile.VaultId != vID {
					welp = fmt.Errorf("⚠ mobile backup for vault %s at request %s carries mismatched embedded vault id %s", vID, lastRequestID, parsedMobile.VaultId)
					return
				}
				mobileVaults[vID] = true

				// Threshold is STRICTLY the mobile file's own (v5) or the -threshold flag; it is
				// never borrowed from a .dr file (enforced at reconstruction). A v5 payload's
				// threshold also cross-checks any other file's threshold for this vault via
				// ensureClearVaultThreshold (a mismatch is a hard error, not a silent pick).
				if parsedMobile.HasThreshold {
					if welp = ensureClearVaultThreshold(clearVaults, vID, parsedMobile.Threshold,
						fmt.Sprintf("mobile backup for vault %s at request %s", vID, lastRequestID)); welp != nil {
						return
					}
					mobileFileThreshold[vID] = true
				} else if _, ok := clearVaults[vID]; !ok {
					// Legacy v4 mobile with no threshold: register the vault so it still lists and can
					// reconstruct once a -threshold flag supplies the quorum.
					clearVaults[vID] = &ClearVault{Name: vID}
				}
				clearVaults[vID].LastRequestID = lastRequestID

				if len(parsedMobile.ECDSA) == 0 {
					welp = fmt.Errorf("no ECDSA shares found for vault %s in mobile backup", vID)
					return
				}
				vaultAllSharesECDSA[vID] = append(vaultAllSharesECDSA[vID], parsedMobile.ECDSA...)
				if parsedMobile.HasEdDSA {
					vaultAllSharesEDDSA[vID] = append(vaultAllSharesEDDSA[vID], parsedMobile.EdDSA...)
					vaultHasEDDSA[vID] = true
				}
			}
		}

		clear(aesKey32)
	}

	// Fold in the .dr shares accumulated above: for each vault, walk the previousRequestId chain
	// (or honor a -request-id override) to find its current epoch, warning on disagreement with
	// whatever the legacy/v4 JSON path already picked for that vault, then merge that epoch's
	// shares into the same pools used by the legacy path so a single recovery run can mix both
	// file formats for a vault.
	for vID, byRequestID := range drSharesByVaultRequestID {
		requestID, err := pickLatestDRRequestID(byRequestID, vID, requestIDOverride, justListingVaults)
		if err != nil {
			welp = err
			return
		}
		if requestID == "" {
			continue
		}
		chosen := byRequestID[requestID]
		if welp = rejectOnRequestIDDisagreement(vID, requestID, clearVaults, vaultLastRequestIDs); welp != nil {
			return
		}
		if err := ensureClearVaultThreshold(clearVaults, vID, chosen.threshold,
			fmt.Sprintf(".dr files for vault %s at request %s", vID, requestID)); err != nil {
			welp = err
			return
		}
		vaultAllSharesECDSA[vID] = append(vaultAllSharesECDSA[vID], chosen.ecdsa...)
		if chosen.hasEdDSA {
			vaultAllSharesEDDSA[vID] = append(vaultAllSharesEDDSA[vID], chosen.eddsa...)
			vaultHasEDDSA[vID] = true
		}
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
		return "", nil, nil, orderedVaults, nil, nil
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

// processDRFile decrypts a Virtual Signer .dr file and folds its shares into the same per-vault
// share pools the legacy mnemonic-encrypted path populates, so a single recovery run can mix both
// file formats for the same vault.
func processDRFile(path string, privateKeyPEM []byte, vaultID *string, justListingVaults bool,
	drSharesByVaultRequestID map[string]map[string]*drVaultShares) error {

	if len(privateKeyPEM) == 0 {
		return fmt.Errorf("⚠ %s is a Virtual Signer .dr file; use -private-key to supply the ML-KEM-768 private key PEM", path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("⚠ failed to read file(%s): %s", path, err)
	}

	parsed, err := dr.DecryptAndParse(privateKeyPEM, raw)
	if err != nil {
		return fmt.Errorf("⚠ failed to decrypt %s: %s", path, err)
	}

	// The reconstructed vault ID and threshold come from the decrypted (AEAD-authenticated)
	// payload, not the plaintext envelope fields, since the latter aren't tamper-evident.
	var vID string
	var threshold int
	switch parsed.Kind {
	case dr.KindECDSA:
		vID, threshold = parsed.ECDSA.VaultId, parsed.ECDSA.Threshold
	case dr.KindEdDSA:
		vID, threshold = parsed.EdDSA.VaultId, parsed.EdDSA.Threshold
	}

	// only look at the vault we're interested in, if one was supplied
	if !justListingVaults && vID != *vaultID {
		return nil
	}
	if threshold < 1 {
		return fmt.Errorf("⚠ %s does not carry a valid threshold", path)
	}

	requestID := parsed.Envelope.RequestId
	if requestID == "" {
		return fmt.Errorf("⚠ %s does not carry a requestId", path)
	}
	byRequestID, ok := drSharesByVaultRequestID[vID]
	if !ok {
		byRequestID = make(map[string]*drVaultShares)
		drSharesByVaultRequestID[vID] = byRequestID
	}
	entry, ok := byRequestID[requestID]
	if !ok {
		entry = &drVaultShares{threshold: threshold, previousRequestId: parsed.Envelope.PreviousRequestId}
		byRequestID[requestID] = entry
	} else if entry.threshold != threshold {
		return fmt.Errorf("⚠ %s: threshold %d disagrees with another .dr file at the same request %s for vault %s (%d)",
			path, threshold, requestID, vID, entry.threshold)
	} else if entry.previousRequestId != parsed.Envelope.PreviousRequestId {
		return fmt.Errorf("⚠ %s: previous request id %q disagrees with another .dr file at the same request %s for vault %s (%q)",
			path, parsed.Envelope.PreviousRequestId, requestID, vID, entry.previousRequestId)
	}

	switch parsed.Kind {
	case dr.KindECDSA:
		shares, err := parsed.ECDSA.ToECDSASaveData()
		if err != nil {
			return fmt.Errorf("⚠ %s: %s", path, err)
		}
		entry.ecdsa = append(entry.ecdsa, shares...)
	case dr.KindEdDSA:
		shares, err := parsed.EdDSA.ToEdDSASaveData()
		if err != nil {
			return fmt.Errorf("⚠ %s: %s", path, err)
		}
		entry.eddsa = append(entry.eddsa, shares...)
		entry.hasEdDSA = true
	}
	return nil
}

// pickLastLegacyNonce selects the reshare nonce to use for a vault from the set of nonces found
// in one legacy flat-nonce JSON file (honoring the -nonce override), warning if it disagrees with
// the nonce already picked for this vault from another legacy file. Returns -1 if no nonce
// survives the override filter.
func pickLastLegacyNonce(nonces map[int]bool, vID string, clearVaults ClearVaultMap, nonceOverride *int,
	justListingVaults bool, vaultLastLegacyNonces map[string]int) int {

	lastReshareNonce := -1
	for nonce := range nonces {
		// support the -nonce flag to override the last reshare nonce we use
		if !justListingVaults && nonceOverride != nil && *nonceOverride > -1 && *nonceOverride != nonce {
			continue
		}
		if nonce > lastReshareNonce {
			lastReshareNonce = nonce
		}
	}
	if lastReshareNonce == -1 {
		return -1
	}
	if glbLastReShareNonce, ok := vaultLastLegacyNonces[vID]; ok && glbLastReShareNonce != lastReshareNonce {
		vaultName := vID
		if cv, ok2 := clearVaults[vID]; ok2 && cv != nil {
			vaultName = cv.Name
		}
		fmt.Println(ui.PlainTextf("\n⚠ Non matching reshare nonce for vault `%s`. You may have to specify prior reshare config with -nonce and -threshold when recovering that vault", vaultName))
		if lastReshareNonce-1 >= 0 {
			fmt.Println(ui.PlainTextf("⚠ If you have problems recovering that vault, you could try: -vault-id %s -nonce %d -threshold x. Replace x with previous vault threshold.", vID, lastReshareNonce-1))
		} else {
			println()
		}
	}
	vaultLastLegacyNonces[vID] = lastReshareNonce
	return lastReshareNonce
}

// pickLatestDRRequestID selects the current epoch's request id for a vault from its .dr files, by
// walking the previousRequestId chain built by processDRFile: the request id in byRequestID that
// is not referenced as any other entry's previousRequestId is the head (most recent) epoch.
// Honors the -request-id override, used directly instead of chain-walking.
//
// Unlike a legacy reshare nonce (where "highest wins" is always well-defined even amid
// disagreement across files), an ambiguous chain has no safe fallback: if more than one .dr file
// is genuinely current we should return -1 (skip). If !justListingVaults, an ambiguous chain
// without an override is a hard error rather than a guess, since a wrong guess here reconstructs
// the wrong key. During listing (no vault selected yet), ambiguity is tolerated with a best-effort
// pick, since nothing here yet influences key reconstruction.
func pickLatestDRRequestID(byRequestID map[string]*drVaultShares, vID string, requestIDOverride *string, justListingVaults bool) (string, error) {
	if !justListingVaults && requestIDOverride != nil && *requestIDOverride != "" {
		if _, ok := byRequestID[*requestIDOverride]; !ok {
			return "", nil // not a show stopper: this vault has no .dr shares matching the override
		}
		return *requestIDOverride, nil
	}

	referenced := make(map[string]bool, len(byRequestID))
	for _, entry := range byRequestID {
		if entry.previousRequestId != "" {
			referenced[entry.previousRequestId] = true
		}
	}
	var head string
	heads := 0
	for requestID := range byRequestID {
		if !referenced[requestID] {
			head = requestID
			heads++
		}
	}
	if heads == 1 || justListingVaults {
		return head, nil
	}
	return "", fmt.Errorf("⚠ vault %s: found %d root epoch(s) among its .dr files' previousRequestId chain (expected exactly 1); specify -request-id to disambiguate", vID, heads)
}

// rejectOnRequestIDDisagreement records vID's chosen request id and errors out if it disagrees
// with the request id already recorded for vID from a previously-processed v4 JSON entry or the
// .dr chain's resolved head: mixing shares from two different reshare epochs into one
// reconstruction pool would silently produce a wrong key, so this must be a hard error rather
// than a warning. Tracked separately from the legacy nonce disagreement warning in
// pickLastLegacyNonce, since a nonce and a request id are never comparable.
func rejectOnRequestIDDisagreement(vID, requestID string, clearVaults ClearVaultMap, vaultLastRequestIDs map[string]string) error {
	if glbRequestID, ok := vaultLastRequestIDs[vID]; ok && glbRequestID != requestID {
		vaultName := vID
		if cv, ok2 := clearVaults[vID]; ok2 && cv != nil {
			vaultName = cv.Name
		}
		return fmt.Errorf("⚠ non matching current request id for vault `%s` (%s vs %s). Specify -request-id and -threshold to disambiguate", vaultName, glbRequestID, requestID)
	}
	vaultLastRequestIDs[vID] = requestID
	return nil
}

// ensureClearVaultThreshold makes sure a ClearVault entry exists for a vault first seen via a .dr
// file (which carries no vault Name, only a VaultId), and errors out if a .dr file's threshold
// disagrees with a threshold already established for this vault from another input file.
func ensureClearVaultThreshold(clearVaults ClearVaultMap, vID string, threshold int, path string) error {
	if threshold < 1 {
		return fmt.Errorf("⚠ %s does not carry a valid threshold", path)
	}
	existing, ok := clearVaults[vID]
	if !ok {
		clearVaults[vID] = &ClearVault{Name: vID, Quroum: threshold}
		return nil
	}
	if existing.Quroum != 0 && existing.Quroum != threshold {
		return fmt.Errorf("⚠ vault %s: threshold mismatch between input files (%d vs %d). "+
			"Make sure all supplied files are from the same vault epoch", vID, existing.Quroum, threshold)
	}
	existing.Quroum = threshold
	return nil
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
