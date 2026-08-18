// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/dr"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/vss"
	ecdsa_keygen "github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip39"
)

// --- .dr file fixture helpers -----------------------------------------------------------------

// encryptDRForTest encrypts plaintext into the .dr wire format with the given ML-KEM-768 public
// key, mirroring the Virtual Signer's EncryptingMarshallerForDR envelope.
func encryptDRForTest(t *testing.T, pub *mlkem.EncapsulationKey768, plaintext []byte) []byte {
	t.Helper()
	sharedSecret, cipherTextKEM := pub.Encapsulate()
	blk, err := aes.NewCipher(sharedSecret)
	require.NoError(t, err)
	aesGCM, err := cipher.NewGCM(blk)
	require.NoError(t, err)
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	require.NoError(t, err)
	sealed := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return append(cipherTextKEM, sealed...)
}

// writeDRFile JSON-marshals payload, encrypts it, wraps it in a dr.FileEnvelope (meta's
// plaintext fields plus the resulting base64 ciphertext as DataB64), and writes it as a .dr file
// under dir/name. Returns the file's path.
func writeDRFile(t *testing.T, dir, name string, pub *mlkem.EncapsulationKey768, meta dr.FileEnvelope, payload any) string {
	t.Helper()
	plaintext, err := json.Marshal(payload)
	require.NoError(t, err)
	ciphertext := encryptDRForTest(t, pub, plaintext)
	meta.DataB64 = base64.StdEncoding.EncodeToString(ciphertext)
	content, err := json.Marshal(meta)
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

func ecPointMirror(curveName string, p *crypto.ECPoint) *dr.ECPoint {
	return &dr.ECPoint{Curve: curveName, Coords: [2]*big.Int{p.X(), p.Y()}}
}

// makeVSSShares creates n real Shamir/Feldman VSS shares of a random secret over ec, requiring
// `threshold` of them to reconstruct (i.e. polynomial degree threshold-1), plus the public key.
func makeVSSShares(t *testing.T, ec elliptic.Curve, threshold, n int) (secret *big.Int, pub *crypto.ECPoint, shares vss.Shares) {
	t.Helper()
	sec, err := rand.Int(rand.Reader, ec.Params().N)
	require.NoError(t, err)
	require.NotZero(t, sec.Sign())

	indexes := make([]*big.Int, n)
	for i := range indexes {
		indexes[i] = big.NewInt(int64(i + 1))
	}
	v, s, err := vss.Create(ec, threshold-1, sec, indexes)
	require.NoError(t, err)
	return sec, v[0], s
}

func makeVSSSharesS256(t *testing.T, threshold, n int) (*big.Int, *crypto.ECPoint, vss.Shares) {
	return makeVSSShares(t, tss.S256(), threshold, n)
}

func makeVSSSharesEdwards(t *testing.T, threshold, n int) (*big.Int, *crypto.ECPoint, vss.Shares) {
	return makeVSSShares(t, tss.Edwards(), threshold, n)
}

// --- legacy (mnemonic-encrypted) fixture helper, for the mixed-format test -------------------

// writeLegacyVaultFile builds a legacy-format SavedData JSON file (AES-256-GCM, mnemonic-derived
// key) carrying the given ECDSA shares for one vault/nonce, and returns its path. The "vaults"
// map is built as raw JSON (rather than via the VaultEntry Go type, which only implements
// UnmarshalJSON - production code never needs to WRITE the legacy flat-nonce shape, only read
// already-existing exports in it) so this helper faithfully reproduces that on-disk shape:
// {"vaults": {vaultID: {"<nonce>": {ciphertext...}}}}.
func writeLegacyVaultFile(t *testing.T, dir, name, mnemonic, vaultID string, nonce, threshold int, ecdsaShareJSONs []string) string {
	t.Helper()

	clearVault := ClearVault{
		Name:   "mixed-format-test-vault",
		Quroum: threshold,
		Curves: []ClearVaultCurve{{Algorithm: "ECDSA", Shares: ecdsaShareJSONs}},
	}
	plaintext, err := json.Marshal(clearVault)
	require.NoError(t, err)

	aesKey32, err := bip39.EntropyFromMnemonic(mnemonic)
	require.NoError(t, err)

	blk, err := aes.NewCipher(aesKey32)
	require.NoError(t, err)
	aesGCM, err := cipher.NewGCM(blk)
	require.NoError(t, err)
	nonceBz := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonceBz)
	require.NoError(t, err)
	sealed := aesGCM.Seal(nil, nonceBz, plaintext, nil)
	ctLen := len(sealed) - aesGCM.Overhead()
	ciphertext, tag := sealed[:ctLen], sealed[ctLen:]

	hash := sha512.Sum512(plaintext)

	cipheredVault := CipheredVault{
		CipherTextB64: base64.StdEncoding.EncodeToString(ciphertext),
		CipherParams:  CipherParams{IV: hex.EncodeToString(nonceBz), Tag: hex.EncodeToString(tag)},
		Cipher:        "aes-256-gcm",
		Hash:          hex.EncodeToString(hash[:]),
	}
	rawSavedData := map[string]any{
		"vaults": map[string]any{
			vaultID: map[string]any{
				fmt.Sprintf("%d", nonce): cipheredVault,
			},
		},
	}
	content, err := json.Marshal(rawSavedData)
	require.NoError(t, err)

	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

// mobileRequestFixture is one epoch's worth of a mobile export's shares for one requestId. The
// ecdsa/eddsa payloads are the SAME dr.*SharesAndVaultId structs a .dr file carries (the mobile
// native SDK marshals the identical Go type). `threshold` > 0 emits the v5 wrapped payload
// {threshold, shares}; threshold == 0 emits the legacy v4 bare shares array (no threshold).
type mobileRequestFixture struct {
	threshold int
	ecdsa     *dr.ECDSASharesAndVaultId
	eddsa     *dr.EdDSASharesAndVaultId // optional
}

// writeMobileVaultFile builds a mobile-format SavedData JSON file: {"vaults": {vaultID:
// {"currentRequestId": ..., "requests": {requestID: {ciphertext...}}}}}, mirroring
// lib/backup-export/create-backup-object.ts. Each request's decrypted payload is the v5 object
// {threshold, shares:[{algorithm,curve,data}]} (or the legacy v4 bare shares array when threshold
// is 0), where each share's `data` is base64 of a dr.*SharesAndVaultId JSON. iv/tag are base64,
// as current-era (expo-crypto) exports produce.
func writeMobileVaultFile(t *testing.T, dir, name, mnemonic, vaultID, currentRequestID string, requests map[string]mobileRequestFixture) string {
	t.Helper()

	aesKey32, err := bip39.EntropyFromMnemonic(mnemonic)
	require.NoError(t, err)

	requestsJSON := map[string]any{}
	for requestID, r := range requests {
		ecdsaData, err := json.Marshal(r.ecdsa)
		require.NoError(t, err)
		shares := []map[string]any{
			{"algorithm": "ECDSA", "curve": "Secp256k1", "data": base64.StdEncoding.EncodeToString(ecdsaData)},
		}
		if r.eddsa != nil {
			eddsaData, err := json.Marshal(r.eddsa)
			require.NoError(t, err)
			shares = append(shares, map[string]any{"algorithm": "EDDSA", "curve": "Edwards", "data": base64.StdEncoding.EncodeToString(eddsaData)})
		}

		// threshold > 0 → v5 wrapped object; threshold == 0 → legacy v4 bare array.
		var payload any = shares
		if r.threshold > 0 {
			payload = map[string]any{"threshold": r.threshold, "shares": shares}
		}
		plaintext, err := json.Marshal(payload)
		require.NoError(t, err)

		blk, err := aes.NewCipher(aesKey32)
		require.NoError(t, err)
		aesGCM, err := cipher.NewGCM(blk)
		require.NoError(t, err)
		nonceBz := make([]byte, aesGCM.NonceSize())
		_, err = io.ReadFull(rand.Reader, nonceBz)
		require.NoError(t, err)
		sealed := aesGCM.Seal(nil, nonceBz, plaintext, nil)
		ctLen := len(sealed) - aesGCM.Overhead()
		ciphertext, tag := sealed[:ctLen], sealed[ctLen:]
		hash := sha512.Sum512(plaintext)

		requestsJSON[requestID] = CipheredVault{
			CipherTextB64: base64.StdEncoding.EncodeToString(ciphertext),
			CipherParams: CipherParams{
				IV:  base64.StdEncoding.EncodeToString(nonceBz),
				Tag: base64.StdEncoding.EncodeToString(tag),
			},
			Cipher: "aes-256-gcm",
			Hash:   hex.EncodeToString(hash[:]),
		}
	}

	rawSavedData := map[string]any{
		"vaults": map[string]any{
			vaultID: map[string]any{
				"currentRequestId": currentRequestID,
				"requests":         requestsJSON,
			},
		},
	}
	content, err := json.Marshal(rawSavedData)
	require.NoError(t, err)

	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

// mobileECDSAPayload builds the ECDSA half of a mobile request from a VSS share + pubkey.
func mobileECDSAPayload(vaultID string, share *vss.Share, pub *crypto.ECPoint) *dr.ECDSASharesAndVaultId {
	return &dr.ECDSASharesAndVaultId{
		Data:    []*dr.ECDSAShare{{Xi: share.Share, ShareID: share.ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
		VaultId: vaultID,
	}
}

// mobileEdDSAPayload builds the EdDSA half of a mobile request from a VSS share + pubkey.
func mobileEdDSAPayload(vaultID string, share *vss.Share, pub *crypto.ECPoint) *dr.EdDSASharesAndVaultId {
	return &dr.EdDSASharesAndVaultId{
		Data:    []*dr.EdDSAShare{{Xi: share.Share, ShareID: share.ID, EDDSAPub: ecPointMirror("ed25519", pub)}},
		VaultId: vaultID,
	}
}

// oidMLKEM768Test is the ML-KEM-768 algorithm identifier (RFC 9935 / NIST CSOR
// 2.16.840.1.101.3.4.4.2) used to wrap generated seeds in the standard
// PKCS#8 PrivateKeyInfo DER structure that OpenSSL 3.5+ and current
// key-generation tooling produce.
var oidMLKEM768Test = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}

func genMLKEMKeyPEM(t *testing.T) (priv *mlkem.DecapsulationKey768, privPEM []byte) {
	t.Helper()
	priv, err := mlkem.GenerateKey768()
	require.NoError(t, err)

	der, err := asn1.Marshal(struct {
		Version    int
		Algo       struct{ Algorithm asn1.ObjectIdentifier }
		PrivateKey []byte
	}{
		Algo:       struct{ Algorithm asn1.ObjectIdentifier }{oidMLKEM768Test},
		PrivateKey: priv.Bytes(),
	})
	require.NoError(t, err)
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return priv, privPEM
}

// --- tests -------------------------------------------------------------------------------------

func TestTool_DR_ECDSA_And_EdDSA_Recovery(t *testing.T) {
	dirTmp := t.TempDir()
	priv, privPEM := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-1"
	const threshold, n = 2, 3

	ecdsaSecret, ecdsaPub, ecdsaShares := makeVSSSharesS256(t, threshold, n)
	eddsaSecret, eddsaPub, eddsaShares := makeVSSSharesEdwards(t, threshold, n)

	// All n devices' shares are for the SAME keygen ceremony, so they share one RequestId
	// (mirroring real VS output, where requestId is the ceremony's id, shared by every
	// participating device) - grouping is by requestId now, not by an arbitrary per-file value.
	const requestID = "keygen-1"

	var files []ui.VaultsDataFile
	for i := 0; i < n; i++ {
		payload := &dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: ecdsaShares[i].Share, ShareID: ecdsaShares[i].ID, ECDSAPub: ecPointMirror("secp256k1", ecdsaPub)}},
			VaultId:   vaultID,
			Threshold: threshold,
		}
		meta := dr.FileEnvelope{VaultId: vaultID, RequestId: requestID, Algo: "ECDSA", Curve: "secp256k1"}
		path := writeDRFile(t, dirTmp, fmt.Sprintf("device%d.ecdsa.secp256k1.dr", i), priv.EncapsulationKey(), meta, payload)
		files = append(files, ui.VaultsDataFile{File: path})
	}
	for i := 0; i < n; i++ {
		payload := &dr.EdDSASharesAndVaultId{
			Data:      []*dr.EdDSAShare{{Xi: eddsaShares[i].Share, ShareID: eddsaShares[i].ID, EDDSAPub: ecPointMirror("ed25519", eddsaPub)}},
			VaultId:   vaultID,
			Threshold: threshold,
		}
		meta := dr.FileEnvelope{VaultId: vaultID, RequestId: requestID, Algo: "EDDSA", Curve: "ed25519"}
		path := writeDRFile(t, dirTmp, fmt.Sprintf("device%d.eddsa.ed25519.dr", i), priv.EncapsulationKey(), meta, payload)
		files = append(files, ui.VaultsDataFile{File: path})
	}

	address, ecSK, edSK, vaultsFormData, _, err := runTool(files, &vaultID, nil, nil, nil, nil, nil, privPEM)
	require.NoError(t, err)
	require.Len(t, vaultsFormData, 1)
	require.Equal(t, vaultID, vaultsFormData[0].VaultID)
	require.Equal(t, threshold, vaultsFormData[0].Quorum)

	_, expectedAddress, err := getTSSPubKeyForEthereum(ecdsaPub.X(), ecdsaPub.Y())
	require.NoError(t, err)
	require.Equal(t, expectedAddress, address)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(ecdsaSecret)), hex.EncodeToString(ecSK))
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(eddsaSecret)), hex.EncodeToString(edSK))
}

func TestTool_DR_ThresholdMismatch(t *testing.T) {
	dirTmp := t.TempDir()
	priv, privPEM := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-mismatch"

	_, pub, shares := makeVSSSharesS256(t, 2, 3)

	// Two devices' shares for the SAME ceremony (shared RequestId) disagreeing on threshold - a
	// tampered/corrupt file, since real devices of one ceremony always agree.
	path1 := writeDRFile(t, dirTmp, "device0.ecdsa.secp256k1.dr", priv.EncapsulationKey(),
		dr.FileEnvelope{VaultId: vaultID, RequestId: "keygen-mismatch", Algo: "ECDSA", Curve: "secp256k1"},
		&dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[0].Share, ShareID: shares[0].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   vaultID,
			Threshold: 2,
		})
	path2 := writeDRFile(t, dirTmp, "device1.ecdsa.secp256k1.dr", priv.EncapsulationKey(),
		dr.FileEnvelope{VaultId: vaultID, RequestId: "keygen-mismatch", Algo: "ECDSA", Curve: "secp256k1"},
		&dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[1].Share, ShareID: shares[1].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   vaultID,
			Threshold: 3, // deliberately different
		})

	files := []ui.VaultsDataFile{{File: path1}, {File: path2}}
	_, _, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, nil, privPEM)
	require.Error(t, err)
	require.Contains(t, err.Error(), "disagrees with another .dr file")
}

func TestTool_DR_MissingPrivateKey(t *testing.T) {
	dirTmp := t.TempDir()
	priv, _ := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-nokey"

	_, pub, shares := makeVSSSharesS256(t, 2, 2)
	path := writeDRFile(t, dirTmp, "req0.ecdsa.secp256k1.dr", priv.EncapsulationKey(),
		dr.FileEnvelope{VaultId: vaultID, RequestId: "req0", Algo: "ECDSA", Curve: "secp256k1"},
		&dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[0].Share, ShareID: shares[0].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   vaultID,
			Threshold: 2,
		})

	files := []ui.VaultsDataFile{{File: path}}
	_, _, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "-private-key")
}

func TestTool_DR_WrongPrivateKey(t *testing.T) {
	dirTmp := t.TempDir()
	priv, _ := genMLKEMKeyPEM(t)
	_, wrongPEM := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-wrongkey"

	_, pub, shares := makeVSSSharesS256(t, 2, 2)
	path := writeDRFile(t, dirTmp, "req0.ecdsa.secp256k1.dr", priv.EncapsulationKey(),
		dr.FileEnvelope{VaultId: vaultID, RequestId: "req0", Algo: "ECDSA", Curve: "secp256k1"},
		&dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[0].Share, ShareID: shares[0].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   vaultID,
			Threshold: 2,
		})

	files := []ui.VaultsDataFile{{File: path}}
	_, _, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, nil, wrongPEM)
	require.Error(t, err)
}

func TestTool_DR_MixedWithLegacy(t *testing.T) {
	dirTmp := t.TempDir()
	priv, privPEM := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-mixed"
	const threshold, n = 2, 2 // one share from legacy, one from .dr

	secret, pub, shares := makeVSSSharesS256(t, threshold, n)

	// Share 0 goes into a legacy mnemonic-encrypted vault file (flat nonce-keyed shape - the
	// legacy path and the .dr path resolve their "current epoch" completely independently of
	// each other, so this doesn't need to "match" the .dr file's identifier in any way).
	legacyShareData := &ecdsa_keygen.LocalPartySaveData{
		LocalSecrets: ecdsa_keygen.LocalSecrets{Xi: shares[0].Share, ShareID: shares[0].ID},
		ECDSAPub:     pub,
	}
	legacyShareJSON, err := json.Marshal(legacyShareData)
	require.NoError(t, err)
	legacyPath := writeLegacyVaultFile(t, dirTmp, "legacy.json", mmI, vaultID, 0, threshold, []string{string(legacyShareJSON)})

	// Share 1 goes into a .dr file - the vault's only (keygen-originated) .dr epoch.
	drPath := writeDRFile(t, dirTmp, "req0.ecdsa.secp256k1.dr", priv.EncapsulationKey(),
		dr.FileEnvelope{VaultId: vaultID, RequestId: "req0", Algo: "ECDSA", Curve: "secp256k1"},
		&dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[1].Share, ShareID: shares[1].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   vaultID,
			Threshold: threshold,
		})

	files := []ui.VaultsDataFile{
		{File: legacyPath, Mnemonics: mmI},
		{File: drPath},
	}
	address, ecSK, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, nil, privPEM)
	require.NoError(t, err)

	_, expectedAddress, err := getTSSPubKeyForEthereum(pub.X(), pub.Y())
	require.NoError(t, err)
	require.Equal(t, expectedAddress, address)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secret)), hex.EncodeToString(ecSK))
}

// TestTool_V5MobileJSON_Recovery recovers from v5 mobile backups whose decrypted payload is the
// {threshold, shares:[{algorithm,curve,data}]} object with opaque dr-format share bytes.
func TestTool_V5MobileJSON_Recovery(t *testing.T) {
	dirTmp := t.TempDir()
	vaultID := "v5-test-vault"
	const threshold, n = 2, 2
	const requestID = "keygen-v5-1"

	secret, pub, shares := makeVSSSharesS256(t, threshold, n)

	var files []ui.VaultsDataFile
	for i := 0; i < n; i++ {
		path := writeMobileVaultFile(t, dirTmp, fmt.Sprintf("device%d.json", i), mmI, vaultID, requestID,
			map[string]mobileRequestFixture{requestID: {threshold: threshold, ecdsa: mobileECDSAPayload(vaultID, shares[i], pub)}})
		files = append(files, ui.VaultsDataFile{File: path, Mnemonics: mmI})
	}

	address, ecSK, _, vaultsFormData, _, err := runTool(files, &vaultID, nil, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	require.Len(t, vaultsFormData, 1)
	require.Equal(t, vaultID, vaultsFormData[0].VaultID)
	require.Equal(t, threshold, vaultsFormData[0].Quorum) // threshold came from the v5 file

	_, expectedAddress, err := getTSSPubKeyForEthereum(pub.X(), pub.Y())
	require.NoError(t, err)
	require.Equal(t, expectedAddress, address)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secret)), hex.EncodeToString(ecSK))
}

// TestTool_V5MobileJSON_ECDSAAndEdDSA recovers a v5 mobile vault carrying both curves.
func TestTool_V5MobileJSON_ECDSAAndEdDSA(t *testing.T) {
	dirTmp := t.TempDir()
	vaultID := "v5-test-vault-mixed-curves"
	const threshold, n = 2, 2
	const requestID = "keygen-v5-mixed"

	ecSecret, ecPub, ecShares := makeVSSSharesS256(t, threshold, n)
	edSecret, edPub, edShares := makeVSSSharesEdwards(t, threshold, n)

	var files []ui.VaultsDataFile
	for i := 0; i < n; i++ {
		path := writeMobileVaultFile(t, dirTmp, fmt.Sprintf("device%d.json", i), mmI, vaultID, requestID,
			map[string]mobileRequestFixture{requestID: {
				threshold: threshold,
				ecdsa:     mobileECDSAPayload(vaultID, ecShares[i], ecPub),
				eddsa:     mobileEdDSAPayload(vaultID, edShares[i], edPub),
			}})
		files = append(files, ui.VaultsDataFile{File: path, Mnemonics: mmI})
	}

	address, ecSK, edSK, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, nil, nil)
	require.NoError(t, err)

	_, expectedAddress, err := getTSSPubKeyForEthereum(ecPub.X(), ecPub.Y())
	require.NoError(t, err)
	require.Equal(t, expectedAddress, address)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(ecSecret)), hex.EncodeToString(ecSK))
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(edSecret)), hex.EncodeToString(edSK))
}

// TestTool_V5MobileJSON_PerEpochThreshold verifies each epoch reconstructs with ITS OWN threshold
// from its own payload: two epochs with different thresholds/secrets, selected via -request-id.
func TestTool_V5MobileJSON_PerEpochThreshold(t *testing.T) {
	dirTmp := t.TempDir()
	vaultID := "v5-test-vault-epochs"
	const reqA, reqB = "epoch-a", "epoch-b"
	// Epoch A: threshold 2. Epoch B (current): threshold 3. Different secrets. Provide 3 devices so
	// both epochs have enough shares.
	const n = 3
	secretA, pubA, sharesA := makeVSSSharesS256(t, 2, n)
	secretB, pubB, sharesB := makeVSSSharesS256(t, 3, n)
	require.NotEqual(t, secretA.String(), secretB.String())

	var files []ui.VaultsDataFile
	for i := 0; i < n; i++ {
		path := writeMobileVaultFile(t, dirTmp, fmt.Sprintf("device%d.json", i), mmI, vaultID, reqB,
			map[string]mobileRequestFixture{
				reqA: {threshold: 2, ecdsa: mobileECDSAPayload(vaultID, sharesA[i], pubA)},
				reqB: {threshold: 3, ecdsa: mobileECDSAPayload(vaultID, sharesB[i], pubB)},
			})
		files = append(files, ui.VaultsDataFile{File: path, Mnemonics: mmI})
	}

	// Default (currentRequestId = epoch B): reconstructs secretB with epoch B's threshold (3).
	_, ecSK, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secretB)), hex.EncodeToString(ecSK))

	// -request-id epoch A: reconstructs secretA with epoch A's threshold (2), proving the threshold
	// tracks the chosen epoch's own payload, not a single vault-wide value.
	reqAOverride := reqA
	_, ecSKA, _, _, _, err := runTool(files, &vaultID, nil, &reqAOverride, nil, nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secretA)), hex.EncodeToString(ecSKA))
}

// TestTool_V4MobileJSON_NoThreshold_RequiresFlag covers legacy v4 mobile backups (bare shares
// array, no threshold): recovery must fail without -threshold and succeed with it — never
// borrowing a threshold from elsewhere.
func TestTool_V4MobileJSON_NoThreshold_RequiresFlag(t *testing.T) {
	dirTmp := t.TempDir()
	vaultID := "v4-legacy-test-vault"
	const threshold, n = 2, 2
	const requestID = "keygen-v4-legacy"

	secret, pub, shares := makeVSSSharesS256(t, threshold, n)

	var files []ui.VaultsDataFile
	for i := 0; i < n; i++ {
		// threshold: 0 → emit the legacy v4 bare shares array with no threshold.
		path := writeMobileVaultFile(t, dirTmp, fmt.Sprintf("device%d.json", i), mmI, vaultID, requestID,
			map[string]mobileRequestFixture{requestID: {threshold: 0, ecdsa: mobileECDSAPayload(vaultID, shares[i], pub)}})
		files = append(files, ui.VaultsDataFile{File: path, Mnemonics: mmI})
	}

	// No -threshold → hard error (no threshold in file, none supplied).
	_, _, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no threshold")

	// With -threshold → recovers correctly.
	quorum := threshold
	address, ecSK, _, _, _, err := runTool(files, &vaultID, nil, nil, &quorum, nil, nil, nil)
	require.NoError(t, err)
	_, expectedAddress, err := getTSSPubKeyForEthereum(pub.X(), pub.Y())
	require.NoError(t, err)
	require.Equal(t, expectedAddress, address)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secret)), hex.EncodeToString(ecSK))
}

// TestTool_V5MobileJSON_ThresholdMismatch: two files for the same vault/epoch disagreeing on the
// v5 threshold is a hard error (a tampered/corrupt file), not a silent pick.
func TestTool_V5MobileJSON_ThresholdMismatch(t *testing.T) {
	dirTmp := t.TempDir()
	vaultID := "v5-test-vault-mismatch"
	const n = 2
	const requestID = "keygen-v5-mismatch"

	_, pub, shares := makeVSSSharesS256(t, 2, n)

	path0 := writeMobileVaultFile(t, dirTmp, "device0.json", mmI, vaultID, requestID,
		map[string]mobileRequestFixture{requestID: {threshold: 2, ecdsa: mobileECDSAPayload(vaultID, shares[0], pub)}})
	path1 := writeMobileVaultFile(t, dirTmp, "device1.json", mmI, vaultID, requestID,
		map[string]mobileRequestFixture{requestID: {threshold: 3, ecdsa: mobileECDSAPayload(vaultID, shares[1], pub)}}) // disagrees

	files := []ui.VaultsDataFile{{File: path0, Mnemonics: mmI}, {File: path1, Mnemonics: mmI}}
	_, _, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "threshold mismatch")
}

func TestTool_DR_ChainWalk_PicksHead(t *testing.T) {
	dirTmp := t.TempDir()
	priv, privPEM := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-chain"
	const threshold, n = 2, 2

	// Old epoch (keygen): shares of oldSecret, must be ignored once superseded.
	oldSecret, oldPub, oldShares := makeVSSSharesS256(t, threshold, n)
	// Current epoch (reshare): shares of newSecret, chained via previousRequestId to the old one.
	newSecret, newPub, newShares := makeVSSSharesS256(t, threshold, n)
	require.NotEqual(t, oldSecret.String(), newSecret.String())

	var files []ui.VaultsDataFile
	for i := 0; i < n; i++ {
		payload := &dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: oldShares[i].Share, ShareID: oldShares[i].ID, ECDSAPub: ecPointMirror("secp256k1", oldPub)}},
			VaultId:   vaultID,
			Threshold: threshold,
		}
		meta := dr.FileEnvelope{VaultId: vaultID, RequestId: "keygen-1", Algo: "ECDSA", Curve: "secp256k1"}
		path := writeDRFile(t, dirTmp, fmt.Sprintf("old-device%d.ecdsa.secp256k1.dr", i), priv.EncapsulationKey(), meta, payload)
		files = append(files, ui.VaultsDataFile{File: path})
	}
	for i := 0; i < n; i++ {
		payload := &dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: newShares[i].Share, ShareID: newShares[i].ID, ECDSAPub: ecPointMirror("secp256k1", newPub)}},
			VaultId:   vaultID,
			Threshold: threshold,
		}
		meta := dr.FileEnvelope{VaultId: vaultID, RequestId: "reshare-2", PreviousRequestId: "keygen-1", Algo: "ECDSA", Curve: "secp256k1"}
		path := writeDRFile(t, dirTmp, fmt.Sprintf("new-device%d.ecdsa.secp256k1.dr", i), priv.EncapsulationKey(), meta, payload)
		files = append(files, ui.VaultsDataFile{File: path})
	}

	_, ecSK, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, nil, privPEM)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(newSecret)), hex.EncodeToString(ecSK))
	require.NotEqual(t, hex.EncodeToString(leftPadTo32Bytes(oldSecret)), hex.EncodeToString(ecSK))
}

func TestTool_DR_ChainWalk_Ambiguous(t *testing.T) {
	dirTmp := t.TempDir()
	priv, privPEM := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-ambiguous"
	const threshold, n = 2, 2

	_, pubA, sharesA := makeVSSSharesS256(t, threshold, n)
	_, pubB, sharesB := makeVSSSharesS256(t, threshold, n)

	// Two disconnected .dr "epochs" for the same vault (no previousRequestId chain relating
	// them) - the tool cannot tell which is current without an override.
	var files []ui.VaultsDataFile
	for i := 0; i < n; i++ {
		payload := &dr.ECDSASharesAndVaultId{
			Data:    []*dr.ECDSAShare{{Xi: sharesA[i].Share, ShareID: sharesA[i].ID, ECDSAPub: ecPointMirror("secp256k1", pubA)}},
			VaultId: vaultID, Threshold: threshold,
		}
		meta := dr.FileEnvelope{VaultId: vaultID, RequestId: "epoch-a", Algo: "ECDSA", Curve: "secp256k1"}
		path := writeDRFile(t, dirTmp, fmt.Sprintf("a-device%d.ecdsa.secp256k1.dr", i), priv.EncapsulationKey(), meta, payload)
		files = append(files, ui.VaultsDataFile{File: path})
	}
	for i := 0; i < n; i++ {
		payload := &dr.ECDSASharesAndVaultId{
			Data:    []*dr.ECDSAShare{{Xi: sharesB[i].Share, ShareID: sharesB[i].ID, ECDSAPub: ecPointMirror("secp256k1", pubB)}},
			VaultId: vaultID, Threshold: threshold,
		}
		meta := dr.FileEnvelope{VaultId: vaultID, RequestId: "epoch-b", Algo: "ECDSA", Curve: "secp256k1"}
		path := writeDRFile(t, dirTmp, fmt.Sprintf("b-device%d.ecdsa.secp256k1.dr", i), priv.EncapsulationKey(), meta, payload)
		files = append(files, ui.VaultsDataFile{File: path})
	}

	_, _, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, nil, privPEM)
	require.Error(t, err)
	require.Contains(t, err.Error(), "-request-id")
}

func TestTool_DR_RequestIDOverride(t *testing.T) {
	dirTmp := t.TempDir()
	priv, privPEM := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-override"
	const threshold, n = 2, 2

	secretA, pubA, sharesA := makeVSSSharesS256(t, threshold, n)
	secretB, pubB, sharesB := makeVSSSharesS256(t, threshold, n)
	require.NotEqual(t, secretA.String(), secretB.String())

	// Same ambiguous, disconnected two-epoch setup as TestTool_DR_ChainWalk_Ambiguous, but this
	// time disambiguated with -request-id.
	var files []ui.VaultsDataFile
	for i := 0; i < n; i++ {
		payload := &dr.ECDSASharesAndVaultId{
			Data:    []*dr.ECDSAShare{{Xi: sharesA[i].Share, ShareID: sharesA[i].ID, ECDSAPub: ecPointMirror("secp256k1", pubA)}},
			VaultId: vaultID, Threshold: threshold,
		}
		meta := dr.FileEnvelope{VaultId: vaultID, RequestId: "epoch-a", Algo: "ECDSA", Curve: "secp256k1"}
		path := writeDRFile(t, dirTmp, fmt.Sprintf("a-device%d.ecdsa.secp256k1.dr", i), priv.EncapsulationKey(), meta, payload)
		files = append(files, ui.VaultsDataFile{File: path})
	}
	for i := 0; i < n; i++ {
		payload := &dr.ECDSASharesAndVaultId{
			Data:    []*dr.ECDSAShare{{Xi: sharesB[i].Share, ShareID: sharesB[i].ID, ECDSAPub: ecPointMirror("secp256k1", pubB)}},
			VaultId: vaultID, Threshold: threshold,
		}
		meta := dr.FileEnvelope{VaultId: vaultID, RequestId: "epoch-b", Algo: "ECDSA", Curve: "secp256k1"}
		path := writeDRFile(t, dirTmp, fmt.Sprintf("b-device%d.ecdsa.secp256k1.dr", i), priv.EncapsulationKey(), meta, payload)
		files = append(files, ui.VaultsDataFile{File: path})
	}

	requestIDOverride := "epoch-b"
	_, ecSK, _, _, _, err := runTool(files, &vaultID, nil, &requestIDOverride, nil, nil, nil, privPEM)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secretB)), hex.EncodeToString(ecSK))
}
