// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/dr"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/recoverypipeline"
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

// drFileBytes builds a .dr file's on-disk bytes without writing them, for embedding in a zip.
func drFileBytes(t *testing.T, pub *mlkem.EncapsulationKey768, meta dr.FileEnvelope, payload any) []byte {
	t.Helper()
	plaintext, err := json.Marshal(payload)
	require.NoError(t, err)
	meta.DataB64 = base64.StdEncoding.EncodeToString(encryptDRForTest(t, pub, plaintext))
	content, err := json.Marshal(meta)
	require.NoError(t, err)
	return content
}

func writeDRFile(t *testing.T, dir, name string, pub *mlkem.EncapsulationKey768, meta dr.FileEnvelope, payload any) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, drFileBytes(t, pub, meta, payload), 0o600))
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

	clearVault := recoverypipeline.ClearVault{
		Name:   "mixed-format-test-vault",
		Quroum: threshold,
		Curves: []recoverypipeline.ClearVaultCurve{{Algorithm: "ECDSA", Shares: ecdsaShareJSONs}},
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

	cipheredVault := recoverypipeline.CipheredVault{
		CipherTextB64: base64.StdEncoding.EncodeToString(ciphertext),
		CipherParams:  recoverypipeline.CipherParams{IV: hex.EncodeToString(nonceBz), Tag: hex.EncodeToString(tag)},
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

		requestsJSON[requestID] = recoverypipeline.CipheredVault{
			CipherTextB64: base64.StdEncoding.EncodeToString(ciphertext),
			CipherParams: recoverypipeline.CipherParams{
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

// --- Virtual Signer bundle fixture helpers ----------------------------------------------------

type bundleFile struct {
	name string
	data []byte
}

// writeBundleZip declares only .dr entries in the manifest, so any other entry reaches the
// expander undeclared and unsupported.
func writeBundleZip(t *testing.T, zipPath, signerID, vaultID string, files []bundleFile) string {
	t.Helper()

	declared := make([]map[string]any, 0, len(files))
	for _, f := range files {
		if !strings.EqualFold(filepath.Ext(f.name), ".dr") {
			continue
		}
		sum := sha256.Sum256(f.data)
		declared = append(declared, map[string]any{
			"path": f.name, "sha256": hex.EncodeToString(sum[:]), "bytes": len(f.data),
		})
	}
	manifest, err := json.Marshal(map[string]any{
		"formatVersion": 2,
		"signerId":      signerID,
		"vaults": []map[string]any{
			{"vaultId": vaultID, "currentRequestId": bundleRequestID, "files": declared},
		},
	})
	require.NoError(t, err)

	out, err := os.OpenFile(zipPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	require.NoError(t, err)
	defer out.Close()

	w := zip.NewWriter(out)
	for _, e := range append([]bundleFile{{name: "manifest.json", data: manifest}}, files...) {
		fw, err := w.Create(e.name)
		require.NoError(t, err)
		_, err = fw.Write(e.data)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return zipPath
}

const (
	bundleVaultID   = "bundle-vault-1"
	bundleRequestID = "keygen-1"
)

// oneVaultBundle writes a bundle of real .dr ECDSA shares for one vault, plus extra entries
// verbatim.
func oneVaultBundle(t *testing.T, dir string, extra []bundleFile) (zipPath string, privPEM []byte, secret *big.Int) {
	t.Helper()
	const threshold, n = 2, 3

	priv, privPEM := genMLKEMKeyPEM(t)

	var (
		pub    *crypto.ECPoint
		shares vss.Shares
	)
	// A coordinate with a leading zero byte serializes short and fails to parse, for
	// reasons unrelated to these tests. Draw again rather than inherit that flake.
	for {
		secret, pub, shares = makeVSSSharesS256(t, threshold, n)
		if len(pub.X().Bytes()) == 32 && len(pub.Y().Bytes()) == 32 {
			break
		}
	}

	files := make([]bundleFile, 0, n+len(extra))
	for i := 0; i < n; i++ {
		payload := &dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[i].Share, ShareID: shares[i].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   bundleVaultID,
			Threshold: threshold,
		}
		meta := dr.FileEnvelope{VaultId: bundleVaultID, RequestId: bundleRequestID, Algo: "ECDSA", Curve: "secp256k1"}
		files = append(files, bundleFile{
			name: fmt.Sprintf("dr/%s/device%d.ecdsa.secp256k1.dr", bundleVaultID, i),
			data: drFileBytes(t, priv.EncapsulationKey(), meta, payload),
		})
	}

	zipPath = writeBundleZip(t, filepath.Join(dir, "signer-backup.zip"), "signer-1", bundleVaultID, append(files, extra...))
	return zipPath, privPEM, secret
}

// bundleTempDirs counts only the caller's own run: tests point TMPDIR at their own directory.
func bundleTempDirs(t *testing.T, root string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, "vault-recovery-bundle-*"))
	require.NoError(t, err)
	return matches
}

// captureStdout returns everything fn prints to os.Stdout. fn must not call t.Fatal: that
// skips the restore below and leaves every later test writing into this pipe.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)

	orig := os.Stdout
	os.Stdout = w

	captured := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		_ = r.Close()
		captured <- buf.String()
	}()

	fn()

	os.Stdout = orig
	require.NoError(t, w.Close())
	return <-captured
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

	address, ecSK, edSK, vaultsFormData, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", [][]byte{privPEM})
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
	_, _, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", [][]byte{privPEM})
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
	_, _, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "-keys")
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
	_, _, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", [][]byte{wrongPEM})
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
	address, ecSK, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", [][]byte{privPEM})
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

	address, ecSK, _, vaultsFormData, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", nil)
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

	address, ecSK, edSK, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", nil)
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
	_, ecSK, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", nil)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secretB)), hex.EncodeToString(ecSK))

	// -request-id epoch A: reconstructs secretA with epoch A's threshold (2), proving the threshold
	// tracks the chosen epoch's own payload, not a single vault-wide value.
	_, ecSKA, _, _, _, err := runToolFiles(files, vaultID, 0, false, reqA, 0, "", "", nil)
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
	_, _, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no threshold")

	// With -threshold → recovers correctly.
	address, ecSK, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", threshold, "", "", nil)
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
	_, _, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "threshold mismatch")
}

// TestTool_LegacyAndV5_ThresholdMismatch_EitherOrder: a legacy file and a v5 mobile file for
// the same vault that disagree on threshold must fail regardless of file processing order.
func TestTool_LegacyAndV5_ThresholdMismatch_EitherOrder(t *testing.T) {
	dirTmp := t.TempDir()
	vaultID := "mixed-legacy-v5-threshold-mismatch"
	const nonce = 7
	const requestID = "mobile-v5-req"

	_, pubA, sharesA := makeVSSSharesS256(t, 2, 2)
	_, pubB, sharesB := makeVSSSharesS256(t, 3, 3)
	legacyShareData := &ecdsa_keygen.LocalPartySaveData{
		LocalSecrets: ecdsa_keygen.LocalSecrets{Xi: sharesA[0].Share, ShareID: sharesA[0].ID},
		ECDSAPub:     pubA,
	}
	legacyShareJSONBytes, err := json.Marshal(legacyShareData)
	require.NoError(t, err)

	legacyPath := writeLegacyVaultFile(t, dirTmp, "legacy.json", mmI, vaultID, nonce, 2,
		[]string{string(legacyShareJSONBytes)})
	mobilePath := writeMobileVaultFile(t, dirTmp, "mobile-v5.json", mmI, vaultID, requestID,
		map[string]mobileRequestFixture{
			requestID: {threshold: 3, ecdsa: mobileECDSAPayload(vaultID, sharesB[0], pubB)},
		})

	filesLegacyThenV5 := []ui.VaultsDataFile{
		{File: legacyPath, Mnemonics: mmI},
		{File: mobilePath, Mnemonics: mmI},
	}
	_, _, _, _, _, err = runToolFiles(filesLegacyThenV5, vaultID, 0, false, "", 0, "", "", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "threshold mismatch")

	filesV5ThenLegacy := []ui.VaultsDataFile{
		{File: mobilePath, Mnemonics: mmI},
		{File: legacyPath, Mnemonics: mmI},
	}
	_, _, _, _, _, err = runToolFiles(filesV5ThenLegacy, vaultID, 0, false, "", 0, "", "", nil)
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

	_, ecSK, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", [][]byte{privPEM})
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

	_, _, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", [][]byte{privPEM})
	require.Error(t, err)
	require.Contains(t, err.Error(), "-request-id")
	require.Contains(t, err.Error(), "candidates: epoch-a, epoch-b")
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

	_, ecSK, _, _, _, err := runToolFiles(files, vaultID, 0, false, "epoch-b", 0, "", "", [][]byte{privPEM})
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secretB)), hex.EncodeToString(ecSK))
}

// TestPrepare_MissingPrivateKey_PathRedactedForWeb: the web frontend appends its own remediation
// to ErrPrivateKeyRequired without running its path stripper, so Prepare must already have applied
// the caller's path presentation. The CLI keeps full paths (see TestTool_DR_MissingPrivateKey).
func TestPrepare_MissingPrivateKey_PathRedactedForWeb(t *testing.T) {
	dirTmp := t.TempDir()
	priv, _ := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-nokey-web"

	_, pub, shares := makeVSSSharesS256(t, 2, 2)
	path := writeDRFile(t, dirTmp, "req0.ecdsa.secp256k1.dr", priv.EncapsulationKey(),
		dr.FileEnvelope{VaultId: vaultID, RequestId: "req0", Algo: "ECDSA", Curve: "secp256k1"},
		&dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[0].Share, ShareID: shares[0].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   vaultID,
			Threshold: 2,
		})

	files := []ui.VaultsDataFile{{File: path}}
	pres := recoverypipeline.ErrorPresentation{Path: filepath.Base}
	inputs, derr := recoverypipeline.Discover(files, pres)
	require.NoError(t, derr)
	defer inputs.Close()
	_, err := recoverypipeline.Prepare(inputs, recoverypipeline.Options{
		VaultID:      vaultID,
		Presentation: pres,
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, recoverypipeline.ErrPrivateKeyRequired))
	require.Contains(t, err.Error(), filepath.Base(path))
	require.NotContains(t, err.Error(), dirTmp)
}

// TestTool_LegacyNoQuorum_ListsAndRecoversWithFlag: a legacy backup that records no quorum still
// lists, and reconstructs once -threshold supplies one.
func TestTool_LegacyNoQuorum_ListsAndRecoversWithFlag(t *testing.T) {
	dirTmp := t.TempDir()
	vaultID := "legacy-test-vault-no-quorum"
	const threshold, n = 2, 2

	secret, pub, shares := makeVSSSharesS256(t, threshold, n)
	shareJSONs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		shareData := &ecdsa_keygen.LocalPartySaveData{
			LocalSecrets: ecdsa_keygen.LocalSecrets{Xi: shares[i].Share, ShareID: shares[i].ID},
			ECDSAPub:     pub,
		}
		shareJSON, err := json.Marshal(shareData)
		require.NoError(t, err)
		shareJSONs = append(shareJSONs, string(shareJSON))
	}
	// threshold: 0 → the legacy payload carries no quorum.
	legacyPath := writeLegacyVaultFile(t, dirTmp, "legacy.json", mmI, vaultID, 0, 0, shareJSONs)
	files := []ui.VaultsDataFile{{File: legacyPath, Mnemonics: mmI}}

	// Listing mode: the vault shows up with quorum 0 rather than failing the run.
	emptyVaultID := ""
	_, _, _, orderedVaults, _, err := runToolFiles(files, emptyVaultID, 0, false, "", 0, "", "", nil)
	require.NoError(t, err)
	require.Len(t, orderedVaults, 1)
	require.Equal(t, vaultID, orderedVaults[0].VaultID)
	require.Equal(t, 0, orderedVaults[0].Quorum)

	// No -threshold → hard error at reconstruction.
	_, _, _, _, _, err = runToolFiles(files, vaultID, 0, false, "", 0, "", "", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no threshold")

	// With -threshold → recovers correctly.
	address, ecSK, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", threshold, "", "", nil)
	require.NoError(t, err)
	_, expectedAddress, err := getTSSPubKeyForEthereum(pub.X(), pub.Y())
	require.NoError(t, err)
	require.Equal(t, expectedAddress, address)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secret)), hex.EncodeToString(ecSK))
}

// TestTool_LegacyNoQuorum_KeepsV5Threshold: a legacy backup with no quorum neither errors out nor
// overwrites the threshold a v5 mobile file already established for the same vault.
func TestTool_LegacyNoQuorum_KeepsV5Threshold(t *testing.T) {
	dirTmp := t.TempDir()
	vaultID := "legacy-no-quorum-with-v5"
	const requestID = "mobile-v5-req"

	_, pubA, sharesA := makeVSSSharesS256(t, 2, 2)
	_, pubB, sharesB := makeVSSSharesS256(t, 3, 3)
	legacyShareData := &ecdsa_keygen.LocalPartySaveData{
		LocalSecrets: ecdsa_keygen.LocalSecrets{Xi: sharesA[0].Share, ShareID: sharesA[0].ID},
		ECDSAPub:     pubA,
	}
	legacyShareJSON, err := json.Marshal(legacyShareData)
	require.NoError(t, err)
	legacyPath := writeLegacyVaultFile(t, dirTmp, "legacy.json", mmI, vaultID, 0, 0, []string{string(legacyShareJSON)})
	mobilePath := writeMobileVaultFile(t, dirTmp, "mobile-v5.json", mmI, vaultID, requestID,
		map[string]mobileRequestFixture{
			requestID: {threshold: 3, ecdsa: mobileECDSAPayload(vaultID, sharesB[0], pubB)},
		})

	for _, order := range [][]ui.VaultsDataFile{
		{{File: legacyPath, Mnemonics: mmI}, {File: mobilePath, Mnemonics: mmI}},
		{{File: mobilePath, Mnemonics: mmI}, {File: legacyPath, Mnemonics: mmI}},
	} {
		emptyVaultID := ""
		_, _, _, orderedVaults, _, err := runToolFiles(order, emptyVaultID, 0, false, "", 0, "", "", nil)
		require.NoError(t, err)
		require.Len(t, orderedVaults, 1)
		require.Equal(t, 3, orderedVaults[0].Quorum)
	}
}

// --- multi-key tests -----------------------------------------------------------------------

// TestTool_DR_MultiKey_SecondKeyDecrypts: the first supplied key is wrong, the second is right;
// the loop tries every key and recovers.
func TestTool_DR_MultiKey_SecondKeyDecrypts(t *testing.T) {
	dirTmp := t.TempDir()
	priv, privPEM := genMLKEMKeyPEM(t)
	_, wrongPEM := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-multikey-second"

	secret, pub, shares := makeVSSSharesS256(t, 2, 2)
	path := writeDRFile(t, dirTmp, "req0.ecdsa.secp256k1.dr", priv.EncapsulationKey(),
		dr.FileEnvelope{VaultId: vaultID, RequestId: "req0", Algo: "ECDSA", Curve: "secp256k1"},
		&dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[0].Share, ShareID: shares[0].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   vaultID,
			Threshold: 2,
		})
	path2 := writeDRFile(t, dirTmp, "req0-b.ecdsa.secp256k1.dr", priv.EncapsulationKey(),
		dr.FileEnvelope{VaultId: vaultID, RequestId: "req0", Algo: "ECDSA", Curve: "secp256k1"},
		&dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[1].Share, ShareID: shares[1].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   vaultID,
			Threshold: 2,
		})

	files := []ui.VaultsDataFile{{File: path}, {File: path2}}
	address, ecSK, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", [][]byte{wrongPEM, privPEM})
	require.NoError(t, err)
	_, expectedAddress, err := getTSSPubKeyForEthereum(pub.X(), pub.Y())
	require.NoError(t, err)
	require.Equal(t, expectedAddress, address)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secret)), hex.EncodeToString(ecSK))
}

// TestTool_DR_MultiKey_DifferentKeysPerFile: two .dr files for the same vault/request, each
// encrypted to a different recipient key; supplying both keys lets both files' shares merge.
func TestTool_DR_MultiKey_DifferentKeysPerFile(t *testing.T) {
	dirTmp := t.TempDir()
	privA, privPEMA := genMLKEMKeyPEM(t)
	privB, privPEMB := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-multikey-perfile"

	secret, pub, shares := makeVSSSharesS256(t, 2, 2)
	pathA := writeDRFile(t, dirTmp, "deviceA.ecdsa.secp256k1.dr", privA.EncapsulationKey(),
		dr.FileEnvelope{VaultId: vaultID, RequestId: "req0", Algo: "ECDSA", Curve: "secp256k1"},
		&dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[0].Share, ShareID: shares[0].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   vaultID,
			Threshold: 2,
		})
	pathB := writeDRFile(t, dirTmp, "deviceB.ecdsa.secp256k1.dr", privB.EncapsulationKey(),
		dr.FileEnvelope{VaultId: vaultID, RequestId: "req0", Algo: "ECDSA", Curve: "secp256k1"},
		&dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[1].Share, ShareID: shares[1].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   vaultID,
			Threshold: 2,
		})

	files := []ui.VaultsDataFile{{File: pathA}, {File: pathB}}
	address, ecSK, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", [][]byte{privPEMA, privPEMB})
	require.NoError(t, err)
	_, expectedAddress, err := getTSSPubKeyForEthereum(pub.X(), pub.Y())
	require.NoError(t, err)
	require.Equal(t, expectedAddress, address)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secret)), hex.EncodeToString(ecSK))
}

// TestTool_DR_MultiKey_AllWrong: with more than one key supplied and none of them correct, the
// error names the file, reports how many keys were tried, and carries no key material.
func TestTool_DR_MultiKey_AllWrong(t *testing.T) {
	dirTmp := t.TempDir()
	priv, _ := genMLKEMKeyPEM(t)
	_, wrongPEM1 := genMLKEMKeyPEM(t)
	_, wrongPEM2 := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-multikey-allwrong"

	_, pub, shares := makeVSSSharesS256(t, 2, 2)
	path := writeDRFile(t, dirTmp, "req0.ecdsa.secp256k1.dr", priv.EncapsulationKey(),
		dr.FileEnvelope{VaultId: vaultID, RequestId: "req0", Algo: "ECDSA", Curve: "secp256k1"},
		&dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[0].Share, ShareID: shares[0].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   vaultID,
			Threshold: 2,
		})

	files := []ui.VaultsDataFile{{File: path}}
	_, _, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", [][]byte{wrongPEM1, wrongPEM2})
	require.Error(t, err)
	require.Contains(t, err.Error(), filepath.Base(path))
	require.Contains(t, err.Error(), "tried 2 keys")
	require.NotContains(t, err.Error(), "PRIVATE KEY")
	require.NotContains(t, err.Error(), string(wrongPEM1))
	require.NotContains(t, err.Error(), string(wrongPEM2))
}

// TestTool_DR_MultiKey_CorruptEnvelope: a corrupt (not-JSON) .dr file fails identically for every
// key tried, and the loop still surfaces the envelope-level message rather than a key error.
func TestTool_DR_MultiKey_CorruptEnvelope(t *testing.T) {
	dirTmp := t.TempDir()
	_, privPEM1 := genMLKEMKeyPEM(t)
	_, privPEM2 := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-multikey-corrupt"

	path := filepath.Join(dirTmp, "corrupt.ecdsa.secp256k1.dr")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0o600))

	files := []ui.VaultsDataFile{{File: path}}
	_, _, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", [][]byte{privPEM1, privPEM2})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a JSON envelope")
}

// TestTool_DR_MultiKey_EmptyKeyList: an explicitly empty (non-nil) key slice reproduces
// ErrPrivateKeyRequired exactly like the nil case.
func TestTool_DR_MultiKey_EmptyKeyList(t *testing.T) {
	dirTmp := t.TempDir()
	priv, _ := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-multikey-empty"

	_, pub, shares := makeVSSSharesS256(t, 2, 2)
	path := writeDRFile(t, dirTmp, "req0.ecdsa.secp256k1.dr", priv.EncapsulationKey(),
		dr.FileEnvelope{VaultId: vaultID, RequestId: "req0", Algo: "ECDSA", Curve: "secp256k1"},
		&dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[0].Share, ShareID: shares[0].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   vaultID,
			Threshold: 2,
		})

	files := []ui.VaultsDataFile{{File: path}}
	inputs, derr := recoverypipeline.Discover(files, recoverypipeline.ErrorPresentation{})
	require.NoError(t, derr)
	defer inputs.Close()
	_, err := recoverypipeline.Prepare(inputs, recoverypipeline.Options{
		VaultID:        vaultID,
		PrivateKeysPEM: [][]byte{},
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, recoverypipeline.ErrPrivateKeyRequired))
}

// TestTool_DR_SingleWrongKey_NoTriedSuffix: with exactly one key supplied, the failure message
// keeps its single-key wording verbatim - no "(tried N keys)" suffix.
func TestTool_DR_SingleWrongKey_NoTriedSuffix(t *testing.T) {
	dirTmp := t.TempDir()
	priv, _ := genMLKEMKeyPEM(t)
	_, wrongPEM := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-singlewrongkey"

	_, pub, shares := makeVSSSharesS256(t, 2, 2)
	path := writeDRFile(t, dirTmp, "req0.ecdsa.secp256k1.dr", priv.EncapsulationKey(),
		dr.FileEnvelope{VaultId: vaultID, RequestId: "req0", Algo: "ECDSA", Curve: "secp256k1"},
		&dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: shares[0].Share, ShareID: shares[0].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
			VaultId:   vaultID,
			Threshold: 2,
		})

	files := []ui.VaultsDataFile{{File: path}}
	_, _, _, _, _, err := runToolFiles(files, vaultID, 0, false, "", 0, "", "", [][]byte{wrongPEM})
	require.Error(t, err)
	require.NotContains(t, err.Error(), "tried")
}

// --- shared input set across a listing and a recover pass -------------------------------------

// The archive is deleted right after Discover, so a second discovery would find nothing at
// that path, fall back to reading the .zip as a plain input, and fail. The run survives only
// by reusing the one extraction. Extraction dirs are counted too, as a second check.
func TestTool_BundleZip_ExpandedOnceAcrossBothPasses(t *testing.T) {
	tmpRoot := t.TempDir()
	zipPath, privPEM, secret := oneVaultBundle(t, t.TempDir(), nil)

	t.Setenv("TMPDIR", tmpRoot)
	inputs, err := recoverypipeline.Discover([]ui.VaultsDataFile{{File: zipPath}}, recoverypipeline.ErrorPresentation{})
	require.NoError(t, err)
	defer inputs.Close()
	require.Len(t, bundleTempDirs(t, tmpRoot), 1)

	require.NoError(t, os.Remove(zipPath))

	_, _, _, orderedVaults, _, err := runTool(inputs, "", 0, false, "", 0, "", "", [][]byte{privPEM})
	require.NoError(t, err)
	require.Len(t, orderedVaults, 1)
	require.Equal(t, bundleVaultID, orderedVaults[0].VaultID)
	require.Len(t, bundleTempDirs(t, tmpRoot), 1)

	_, ecSK, _, _, _, err := runTool(inputs, bundleVaultID, 0, false, "", 0, "", "", [][]byte{privPEM})
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secret)), hex.EncodeToString(ecSK))

	// The recover pass owns the Close, so the run leaves nothing behind.
	require.Empty(t, bundleTempDirs(t, tmpRoot))
}

// The dropped entry is found once by Discover, so the listing/recover pair must print it once
// between them, not once each.
func TestTool_BundleZip_EntryIgnoredWarning_RenderedOnce(t *testing.T) {
	extra := []bundleFile{{name: "notes.txt", data: []byte("not a share")}}
	zipPath, privPEM, secret := oneVaultBundle(t, t.TempDir(), extra)

	inputs, err := recoverypipeline.Discover([]ui.VaultsDataFile{{File: zipPath}}, recoverypipeline.ErrorPresentation{})
	require.NoError(t, err)
	defer inputs.Close()

	var (
		orderedVaults []ui.VaultPickerItem
		listErr       error
	)
	listingOut := captureStdout(t, func() {
		_, _, _, orderedVaults, _, listErr = runTool(inputs, "", 0, false, "", 0, "", "", [][]byte{privPEM})
	})
	require.NoError(t, listErr)
	require.Len(t, orderedVaults, 1)

	var (
		ecSK       []byte
		recoverErr error
	)
	recoverOut := captureStdout(t, func() {
		_, ecSK, _, _, _, recoverErr = runTool(inputs, bundleVaultID, 0, false, "", 0, "", "", [][]byte{privPEM})
	})
	require.NoError(t, recoverErr)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secret)), hex.EncodeToString(ecSK))

	const marker = `ignoring unsupported entry "notes.txt"`
	total := strings.Count(listingOut, marker) + strings.Count(recoverOut, marker)
	require.Equal(t, 1, total, "listing output:\n%s\nrecover output:\n%s", listingOut, recoverOut)
}

// The extraction directory is made unwritable so os.RemoveAll genuinely fails; it returns nil
// for a directory that is merely already gone, so that cannot be the setup.
func TestTool_BundleZip_CleanupFailure_RecoversAndWarnsOnce(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX directory permissions to make os.RemoveAll fail")
	}

	tmpRoot := t.TempDir()
	zipPath, privPEM, secret := oneVaultBundle(t, t.TempDir(), nil)

	t.Setenv("TMPDIR", tmpRoot)
	inputs, err := recoverypipeline.Discover([]ui.VaultsDataFile{{File: zipPath}}, recoverypipeline.ErrorPresentation{})
	require.NoError(t, err)
	defer inputs.Close()

	dirs := bundleTempDirs(t, tmpRoot)
	require.Len(t, dirs, 1)
	require.NoError(t, os.Chmod(dirs[0], 0o500))
	t.Cleanup(func() { _ = os.Chmod(dirs[0], 0o700) })

	var (
		ecSK       []byte
		recoverErr error
	)
	out := captureStdout(t, func() {
		_, ecSK, _, _, _, recoverErr = runTool(inputs, bundleVaultID, 0, false, "", 0, "", "", [][]byte{privPEM})
	})
	require.NoError(t, recoverErr)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secret)), hex.EncodeToString(ecSK))
	require.Equal(t, 1, strings.Count(out, "failed to remove temporary recovery files"), "output:\n%s", out)
}
