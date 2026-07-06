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

// writeDRFile JSON-marshals payload, encrypts it as a .dr file under dir/name, and returns its path.
func writeDRFile(t *testing.T, dir, name string, pub *mlkem.EncapsulationKey768, payload any) string {
	t.Helper()
	plaintext, err := json.Marshal(payload)
	require.NoError(t, err)
	raw := encryptDRForTest(t, pub, plaintext)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
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
// key) carrying the given ECDSA shares for one vault/nonce, and returns its path.
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

	savedData := SavedData{
		Vaults: map[string]CipheredVaultMap{
			vaultID: {
				nonce: CipheredVault{
					CipherTextB64: base64.StdEncoding.EncodeToString(ciphertext),
					CipherParams:  CipherParams{IV: hex.EncodeToString(nonceBz), Tag: hex.EncodeToString(tag)},
					Cipher:        "aes-256-gcm",
					Hash:          hex.EncodeToString(hash[:]),
				},
			},
		},
	}
	content, err := json.Marshal(savedData)
	require.NoError(t, err)

	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
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

	var files []ui.VaultsDataFile
	for i := 0; i < n; i++ {
		payload := &dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: ecdsaShares[i].Share, ShareID: ecdsaShares[i].ID, ECDSAPub: ecPointMirror("secp256k1", ecdsaPub)}},
			VaultId:   vaultID,
			Threshold: threshold,
		}
		path := writeDRFile(t, dirTmp, fmt.Sprintf("req%d.ecdsa.secp256k1.dr", i), priv.EncapsulationKey(), payload)
		files = append(files, ui.VaultsDataFile{File: path})
	}
	for i := 0; i < n; i++ {
		payload := &dr.EdDSASharesAndVaultId{
			Data:      []*dr.EdDSAShare{{Xi: eddsaShares[i].Share, ShareID: eddsaShares[i].ID, EDDSAPub: ecPointMirror("ed25519", eddsaPub)}},
			VaultId:   vaultID,
			Threshold: threshold,
		}
		path := writeDRFile(t, dirTmp, fmt.Sprintf("req%d.eddsa.ed25519.dr", i), priv.EncapsulationKey(), payload)
		files = append(files, ui.VaultsDataFile{File: path})
	}

	address, ecSK, edSK, vaultsFormData, _, err := runTool(files, &vaultID, nil, nil, nil, nil, privPEM)
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

	path1 := writeDRFile(t, dirTmp, "req0.ecdsa.secp256k1.dr", priv.EncapsulationKey(), &dr.ECDSASharesAndVaultId{
		Data:      []*dr.ECDSAShare{{Xi: shares[0].Share, ShareID: shares[0].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
		VaultId:   vaultID,
		Threshold: 2,
	})
	path2 := writeDRFile(t, dirTmp, "req1.ecdsa.secp256k1.dr", priv.EncapsulationKey(), &dr.ECDSASharesAndVaultId{
		Data:      []*dr.ECDSAShare{{Xi: shares[1].Share, ShareID: shares[1].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
		VaultId:   vaultID,
		Threshold: 3, // deliberately different
	})

	files := []ui.VaultsDataFile{{File: path1}, {File: path2}}
	_, _, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, privPEM)
	require.Error(t, err)
	require.Contains(t, err.Error(), "threshold mismatch")
}

func TestTool_DR_MissingPrivateKey(t *testing.T) {
	dirTmp := t.TempDir()
	priv, _ := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-nokey"

	_, pub, shares := makeVSSSharesS256(t, 2, 2)
	path := writeDRFile(t, dirTmp, "req0.ecdsa.secp256k1.dr", priv.EncapsulationKey(), &dr.ECDSASharesAndVaultId{
		Data:      []*dr.ECDSAShare{{Xi: shares[0].Share, ShareID: shares[0].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
		VaultId:   vaultID,
		Threshold: 2,
	})

	files := []ui.VaultsDataFile{{File: path}}
	_, _, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "-private-key")
}

func TestTool_DR_WrongPrivateKey(t *testing.T) {
	dirTmp := t.TempDir()
	priv, _ := genMLKEMKeyPEM(t)
	_, wrongPEM := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-wrongkey"

	_, pub, shares := makeVSSSharesS256(t, 2, 2)
	path := writeDRFile(t, dirTmp, "req0.ecdsa.secp256k1.dr", priv.EncapsulationKey(), &dr.ECDSASharesAndVaultId{
		Data:      []*dr.ECDSAShare{{Xi: shares[0].Share, ShareID: shares[0].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
		VaultId:   vaultID,
		Threshold: 2,
	})

	files := []ui.VaultsDataFile{{File: path}}
	_, _, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, wrongPEM)
	require.Error(t, err)
}

func TestTool_DR_MixedWithLegacy(t *testing.T) {
	dirTmp := t.TempDir()
	priv, privPEM := genMLKEMKeyPEM(t)
	vaultID := "dr-test-vault-mixed"
	const threshold, n = 2, 2 // one share from legacy, one from .dr

	secret, pub, shares := makeVSSSharesS256(t, threshold, n)

	// Share 0 goes into a legacy mnemonic-encrypted vault file.
	legacyShareData := &ecdsa_keygen.LocalPartySaveData{
		LocalSecrets: ecdsa_keygen.LocalSecrets{Xi: shares[0].Share, ShareID: shares[0].ID},
		ECDSAPub:     pub,
	}
	legacyShareJSON, err := json.Marshal(legacyShareData)
	require.NoError(t, err)
	legacyPath := writeLegacyVaultFile(t, dirTmp, "legacy.json", mmI, vaultID, 0, threshold, []string{string(legacyShareJSON)})

	// Share 1 goes into a .dr file.
	drPath := writeDRFile(t, dirTmp, "req0.ecdsa.secp256k1.dr", priv.EncapsulationKey(), &dr.ECDSASharesAndVaultId{
		Data:      []*dr.ECDSAShare{{Xi: shares[1].Share, ShareID: shares[1].ID, ECDSAPub: ecPointMirror("secp256k1", pub)}},
		VaultId:   vaultID,
		Threshold: threshold,
	})

	files := []ui.VaultsDataFile{
		{File: legacyPath, Mnemonics: mmI},
		{File: drPath},
	}
	address, ecSK, _, _, _, err := runTool(files, &vaultID, nil, nil, nil, nil, privPEM)
	require.NoError(t, err)

	_, expectedAddress, err := getTSSPubKeyForEthereum(pub.X(), pub.Y())
	require.NoError(t, err)
	require.Equal(t, expectedAddress, address)
	require.Equal(t, hex.EncodeToString(leftPadTo32Bytes(secret)), hex.EncodeToString(ecSK))
}
