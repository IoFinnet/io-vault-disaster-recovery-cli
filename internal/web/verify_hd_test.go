// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/hd"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/solana"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

// encodeTestXpub builds a depth-0 xpub for a master public key, the shape ParseXpub reads: a
// 33-byte compressed key for secp256k1, or 0x00 followed by the 32-byte key for Ed25519.
func encodeTestXpub(pub, chainCode []byte) string {
	payload := []byte{0x04, 0x88, 0xB2, 0x1E, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	payload = append(payload, chainCode...)
	if len(pub) == 32 {
		payload = append(payload, 0x00)
	}
	payload = append(payload, pub...)
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	return base58.Encode(append(payload, second[:4]...))
}

// lqnsXpubs returns xpubs for the lqns fixture vault's master keys, plus the keys themselves.
func lqnsXpubs(t *testing.T) (ecdsaXpub, eddsaXpub string, ecdsaSK, eddsaSK []byte) {
	t.Helper()
	ecdsaSK, err := hex.DecodeString(fixtureLqnsECDSAKey)
	require.NoError(t, err)
	eddsaSK, err = hex.DecodeString(fixtureLqnsEdDSAKey)
	require.NoError(t, err)

	ecdsaPub := secp256k1.PrivKeyFromBytes(ecdsaSK).PubKey().SerializeCompressed()
	_, edPub, err := edwards.PrivKeyFromScalar(eddsaSK)
	require.NoError(t, err)

	chainCode := make([]byte, 32)
	for i := range chainCode {
		chainCode[i] = byte(0xA0 + i)
	}
	return encodeTestXpub(ecdsaPub, chainCode), encodeTestXpub(edPub.Serialize(), chainCode), ecdsaSK, eddsaSK
}

func postVerifyWithCSV(t *testing.T, uploads []uploadFixture, csv string) VerifyResponse {
	t.Helper()
	req := multipartRequest(t, "/api/verify", uploads, func(form *multipart.Writer) {
		part, err := form.CreateFormFile("hdAddressesCSV", "hd_addresses.csv")
		require.NoError(t, err)
		_, err = part.Write([]byte(csv))
		require.NoError(t, err)
	})
	rec := httptest.NewRecorder()
	newTestServer(t).handleVerify(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp VerifyResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	for _, secret := range []string{fixtureLqnsECDSAKey, fixtureLqnsEdDSAKey} {
		require.NotContains(t, strings.ToLower(rec.Body.String()), secret, "the verify response must never carry key material")
	}
	return resp
}

func lqnsUploads() []uploadFixture {
	return []uploadFixture{
		{filepath.Join(fixtureTestFilesDir, "new_bvn.json"), fixtureMnemonicBvn},
		{filepath.Join(fixtureTestFilesDir, "new_x2q.json"), fixtureMnemonicX2q},
		{filepath.Join(fixtureTestFilesDir, "new_u44.json"), fixtureMnemonicU44},
	}
}

func TestHandleVerify_HDAddresses(t *testing.T) {
	ecdsaXpub, eddsaXpub, ecdsaSK, eddsaSK := lqnsXpubs(t)

	// Expected addresses come from the PRIVATE derivation the recover flow uses, so this checks
	// verify's public-only derivation against an independent path.
	deriver, err := hd.NewDeriver(ecdsaSK, eddsaSK)
	require.NoError(t, err)
	derived, err := deriver.DeriveAll([]hd.AddressRecord{
		{Address: "-", Xpub: ecdsaXpub, Path: "m/44/60/0/0/0", Algorithm: hd.AlgorithmECDSA, Curve: hd.CurveSecp256k1},
		{Address: "-", Xpub: eddsaXpub, Path: "m/44/501/0/0", Algorithm: hd.AlgorithmEDDSA, Curve: hd.CurveEdwards25519},
	})
	require.NoError(t, err)
	childECDSA, err := hex.DecodeString(derived[0].PrivateKey)
	require.NoError(t, err)
	childKey, err := ethcrypto.ToECDSA(childECDSA)
	require.NoError(t, err)
	wantETH := ethcrypto.PubkeyToAddress(childKey.PublicKey).Hex()
	childEdPub, err := hex.DecodeString(derived[1].PublicKey)
	require.NoError(t, err)
	wantSolana, err := solana.DeriveSolanaAddress(childEdPub)
	require.NoError(t, err)

	otherXpub := encodeTestXpub(secp256k1.PrivKeyFromBytes([]byte{1, 2, 3}).PubKey().SerializeCompressed(), make([]byte, 32))
	csv := "address,xpub,path,algorithm,curve,flags\n" +
		fmt.Sprintf("%s,%s,m/44/60/0/0/0,ECDSA,secp256k1,0\n", wantETH, ecdsaXpub) +
		fmt.Sprintf("%s,%s,m/44/501/0/0,EDDSA,Edwards25519,0\n", wantSolana, eddsaXpub) +
		fmt.Sprintf("treasury label,%s,m/44/60/0/0/0,ECDSA,secp256k1,0\n", ecdsaXpub) +
		fmt.Sprintf("%s,%s,m/44/60/0/0/1,ECDSA,secp256k1,0\n", wantETH, ecdsaXpub) +
		fmt.Sprintf("%s,%s,m/0,ECDSA,secp256k1,0\n", wantETH, otherXpub)

	resp := postVerifyWithCSV(t, lqnsUploads(), csv)
	require.NotNil(t, resp.HDAddresses)
	require.Empty(t, resp.HDAddresses.Error)
	require.Equal(t, "hd_addresses.csv", resp.HDAddresses.File)
	rows := resp.HDAddresses.Rows
	require.Len(t, rows, 5)

	require.Equal(t, "match", rows[0].Status, rows[0].Message)
	require.Equal(t, fixtureLqnsVaultID, rows[0].VaultID)
	require.Equal(t, "Ethereum", rows[0].Chain)
	require.Equal(t, wantETH, rows[0].DerivedAddress)
	require.Equal(t, 2, rows[0].Row)

	require.Equal(t, "match", rows[1].Status, rows[1].Message)
	require.Equal(t, fixtureLqnsVaultID, rows[1].VaultID)
	require.Equal(t, wantSolana, rows[1].DerivedAddress)

	require.Equal(t, "label", rows[2].Status)
	require.Equal(t, wantETH, rows[2].DerivedAddress)

	require.Equal(t, "mismatch", rows[3].Status)
	require.Equal(t, fixtureLqnsVaultID, rows[3].VaultID)

	require.Equal(t, "no-vault", rows[4].Status)
	require.Empty(t, rows[4].VaultID)
}

func TestHandleVerify_HDAddresses_LockedVaultIsNoVault(t *testing.T) {
	ecdsaXpub, _, _, _ := lqnsXpubs(t)
	// Without mnemonics no share is decrypted, so no public key is known to match the xpub.
	uploads := lqnsUploads()
	for i := range uploads {
		uploads[i].mnemonic = ""
	}
	csv := "address,xpub,path,algorithm,curve,flags\n" +
		fmt.Sprintf("label,%s,m/0,ECDSA,secp256k1,0\n", ecdsaXpub)
	resp := postVerifyWithCSV(t, uploads, csv)
	require.Len(t, resp.HDAddresses.Rows, 1)
	require.Equal(t, "no-vault", resp.HDAddresses.Rows[0].Status)
}

func TestHandleVerify_HDAddresses_BadCSV(t *testing.T) {
	resp := postVerifyWithCSV(t, lqnsUploads(), "address,path\nfoo,m/0\n")
	require.NotNil(t, resp.HDAddresses)
	require.NotEmpty(t, resp.HDAddresses.Error)
	require.Empty(t, resp.HDAddresses.Rows)
	require.NotEmpty(t, resp.Vaults, "a bad CSV must not stop the backup check")
}

func TestHandleVerify_NoHDCSV(t *testing.T) {
	resp, body := postVerify(t, lqnsUploads())
	require.Nil(t, resp.HDAddresses)
	require.NotContains(t, body, "hdAddresses")
}
