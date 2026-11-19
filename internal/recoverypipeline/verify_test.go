// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package recoverypipeline

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
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/vss"
	"github.com/iofinnet/tss-lib/v3/tss"
	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip39"
)

// Test fixture mnemonics, shared with the root package's tests. Used only for this purpose.
const (
	vtMnemonicI = "season pole chronic surround fiber stumble remove artwork muffin apart limit vacuum horror above donkey olympic earn dizzy addict gym animal leopard before unfair"
	vtMnemonicL = "casual gallery jump mad claw curve portion enrich oyster calm spoon flash hat soft dizzy example exile large provide smart magnet raven nurse prison"

	vtMnemonicNewBvn = "domain damp hill depth label eye erode dutch impulse betray floor donate bonus hover bitter ring unfold poet identify capital combine question profit april"
	vtMnemonicNewX2q = "found midnight praise exhibit weather neutral inmate strong grass famous blind pet frozen shock avocado ring fringe planet opera license stand coil beauty capable"
	vtMnemonicNewU44 = "aerobic foam smooth immune card tragic window myth planet notice piece agree add target tortoise weather kite track spot dish dignity twice gadget spell"
)

// --- fixture helpers (mirroring tool_dr_test.go in the root package) ------------------------

var vtOIDMLKEM768 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}

func vtKeyPEM(t *testing.T) (*mlkem.DecapsulationKey768, []byte) {
	t.Helper()
	priv, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	der, err := asn1.Marshal(struct {
		Version    int
		Algo       struct{ Algorithm asn1.ObjectIdentifier }
		PrivateKey []byte
	}{
		Algo:       struct{ Algorithm asn1.ObjectIdentifier }{vtOIDMLKEM768},
		PrivateKey: priv.Bytes(),
	})
	require.NoError(t, err)
	return priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func vtWriteDR(t *testing.T, dir, name string, pub *mlkem.EncapsulationKey768, meta dr.FileEnvelope, payload any) string {
	t.Helper()
	plaintext, err := json.Marshal(payload)
	require.NoError(t, err)

	sharedSecret, capsule := pub.Encapsulate()
	blk, err := aes.NewCipher(sharedSecret)
	require.NoError(t, err)
	aesGCM, err := cipher.NewGCM(blk)
	require.NoError(t, err)
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	require.NoError(t, err)
	sealed := aesGCM.Seal(nonce, nonce, plaintext, nil)

	meta.DataB64 = base64.StdEncoding.EncodeToString(append(capsule, sealed...))
	content, err := json.Marshal(meta)
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

func vtMirror(curveName string, p *crypto.ECPoint) *dr.ECPoint {
	return &dr.ECPoint{Curve: curveName, Coords: [2]*big.Int{p.X(), p.Y()}}
}

func vtShares(t *testing.T, ec elliptic.Curve, threshold, n int) (*big.Int, *crypto.ECPoint, vss.Shares) {
	t.Helper()
	secret, err := rand.Int(rand.Reader, ec.Params().N)
	require.NoError(t, err)
	indexes := make([]*big.Int, n)
	for i := range indexes {
		indexes[i] = big.NewInt(int64(i + 1))
	}
	v, shares, err := vss.Create(ec, threshold-1, secret, indexes)
	require.NoError(t, err)
	return secret, v[0], shares
}

// vtDRFiles writes one ECDSA .dr file per share for vaultID at requestID.
func vtDRFiles(t *testing.T, dir, prefix, vaultID, requestID, previousRequestID string, threshold int,
	pub *mlkem.EncapsulationKey768, ecPub *crypto.ECPoint, shares vss.Shares) []ui.VaultsDataFile {
	t.Helper()
	files := make([]ui.VaultsDataFile, 0, len(shares))
	for i, share := range shares {
		payload := &dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: share.Share, ShareID: share.ID, ECDSAPub: vtMirror("secp256k1", ecPub)}},
			VaultId:   vaultID,
			Threshold: threshold,
		}
		meta := dr.FileEnvelope{VaultId: vaultID, RequestId: requestID, PreviousRequestId: previousRequestID, Algo: "ECDSA", Curve: "secp256k1"}
		path := vtWriteDR(t, dir, fmt.Sprintf("%s%d.ecdsa.secp256k1.dr", prefix, i), pub, meta, payload)
		files = append(files, ui.VaultsDataFile{File: path})
	}
	return files
}

// vtMobileFile writes a mobile export holding one ECDSA share for vaultID at requestID. A
// threshold of 0 writes the v4 shape, which records no threshold; above 0 writes v5.
func vtMobileFile(t *testing.T, dir, name, mnemonic, vaultID, requestID string, threshold int, share *vss.Share, ecPub *crypto.ECPoint) string {
	t.Helper()
	ecdsaData, err := json.Marshal(&dr.ECDSASharesAndVaultId{
		Data:    []*dr.ECDSAShare{{Xi: share.Share, ShareID: share.ID, ECDSAPub: vtMirror("secp256k1", ecPub)}},
		VaultId: vaultID,
	})
	require.NoError(t, err)
	shares := []map[string]any{{"algorithm": "ECDSA", "curve": "Secp256k1", "data": base64.StdEncoding.EncodeToString(ecdsaData)}}
	var payload any = shares
	if threshold > 0 {
		payload = map[string]any{"threshold": threshold, "shares": shares}
	}
	plaintext, err := json.Marshal(payload)
	require.NoError(t, err)

	aesKey32, err := bip39.EntropyFromMnemonic(mnemonic)
	require.NoError(t, err)
	blk, err := aes.NewCipher(aesKey32)
	require.NoError(t, err)
	aesGCM, err := cipher.NewGCM(blk)
	require.NoError(t, err)
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	require.NoError(t, err)
	sealed := aesGCM.Seal(nil, nonce, plaintext, nil)
	ctLen := len(sealed) - aesGCM.Overhead()
	hash := sha512.Sum512(plaintext)

	content, err := json.Marshal(map[string]any{
		"vaults": map[string]any{
			vaultID: map[string]any{
				"currentRequestId": requestID,
				"requests": map[string]any{
					requestID: CipheredVault{
						CipherTextB64: base64.StdEncoding.EncodeToString(sealed[:ctLen]),
						CipherParams: CipherParams{
							IV:  base64.StdEncoding.EncodeToString(nonce),
							Tag: base64.StdEncoding.EncodeToString(sealed[ctLen:]),
						},
						Cipher: "aes-256-gcm",
						Hash:   hex.EncodeToString(hash[:]),
					},
				},
			},
		},
	})
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

func vtVerify(t *testing.T, files []ui.VaultsDataFile, keys [][]byte) *VerifyReport {
	t.Helper()
	inputs, err := Discover(files, ErrorPresentation{})
	require.NoError(t, err)
	defer inputs.Close()
	report, err := Verify(inputs, keys, ErrorPresentation{})
	require.NoError(t, err)
	return report
}

func vtVault(t *testing.T, report *VerifyReport, vaultID string) VerifyVault {
	t.Helper()
	for _, v := range report.Vaults {
		if v.VaultID == vaultID {
			return v
		}
	}
	t.Fatalf("vault %s not in report", vaultID)
	return VerifyVault{}
}

// vtRequireNoSecrets fails if the serialized report contains any of the given secrets.
func vtRequireNoSecrets(t *testing.T, report *VerifyReport, secrets ...string) {
	t.Helper()
	serialized, err := json.Marshal(report)
	require.NoError(t, err)
	for _, secret := range secrets {
		require.NotContains(t, string(serialized), secret)
	}
}

func vtShareSecrets(secret *big.Int, shares vss.Shares) []string {
	out := []string{secret.String(), hex.EncodeToString(secret.Bytes())}
	for _, s := range shares {
		out = append(out, s.Share.String(), hex.EncodeToString(s.Share.Bytes()))
	}
	return out
}

// --- tests ------------------------------------------------------------------------------------

func TestVerify_RecoverableDRVaultWithBothCurves(t *testing.T) {
	dir := t.TempDir()
	priv, privPEM := vtKeyPEM(t)
	const vaultID, requestID = "verify-dr-vault", "keygen-1"
	const threshold, n = 2, 3

	ecSecret, ecPub, ecShares := vtShares(t, tss.S256(), threshold, n)
	edSecret, edPub, edShares := vtShares(t, tss.Edwards(), threshold, n)

	files := vtDRFiles(t, dir, "device", vaultID, requestID, "", threshold, priv.EncapsulationKey(), ecPub, ecShares)
	for i, share := range edShares {
		payload := &dr.EdDSASharesAndVaultId{
			Data:      []*dr.EdDSAShare{{Xi: share.Share, ShareID: share.ID, EDDSAPub: vtMirror("ed25519", edPub)}},
			VaultId:   vaultID,
			Threshold: threshold,
		}
		meta := dr.FileEnvelope{VaultId: vaultID, RequestId: requestID, Algo: "EDDSA", Curve: "ed25519"}
		files = append(files, ui.VaultsDataFile{File: vtWriteDR(t, dir, fmt.Sprintf("device%d.eddsa.ed25519.dr", i), priv.EncapsulationKey(), meta, payload)})
	}

	report := vtVerify(t, files, [][]byte{privPEM})

	require.Len(t, report.Sources, 2*n)
	for _, src := range report.Sources {
		require.Equal(t, VerifyLevelDecrypted, src.Level, src.Error)
		require.Equal(t, SourceKindDRShare, src.Kind)
		require.Equal(t, 1, src.FileCount)
	}

	require.Len(t, report.Vaults, 1)
	v := report.Vaults[0]
	require.Equal(t, VerifyStatusRecoverable, v.Status, v.Message)
	require.Empty(t, v.Message)
	require.Equal(t, vaultID, v.VaultID)
	require.Empty(t, v.Name) // .dr files carry no vault name
	require.Equal(t, threshold, v.Threshold)
	require.Equal(t, requestID, v.CurrentRequestID)
	require.Equal(t, n, v.SharesCounted)
	require.Equal(t, n, v.EdDSAShares)
	require.True(t, v.HasEdDSA)
	require.Zero(t, v.PendingSources)
	require.NotNil(t, v.ECDSAPub)
	require.Zero(t, v.ECDSAPub.X().Cmp(ecPub.X()))
	require.Zero(t, v.ECDSAPub.Y().Cmp(ecPub.Y()))
	require.NotNil(t, v.EdDSAPub)
	require.Zero(t, v.EdDSAPub.X().Cmp(edPub.X()))

	require.Len(t, v.Contributions, 2*n)
	for i, c := range v.Contributions {
		require.Equal(t, i, c.Source)
		require.Equal(t, ContributionCounted, c.State)
		require.Equal(t, requestID, c.RequestID)
		if i < n {
			require.Equal(t, []string{"ECDSA"}, c.Algorithms)
		} else {
			require.Equal(t, []string{"EdDSA"}, c.Algorithms)
		}
	}

	vtRequireNoSecrets(t, report, append(vtShareSecrets(ecSecret, ecShares), vtShareSecrets(edSecret, edShares)...)...)
}

func TestVerify_WithoutKeysReadsHeadersOnly(t *testing.T) {
	dir := t.TempDir()
	priv, _ := vtKeyPEM(t)
	const vaultID, requestID = "verify-locked-vault", "keygen-1"
	_, ecPub, ecShares := vtShares(t, tss.S256(), 2, 3)
	files := vtDRFiles(t, dir, "device", vaultID, requestID, "", 2, priv.EncapsulationKey(), ecPub, ecShares)

	report := vtVerify(t, files, nil)

	for _, src := range report.Sources {
		require.Equal(t, VerifyLevelHeader, src.Level)
		require.Empty(t, src.Error)
	}
	v := vtVault(t, report, vaultID)
	require.Equal(t, VerifyStatusNotChecked, v.Status)
	require.Contains(t, v.Message, "header only")
	require.Zero(t, v.Threshold)
	require.Zero(t, v.SharesCounted)
	require.Nil(t, v.ECDSAPub)
	require.Equal(t, 3, v.PendingSources)
	require.Len(t, v.Contributions, 3)
	for _, c := range v.Contributions {
		require.Equal(t, ContributionHeader, c.State)
		require.Equal(t, requestID, c.RequestID)
		require.Equal(t, []string{"ECDSA"}, c.Algorithms)
	}
}

// A wrong mnemonic makes that one file an error; the rest of the report still stands.
func TestVerify_WrongMnemonicIsThatFilesError(t *testing.T) {
	dir := t.TempDir()
	const vaultID, requestID = "verify-mobile-vault", "req-1"
	ecSecret, ecPub, shares := vtShares(t, tss.S256(), 2, 2)

	good := vtMobileFile(t, dir, "device0.json", vtMnemonicI, vaultID, requestID, 2, shares[0], ecPub)
	bad := vtMobileFile(t, dir, "device1.json", vtMnemonicI, vaultID, requestID, 2, shares[1], ecPub)
	report := vtVerify(t, []ui.VaultsDataFile{
		{File: good, Mnemonics: vtMnemonicI},
		{File: bad, Mnemonics: vtMnemonicL}, // a valid phrase, but not this file's
	}, nil)

	require.Len(t, report.Sources, 2)
	require.Equal(t, VerifyLevelDecrypted, report.Sources[0].Level)
	require.Equal(t, SourceKindMobileExport, report.Sources[0].Kind)
	require.Equal(t, VerifyLevelError, report.Sources[1].Level)
	require.NotEmpty(t, report.Sources[1].Error)

	v := vtVault(t, report, vaultID)
	require.Equal(t, VerifyStatusBelowThreshold, v.Status)
	require.Equal(t, 2, v.Threshold)
	require.Equal(t, 1, v.SharesCounted)
	require.Equal(t, requestID, v.CurrentRequestID)
	require.Contains(t, v.Message, "1 of 2")
	require.Len(t, v.Contributions, 2)
	require.Equal(t, ContributionCounted, v.Contributions[0].State)
	require.Equal(t, ContributionError, v.Contributions[1].State)
	require.Equal(t, requestID, v.Contributions[1].RequestID) // from the locked file's header

	vtRequireNoSecrets(t, report, append(vtShareSecrets(ecSecret, shares), vtMnemonicI, vtMnemonicL)...)
}

func TestVerify_MobileWithoutMnemonicIsHeaderOnly(t *testing.T) {
	dir := t.TempDir()
	const vaultID, requestID = "verify-mobile-locked", "req-7"
	_, ecPub, shares := vtShares(t, tss.S256(), 2, 2)
	path := vtMobileFile(t, dir, "device0.json", vtMnemonicI, vaultID, requestID, 2, shares[0], ecPub)

	report := vtVerify(t, []ui.VaultsDataFile{{File: path}}, nil)

	require.Equal(t, VerifyLevelHeader, report.Sources[0].Level)
	v := vtVault(t, report, vaultID)
	require.Equal(t, VerifyStatusNotChecked, v.Status)
	require.Equal(t, 1, v.PendingSources)
	require.Equal(t, ContributionHeader, v.Contributions[0].State)
	require.Equal(t, requestID, v.Contributions[0].RequestID)
}

func TestVerify_BelowThresholdDRChain(t *testing.T) {
	dir := t.TempDir()
	priv, privPEM := vtKeyPEM(t)
	const vaultID, requestID = "verify-short-vault", "keygen-1"
	const threshold = 3
	_, ecPub, shares := vtShares(t, tss.S256(), threshold, 3)
	files := vtDRFiles(t, dir, "device", vaultID, requestID, "", threshold, priv.EncapsulationKey(), ecPub, shares[:2])

	report := vtVerify(t, files, [][]byte{privPEM})

	v := vtVault(t, report, vaultID)
	require.Equal(t, VerifyStatusBelowThreshold, v.Status)
	require.Equal(t, threshold, v.Threshold)
	require.Equal(t, 2, v.SharesCounted)
	require.Equal(t, requestID, v.CurrentRequestID)
	require.Contains(t, v.Message, "2 of 3")
	require.NotNil(t, v.ECDSAPub)
	for _, c := range v.Contributions {
		require.Equal(t, ContributionCounted, c.State)
	}
}

// Files from a superseded reshare are reported, but not counted.
func TestVerify_OlderReshareIsNotCounted(t *testing.T) {
	dir := t.TempDir()
	priv, privPEM := vtKeyPEM(t)
	const vaultID = "verify-chain-vault"
	const threshold, n = 2, 2
	_, oldPub, oldShares := vtShares(t, tss.S256(), threshold, n)
	_, newPub, newShares := vtShares(t, tss.S256(), threshold, n)

	files := vtDRFiles(t, dir, "old-device", vaultID, "keygen-1", "", threshold, priv.EncapsulationKey(), oldPub, oldShares)
	files = append(files, vtDRFiles(t, dir, "new-device", vaultID, "reshare-2", "keygen-1", threshold, priv.EncapsulationKey(), newPub, newShares)...)

	report := vtVerify(t, files, [][]byte{privPEM})

	v := vtVault(t, report, vaultID)
	require.Equal(t, VerifyStatusRecoverable, v.Status, v.Message)
	require.Equal(t, "reshare-2", v.CurrentRequestID)
	require.Equal(t, n, v.SharesCounted)
	require.Zero(t, v.ECDSAPub.X().Cmp(newPub.X()))
	require.Len(t, v.Contributions, 2*n)
	for i, c := range v.Contributions {
		if i < n {
			require.Equal(t, ContributionOtherReshare, c.State)
			require.Equal(t, "keygen-1", c.RequestID)
		} else {
			require.Equal(t, ContributionCounted, c.State)
			require.Equal(t, "reshare-2", c.RequestID)
		}
	}
}

func TestVerify_V4MobileThresholdUnknown(t *testing.T) {
	dir := t.TempDir()
	const vaultID, requestID = "verify-v4-vault", "req-1"
	_, ecPub, shares := vtShares(t, tss.S256(), 2, 2)
	files := []ui.VaultsDataFile{
		{File: vtMobileFile(t, dir, "device0.json", vtMnemonicI, vaultID, requestID, 0, shares[0], ecPub), Mnemonics: vtMnemonicI},
		{File: vtMobileFile(t, dir, "device1.json", vtMnemonicI, vaultID, requestID, 0, shares[1], ecPub), Mnemonics: vtMnemonicI},
	}

	report := vtVerify(t, files, nil)

	v := vtVault(t, report, vaultID)
	require.Equal(t, VerifyStatusThresholdUnknown, v.Status)
	require.Zero(t, v.Threshold)
	require.Equal(t, 2, v.SharesCounted)
	require.Contains(t, v.Message, "threshold")
}

// Two different files holding the same share would break reconstruction.
func TestVerify_DuplicateShareIsConflict(t *testing.T) {
	dir := t.TempDir()
	const vaultID, requestID = "verify-dup-vault", "req-1"
	_, ecPub, shares := vtShares(t, tss.S256(), 2, 2)
	// Same share, encrypted twice: different bytes, so input dedup keeps both.
	files := []ui.VaultsDataFile{
		{File: vtMobileFile(t, dir, "export-a.json", vtMnemonicI, vaultID, requestID, 2, shares[0], ecPub), Mnemonics: vtMnemonicI},
		{File: vtMobileFile(t, dir, "export-b.json", vtMnemonicI, vaultID, requestID, 2, shares[0], ecPub), Mnemonics: vtMnemonicI},
	}

	report := vtVerify(t, files, nil)

	v := vtVault(t, report, vaultID)
	require.Equal(t, VerifyStatusConflict, v.Status)
	require.Contains(t, v.Message, "same share")
	for _, c := range v.Contributions {
		require.Equal(t, ContributionConflict, c.State)
	}
}

// Real mobile app exports from test-files: the vault recovered by TestTool_New_V2_Export_lqns.
func TestVerify_FixtureExports(t *testing.T) {
	files := []ui.VaultsDataFile{
		{File: "../../test-files/new_bvn.json", Mnemonics: vtMnemonicNewBvn},
		{File: "../../test-files/new_x2q.json", Mnemonics: vtMnemonicNewX2q},
		{File: "../../test-files/new_u44.json", Mnemonics: vtMnemonicNewU44},
	}

	report := vtVerify(t, files, nil)

	require.Len(t, report.Sources, 3)
	for _, src := range report.Sources {
		require.Equal(t, VerifyLevelDecrypted, src.Level, src.Error)
	}
	require.Len(t, report.Vaults, 14)

	v := vtVault(t, report, "yz5x2a7zhwwt7r0lv4gklqns")
	require.Equal(t, VerifyStatusRecoverable, v.Status, v.Message)
	require.GreaterOrEqual(t, v.SharesCounted, v.Threshold)
	require.True(t, v.HasEdDSA)
	require.NotNil(t, v.ECDSAPub)
	require.NotNil(t, v.EdDSAPub)

	// The private keys TestTool_New_V2_Export_lqns reconstructs must never appear.
	vtRequireNoSecrets(t, report,
		"4cc05b1d3216da8ef91729744159019b25ea1ed5932e387199f1de6ff6667ac2",
		"0e6f0e12d72483d32255000d01242fa4e179b9bbfa060de26cfb9c84e1d02d9e",
		vtMnemonicNewBvn, vtMnemonicNewX2q, vtMnemonicNewU44)
}

func TestVerify_NilInputs(t *testing.T) {
	_, err := Verify(nil, nil, ErrorPresentation{})
	require.Error(t, err)
}
