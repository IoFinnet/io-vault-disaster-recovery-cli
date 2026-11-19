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
	"strconv"
	"strings"
	"testing"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/dr"
	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
	"github.com/iofinnet/tss-lib/v3/crypto"
	"github.com/iofinnet/tss-lib/v3/crypto/vss"
	"github.com/iofinnet/tss-lib/v3/tss"
	ecdsa_keygen "github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
	eddsa_keygen "github.com/iofinnet/tss-lib/v3/tss/schnorr/keygen"
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
	return vtWriteExport(t, dir, name, map[string]any{
		vaultID: vtMobileEntry(t, mnemonic, vaultID, requestID, threshold, share, ecPub),
	})
}

// vtMobileEntry is one vault's entry in a mobile export, sealed with mnemonic.
func vtMobileEntry(t *testing.T, mnemonic, vaultID, requestID string, threshold int, share *vss.Share, ecPub *crypto.ECPoint) map[string]any {
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
	return map[string]any{
		"currentRequestId": requestID,
		"requests":         map[string]any{requestID: vtSeal(t, mnemonic, plaintext)},
	}
}

// vtLegacyFile writes a legacy flat-nonce export: one vault at one reshare nonce, whose payload is
// a ClearVault holding the given tss-lib save data as plain JSON shares.
func vtLegacyFile(t *testing.T, dir, name, mnemonic, vaultID string, nonce, threshold int, shares []*ecdsa_keygen.LocalPartySaveData) string {
	t.Helper()
	encoded := make([]string, 0, len(shares))
	for _, s := range shares {
		raw, err := json.Marshal(s)
		require.NoError(t, err)
		encoded = append(encoded, string(raw))
	}
	plaintext, err := json.Marshal(ClearVault{Name: "Legacy vault", Quroum: threshold, SharesLegacy: encoded})
	require.NoError(t, err)
	return vtWriteExport(t, dir, name, map[string]any{
		vaultID: map[string]any{strconv.Itoa(nonce): vtSeal(t, mnemonic, plaintext)},
	})
}

// vtLegacyShare is a legacy save-data share; a nil xi leaves the secret value out.
func vtLegacyShare(xi, shareID *big.Int, ecPub *crypto.ECPoint) *ecdsa_keygen.LocalPartySaveData {
	return &ecdsa_keygen.LocalPartySaveData{LocalSecrets: ecdsa_keygen.LocalSecrets{Xi: xi, ShareID: shareID}, ECDSAPub: ecPub}
}

// vtSeal encrypts plaintext the way an io.vault export does, with the mnemonic's entropy as key.
func vtSeal(t *testing.T, mnemonic string, plaintext []byte) CipheredVault {
	t.Helper()
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
	return CipheredVault{
		CipherTextB64: base64.StdEncoding.EncodeToString(sealed[:ctLen]),
		CipherParams: CipherParams{
			IV:  base64.StdEncoding.EncodeToString(nonce),
			Tag: base64.StdEncoding.EncodeToString(sealed[ctLen:]),
		},
		Cipher: "aes-256-gcm",
		Hash:   hex.EncodeToString(hash[:]),
	}
}

// vtWriteExport writes an export file holding the given vault entries.
func vtWriteExport(t *testing.T, dir, name string, vaults map[string]any) string {
	t.Helper()
	content, err := json.Marshal(map[string]any{"vaults": vaults})
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

// vtEdDSADRFiles writes one EdDSA .dr file per share for vaultID at requestID.
func vtEdDSADRFiles(t *testing.T, dir, prefix, vaultID, requestID string, threshold int,
	pub *mlkem.EncapsulationKey768, edPub *crypto.ECPoint, shares vss.Shares) []ui.VaultsDataFile {
	t.Helper()
	files := make([]ui.VaultsDataFile, 0, len(shares))
	for i, share := range shares {
		payload := &dr.EdDSASharesAndVaultId{
			Data:      []*dr.EdDSAShare{{Xi: share.Share, ShareID: share.ID, EDDSAPub: vtMirror("ed25519", edPub)}},
			VaultId:   vaultID,
			Threshold: threshold,
		}
		meta := dr.FileEnvelope{VaultId: vaultID, RequestId: requestID, Algo: "EDDSA", Curve: "ed25519"}
		files = append(files, ui.VaultsDataFile{File: vtWriteDR(t, dir, fmt.Sprintf("%s%d.eddsa.ed25519.dr", prefix, i), pub, meta, payload)})
	}
	return files
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

// --- review fixes -----------------------------------------------------------------------------

func vtPrepare(t *testing.T, files []ui.VaultsDataFile, opts Options) (*Result, error) {
	t.Helper()
	inputs, err := Discover(files, ErrorPresentation{})
	require.NoError(t, err)
	defer inputs.Close()
	return Prepare(inputs, opts)
}

// One damaged vault in a multi-vault export must not hide the shares it holds for other vaults.
func TestVerify_DamagedVaultKeepsTheExportsOtherVaults(t *testing.T) {
	dir := t.TempDir()
	const vaultA, vaultB, requestID = "verify-vault-a", "verify-vault-b", "req-1"
	_, pubA, sharesA := vtShares(t, tss.S256(), 2, 2)
	_, pubB, sharesB := vtShares(t, tss.S256(), 2, 2)

	damaged := vtMobileEntry(t, vtMnemonicI, vaultB, requestID, 2, sharesB[0], pubB)
	cv := damaged["requests"].(map[string]any)[requestID].(CipheredVault)
	cv.Hash = strings.Repeat("0", 128) // decrypts, but fails the integrity check
	damaged["requests"] = map[string]any{requestID: cv}
	mixed := vtWriteExport(t, dir, "mixed.json", map[string]any{
		vaultA: vtMobileEntry(t, vtMnemonicI, vaultA, requestID, 2, sharesA[0], pubA),
		vaultB: damaged,
	})
	other := vtMobileFile(t, dir, "other.json", vtMnemonicI, vaultA, requestID, 2, sharesA[1], pubA)

	report := vtVerify(t, []ui.VaultsDataFile{
		{File: mixed, Mnemonics: vtMnemonicI},
		{File: other, Mnemonics: vtMnemonicI},
	}, nil)

	a := vtVault(t, report, vaultA)
	require.Equal(t, VerifyStatusRecoverable, a.Status, a.Message)
	require.Equal(t, 2, a.SharesCounted)
	require.Len(t, a.Contributions, 2)
	for _, c := range a.Contributions {
		require.Equal(t, ContributionCounted, c.State)
	}

	b := vtVault(t, report, vaultB)
	require.Equal(t, VerifyStatusNotChecked, b.Status)
	require.Len(t, b.Contributions, 1)
	require.Equal(t, ContributionError, b.Contributions[0].State)

	// The export still reports its damaged vault, by name.
	require.Equal(t, VerifyLevelError, report.Sources[0].Level)
	require.Contains(t, report.Sources[0].Error, vaultB)
	require.Equal(t, VerifyLevelDecrypted, report.Sources[1].Level)
}

// A wrong mnemonic still excludes every vault of a multi-vault export.
func TestVerify_WrongMnemonicExcludesWholeMultiVaultExport(t *testing.T) {
	dir := t.TempDir()
	const vaultA, vaultB, requestID = "verify-vault-a", "verify-vault-b", "req-1"
	_, pubA, sharesA := vtShares(t, tss.S256(), 2, 2)
	_, pubB, sharesB := vtShares(t, tss.S256(), 2, 2)
	mixed := vtWriteExport(t, dir, "mixed.json", map[string]any{
		vaultA: vtMobileEntry(t, vtMnemonicI, vaultA, requestID, 2, sharesA[0], pubA),
		vaultB: vtMobileEntry(t, vtMnemonicI, vaultB, requestID, 2, sharesB[0], pubB),
	})
	other := vtMobileFile(t, dir, "other.json", vtMnemonicI, vaultA, requestID, 2, sharesA[1], pubA)

	report := vtVerify(t, []ui.VaultsDataFile{
		{File: mixed, Mnemonics: vtMnemonicL}, // a valid phrase, but not this file's
		{File: other, Mnemonics: vtMnemonicI},
	}, nil)

	require.Equal(t, VerifyLevelError, report.Sources[0].Level)
	a := vtVault(t, report, vaultA)
	require.Equal(t, VerifyStatusBelowThreshold, a.Status)
	require.Equal(t, 1, a.SharesCounted)
	require.Equal(t, ContributionError, a.Contributions[0].State)
	require.Equal(t, ContributionCounted, a.Contributions[1].State)
	b := vtVault(t, report, vaultB)
	require.Equal(t, VerifyStatusNotChecked, b.Status)
	require.Equal(t, ContributionError, b.Contributions[0].State)
}

// A verify-only Prepare pass zeroes every share value it decrypts but does not hand back.
func TestPrepare_VerifyTrackerWipesWhatItDoesNotReturn(t *testing.T) {
	dir := t.TempDir()
	priv, privPEM := vtKeyPEM(t)
	const vaultID = "wipe-vault"

	t.Run("not enough shares", func(t *testing.T) {
		_, ecPub, shares := vtShares(t, tss.S256(), 3, 3)
		files := vtDRFiles(t, dir, "short", vaultID, "keygen-1", "", 3, priv.EncapsulationKey(), ecPub, shares[:2])
		tracker := &secretTracker{}
		_, err := vtPrepare(t, files, Options{VaultID: vaultID, PrivateKeysPEM: [][]byte{privPEM}, quiet: true, secrets: tracker})
		require.ErrorIs(t, err, ErrNotEnoughShares)
		require.Len(t, tracker.xis, 2)
		for _, xi := range tracker.xis {
			require.Zero(t, xi.Sign(), "a failed pass hands nothing back, so nothing may survive")
		}
	})

	t.Run("unselected reshare and another vault", func(t *testing.T) {
		_, oldPub, oldShares := vtShares(t, tss.S256(), 2, 2)
		_, newPub, newShares := vtShares(t, tss.S256(), 2, 2)
		_, otherPub, otherShares := vtShares(t, tss.S256(), 2, 2)
		files := vtDRFiles(t, dir, "old", vaultID, "keygen-1", "", 2, priv.EncapsulationKey(), oldPub, oldShares)
		files = append(files, vtDRFiles(t, dir, "new", vaultID, "reshare-2", "keygen-1", 2, priv.EncapsulationKey(), newPub, newShares)...)
		files = append(files, vtDRFiles(t, dir, "other", "wipe-other-vault", "keygen-9", "", 2, priv.EncapsulationKey(), otherPub, otherShares[:1])...)

		tracker := &secretTracker{}
		res, err := vtPrepare(t, files, Options{VaultID: vaultID, PrivateKeysPEM: [][]byte{privPEM}, quiet: true, secrets: tracker})
		require.NoError(t, err)
		returned := make(map[*big.Int]bool)
		for _, s := range res.SharesECDSA[vaultID] {
			require.NotZero(t, s.Xi.Sign(), "the selected shares are the caller's to wipe")
			returned[s.Xi] = true
		}
		require.Len(t, returned, 2)
		require.Len(t, tracker.xis, 5)
		wiped := 0
		for _, xi := range tracker.xis {
			if !returned[xi] {
				require.Zero(t, xi.Sign())
				wiped++
			}
		}
		require.Equal(t, 3, wiped, "the older reshare's two shares and the other vault's share")
	})
}

// Thresholds that disagree at one reshare are a conflict, even when that reshare is short.
func TestVerify_ThresholdConflictWhileShortOfShares(t *testing.T) {
	dir := t.TempDir()
	priv, privPEM := vtKeyPEM(t)
	const vaultID, requestID = "verify-threshold-conflict", "reshare-1"
	_, ecPub, shares := vtShares(t, tss.S256(), 3, 3)
	files := vtDRFiles(t, dir, "device", vaultID, requestID, "", 3, priv.EncapsulationKey(), ecPub, shares[:1])
	files = append(files, ui.VaultsDataFile{
		File:      vtMobileFile(t, dir, "phone.json", vtMnemonicI, vaultID, requestID, 2, shares[1], ecPub),
		Mnemonics: vtMnemonicI,
	})

	report := vtVerify(t, files, [][]byte{privPEM})

	v := vtVault(t, report, vaultID)
	require.Equal(t, VerifyStatusConflict, v.Status, v.Message)
	require.Contains(t, v.Message, "different thresholds (2 and 3)")
	for _, c := range v.Contributions {
		require.Equal(t, ContributionConflict, c.State)
	}

	// A legacy export carries no request id, so its threshold is compared at the .dr reshare.
	legacy := vtLegacyFile(t, dir, "legacy.json", vtMnemonicI, vaultID, 1, 2, []*ecdsa_keygen.LocalPartySaveData{
		vtLegacyShare(shares[1].Share, shares[1].ID, ecPub),
	})
	report = vtVerify(t, []ui.VaultsDataFile{files[0], {File: legacy, Mnemonics: vtMnemonicI}}, [][]byte{privPEM})
	v = vtVault(t, report, vaultID)
	require.Equal(t, VerifyStatusConflict, v.Status, v.Message)
	require.Contains(t, v.Message, "different thresholds (2 and 3)")
}

// A legacy share with no secret value must not make a vault look recoverable, and recovery must
// stop on it with an error that names the file.
func TestVerify_LegacyShareWithoutXiIsRejected(t *testing.T) {
	dir := t.TempDir()
	const vaultID = "verify-legacy-no-xi"
	_, ecPub, shares := vtShares(t, tss.S256(), 2, 2)
	path := vtLegacyFile(t, dir, "legacy.json", vtMnemonicI, vaultID, 3, 2, []*ecdsa_keygen.LocalPartySaveData{
		vtLegacyShare(shares[0].Share, shares[0].ID, ecPub),
		vtLegacyShare(nil, shares[1].ID, ecPub),
	})
	files := []ui.VaultsDataFile{{File: path, Mnemonics: vtMnemonicI}}

	report := vtVerify(t, files, nil)
	require.Equal(t, VerifyLevelError, report.Sources[0].Level)
	require.Contains(t, report.Sources[0].Error, "legacy.json")
	require.Contains(t, report.Sources[0].Error, "(Xi)")
	v := vtVault(t, report, vaultID)
	require.NotEqual(t, VerifyStatusRecoverable, v.Status)
	require.Equal(t, ContributionError, v.Contributions[0].State)

	_, err := vtPrepare(t, files, Options{VaultID: vaultID, Presentation: ErrorPresentation{Path: filepath.Base}})
	require.ErrorContains(t, err, "legacy.json")
	require.ErrorContains(t, err, "(Xi)")
}

// Mobile and .dr shares without a secret value are rejected the same way.
func TestPrepare_RejectsSharesWithoutXi(t *testing.T) {
	dir := t.TempDir()
	priv, privPEM := vtKeyPEM(t)
	const vaultID, requestID = "prepare-no-xi", "req-1"
	_, ecPub, shares := vtShares(t, tss.S256(), 2, 2)
	noXi := &vss.Share{ID: shares[1].ID}

	mobile := vtMobileFile(t, dir, "phone.json", vtMnemonicI, vaultID, requestID, 2, noXi, ecPub)
	drFiles := vtDRFiles(t, dir, "device", vaultID, requestID, "", 2, priv.EncapsulationKey(), ecPub, vss.Shares{noXi})
	for name, files := range map[string][]ui.VaultsDataFile{
		"phone.json":                   {{File: mobile, Mnemonics: vtMnemonicI}},
		filepath.Base(drFiles[0].File): drFiles,
	} {
		_, err := vtPrepare(t, files, Options{VaultID: vaultID, PrivateKeysPEM: [][]byte{privPEM}, Presentation: ErrorPresentation{Path: filepath.Base}})
		require.ErrorContains(t, err, name)
		require.ErrorContains(t, err, "(Xi)")
	}
}

// Every distinct key a file states is kept for HD matching; the vault's own key still needs
// agreement.
func TestVerify_PublicKeysKeepEveryDistinctKey(t *testing.T) {
	dir := t.TempDir()
	const vaultID = "verify-two-keys"
	_, pubA, sharesA := vtShares(t, tss.S256(), 2, 2)
	_, pubB, sharesB := vtShares(t, tss.S256(), 2, 2)
	path := vtLegacyFile(t, dir, "legacy.json", vtMnemonicI, vaultID, 1, 2, []*ecdsa_keygen.LocalPartySaveData{
		vtLegacyShare(sharesA[0].Share, sharesA[0].ID, pubA),
		vtLegacyShare(sharesB[1].Share, sharesB[1].ID, pubB),
	})

	report := vtVerify(t, []ui.VaultsDataFile{{File: path, Mnemonics: vtMnemonicI}}, nil)

	var keys []*crypto.ECPoint
	for _, k := range report.PublicKeys {
		if k.VaultID == vaultID && !k.EdDSA {
			keys = append(keys, k.Point)
		}
	}
	require.Len(t, keys, 2)
	require.True(t, keys[0].Equals(pubA) || keys[1].Equals(pubA))
	require.True(t, keys[0].Equals(pubB) || keys[1].Equals(pubB))

	v := vtVault(t, report, vaultID)
	require.Equal(t, VerifyStatusConflict, v.Status)
	require.Nil(t, v.ECDSAPub)
}

// A .dr file's request link belongs to the vault its payload names, whatever its envelope says.
func TestVerify_DRRequestLinkFollowsThePayloadVault(t *testing.T) {
	dir := t.TempDir()
	priv, privPEM := vtKeyPEM(t)
	const vaultID, threshold = "verify-link-vault", 3
	_, oldPub, oldShares := vtShares(t, tss.S256(), threshold, 3)
	_, newPub, newShares := vtShares(t, tss.S256(), threshold, 3)

	// The request ids sort the wrong way round, so a lost link would make the older one look current.
	files := vtDRFiles(t, dir, "old", vaultID, "z-old", "", threshold, priv.EncapsulationKey(), oldPub, oldShares[:1])
	payload := &dr.ECDSASharesAndVaultId{
		Data:      []*dr.ECDSAShare{{Xi: newShares[0].Share, ShareID: newShares[0].ID, ECDSAPub: vtMirror("secp256k1", newPub)}},
		VaultId:   vaultID,
		Threshold: threshold,
	}
	meta := dr.FileEnvelope{VaultId: "envelope-names-another-vault", RequestId: "a-new", PreviousRequestId: "z-old", Algo: "ECDSA", Curve: "secp256k1"}
	files = append(files, ui.VaultsDataFile{File: vtWriteDR(t, dir, "new0.ecdsa.secp256k1.dr", priv.EncapsulationKey(), meta, payload)})

	report := vtVerify(t, files, [][]byte{privPEM})

	require.Len(t, report.Vaults, 1, "once decrypted, the unauthenticated envelope vault id names no vault")
	v := report.Vaults[0]
	require.Equal(t, vaultID, v.VaultID)
	require.Equal(t, VerifyStatusBelowThreshold, v.Status, v.Message)
	require.Equal(t, "a-new", v.CurrentRequestID)
	require.Equal(t, 1, v.SharesCounted)
}

// A key attributes a .dr file whose envelope has no vaultId; without one the file is an error.
func TestVerify_DRWithoutEnvelopeVaultID(t *testing.T) {
	dir := t.TempDir()
	priv, privPEM := vtKeyPEM(t)
	const vaultID = "verify-no-envelope-id"
	_, ecPub, shares := vtShares(t, tss.S256(), 2, 2)
	var files []ui.VaultsDataFile
	for i, share := range shares {
		payload := &dr.ECDSASharesAndVaultId{
			Data:      []*dr.ECDSAShare{{Xi: share.Share, ShareID: share.ID, ECDSAPub: vtMirror("secp256k1", ecPub)}},
			VaultId:   vaultID,
			Threshold: 2,
		}
		meta := dr.FileEnvelope{RequestId: "keygen-1", Algo: "ECDSA", Curve: "secp256k1"}
		files = append(files, ui.VaultsDataFile{File: vtWriteDR(t, dir, fmt.Sprintf("device%d.ecdsa.secp256k1.dr", i), priv.EncapsulationKey(), meta, payload)})
	}

	report := vtVerify(t, files, [][]byte{privPEM})
	for _, src := range report.Sources {
		require.Equal(t, VerifyLevelDecrypted, src.Level, src.Error)
	}
	v := vtVault(t, report, vaultID)
	require.Equal(t, VerifyStatusRecoverable, v.Status, v.Message)
	for _, c := range v.Contributions {
		require.Equal(t, []string{"ECDSA"}, c.Algorithms)
	}

	locked := vtVerify(t, files, nil)
	require.Empty(t, locked.Vaults)
	for _, src := range locked.Sources {
		require.Equal(t, VerifyLevelError, src.Level)
		require.Contains(t, src.Error, "missing vaultId")
	}
}

// An EdDSA shortfall is reported as such, never as a negative number of missing signers.
func TestVerify_EdDSAShortfallMessage(t *testing.T) {
	dir := t.TempDir()
	priv, privPEM := vtKeyPEM(t)
	const vaultID, requestID = "verify-eddsa-short", "keygen-1"
	_, ecPub, ecShares := vtShares(t, tss.S256(), 2, 3)
	_, edPub, edShares := vtShares(t, tss.Edwards(), 2, 3)
	files := vtDRFiles(t, dir, "device", vaultID, requestID, "", 2, priv.EncapsulationKey(), ecPub, ecShares)
	files = append(files, vtEdDSADRFiles(t, dir, "device", vaultID, requestID, 2, priv.EncapsulationKey(), edPub, edShares[:1])...)

	report := vtVerify(t, files, [][]byte{privPEM})

	v := vtVault(t, report, vaultID)
	require.Equal(t, VerifyStatusBelowThreshold, v.Status)
	require.Equal(t, 3, v.SharesCounted)
	require.Equal(t, 1, v.EdDSAShares)
	// Adding just one EdDSA backup would leave 3 ECDSA and 2 EdDSA shares, which recovery refuses,
	// so the advice pairs the curves up: match all three, or set the extra ECDSA backups aside.
	require.Equal(t, "3 ECDSA and 1 EdDSA shares found at the current reshare. Recovery uses each signer's ECDSA and EdDSA shares together, so it needs both from 2 signers. "+
		"Add the EdDSA backups of the signers whose ECDSA backups are here (2 missing), or set aside the ECDSA backups that have no EdDSA match and add both backups from 1 more signer.",
		v.Message)
}

func TestBelowThresholdMessage(t *testing.T) {
	// Whole signers missing (equal counts on both curves, or no EdDSA): the plain wording.
	require.Equal(t, "1 of 3 required shares found at the current reshare. Add backups from 2 more signers.",
		belowThresholdMessage(1, 1, true, 3))
	require.Equal(t, "2 of 3 required shares found at the current reshare. Add backups from 1 more signer.",
		belowThresholdMessage(2, 0, false, 3))
	// Unequal counts: either advice leads to equal counts of at least the threshold.
	require.Equal(t, "4 ECDSA and 1 EdDSA shares found at the current reshare. Recovery uses each signer's ECDSA and EdDSA shares together, so it needs both from 3 signers. "+
		"Add the EdDSA backups of the signers whose ECDSA backups are here (3 missing), or set aside the ECDSA backups that have no EdDSA match and add both backups from 2 more signers.",
		belowThresholdMessage(4, 1, true, 3))
	// Matching the extra backups is not enough on its own here: whole signers are missing too.
	require.Equal(t, "1 ECDSA and 2 EdDSA shares found at the current reshare. Recovery uses each signer's ECDSA and EdDSA shares together, so it needs both from 3 signers. "+
		"Add the ECDSA backups of the signers whose EdDSA backups are here (1 missing), and both backups from 1 more signer.",
		belowThresholdMessage(1, 2, true, 3))
	// Both curves meet the threshold but differ: setting the extra ones aside is enough.
	require.Equal(t, "3 ECDSA and 2 EdDSA shares found at the current reshare. Recovery uses each signer's ECDSA and EdDSA shares together, so it needs both from 2 signers. "+
		"Add the EdDSA backups of the signers whose ECDSA backups are here (1 missing), or set aside the ECDSA backups that have no EdDSA match.",
		belowThresholdMessage(3, 2, true, 2))
	require.Equal(t, "2 shares found at the current reshare, which is not enough to recover this vault.",
		belowThresholdMessage(2, 0, false, 0))
}

// Two files at the current reshare that hold the same share are a conflict, even when the reshare
// is short of shares: asking for more backups would not help while the duplicate is there.
func TestVerify_DuplicateShareWhileShortIsConflict(t *testing.T) {
	dir := t.TempDir()
	priv, privPEM := vtKeyPEM(t)
	const vaultID, requestID = "verify-dup-short", "keygen-1"
	_, ecPub, shares := vtShares(t, tss.S256(), 3, 3)
	files := vtDRFiles(t, dir, "device", vaultID, requestID, "", 3, priv.EncapsulationKey(), ecPub, vss.Shares{shares[0], shares[0]})

	v := vtVault(t, vtVerify(t, files, [][]byte{privPEM}), vaultID)
	require.Equal(t, VerifyStatusConflict, v.Status)
	require.Equal(t, duplicateShareMessage, v.Message)
}

// A share ID that recurs at an older reshare is not a duplicate: only the current reshare counts.
func TestVerify_ShareIDAtOlderReshareIsNotDuplicate(t *testing.T) {
	dir := t.TempDir()
	priv, privPEM := vtKeyPEM(t)
	const vaultID = "verify-dup-older"
	_, ecPub, shares := vtShares(t, tss.S256(), 3, 3)
	files := vtDRFiles(t, dir, "old", vaultID, "keygen-1", "", 3, priv.EncapsulationKey(), ecPub, vss.Shares{shares[0]})
	files = append(files, vtDRFiles(t, dir, "new", vaultID, "reshare-2", "keygen-1", 3, priv.EncapsulationKey(), ecPub, vss.Shares{shares[0]})...)

	v := vtVault(t, vtVerify(t, files, [][]byte{privPEM}), vaultID)
	require.Equal(t, VerifyStatusBelowThreshold, v.Status, v.Message)
	require.Equal(t, "reshare-2", v.CurrentRequestID)
	require.Equal(t, 1, v.SharesCounted)
}

// WipeShares, which recovery defers straight after Prepare, zeroes every share's secret value on
// both curves and is safe on a nil result.
func TestResult_WipeShares(t *testing.T) {
	ecdsaXi, eddsaXi := big.NewInt(12345), big.NewInt(678)
	ecdsaShare := &ecdsa_keygen.LocalPartySaveData{}
	ecdsaShare.Xi = ecdsaXi
	eddsaShare := &eddsa_keygen.LocalPartySaveData{}
	eddsaShare.Xi = eddsaXi
	res := &Result{
		SharesECDSA: VaultAllSharesECDSA{"vault": {ecdsaShare}},
		SharesEdDSA: VaultAllSharesEdDSA{"vault": {eddsaShare}},
	}
	res.WipeShares()
	require.Zero(t, ecdsaXi.Sign())
	require.Zero(t, eddsaXi.Sign())

	var none *Result
	none.WipeShares()
}
