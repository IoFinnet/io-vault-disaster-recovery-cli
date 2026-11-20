// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/xrpl"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // RIPEMD-160 is part of the Bitcoin address format
)

// Test fixture mnemonics for test-files/, shared with the root package's tests. Used only for this purpose.
const (
	fixtureMnemonicBvn    = "domain damp hill depth label eye erode dutch impulse betray floor donate bonus hover bitter ring unfold poet identify capital combine question profit april"
	fixtureMnemonicX2q    = "found midnight praise exhibit weather neutral inmate strong grass famous blind pet frozen shock avocado ring fringe planet opera license stand coil beauty capable"
	fixtureMnemonicU44    = "aerobic foam smooth immune card tragic window myth planet notice piece agree add target tortoise weather kite track spot dish dignity twice gadget spell"
	fixtureMnemonicSingle = "jacket zone rotate merry forward paper cruel forget train prevent teach bitter lumber razor uncle stairs finger chief curtain render tray tower odor garbage"
	fixtureMnemonicV2     = "ridge scare utility perfect trial van inflict feel top dice present monitor always order charge door curious lobster quick guide obvious danger crisp cinnamon"

	// The keys TestTool_New_V2_Export_lqns reconstructs for vault yz5x2a7zhwwt7r0lv4gklqns.
	fixtureLqnsVaultID    = "yz5x2a7zhwwt7r0lv4gklqns"
	fixtureLqnsAddress    = "0x620Ac72121234f1b313BD4e8b78C81323502679A"
	fixtureLqnsECDSAKey   = "4cc05b1d3216da8ef91729744159019b25ea1ed5932e387199f1de6ff6667ac2"
	fixtureLqnsEdDSAKey   = "0e6f0e12d72483d32255000d01242fa4e179b9bbfa060de26cfb9c84e1d02d9e"
	fixtureTestFilesDir   = "../../test-files"
	formFieldMnemonicPfx  = "mnemonic_"
	formFieldPrivateKey   = "privateKeyFile"
	formFieldBackupFiles  = "files"
	formFieldPastedPEMKey = "privateKey"
)

type uploadFixture struct {
	path     string
	mnemonic string // empty: no mnemonic field is sent
}

func multipartRequest(t *testing.T, target string, uploads []uploadFixture, extra func(*multipart.Writer)) *http.Request {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for _, u := range uploads {
		content, err := os.ReadFile(u.path)
		require.NoError(t, err)
		name := filepath.Base(u.path)
		part, err := form.CreateFormFile(formFieldBackupFiles, name)
		require.NoError(t, err)
		_, err = part.Write(content)
		require.NoError(t, err)
		if u.mnemonic != "" {
			require.NoError(t, form.WriteField(formFieldMnemonicPfx+strings.TrimSuffix(name, filepath.Ext(name)), u.mnemonic))
		}
	}
	if extra != nil {
		extra(form)
	}
	require.NoError(t, form.Close())

	req := httptest.NewRequest(http.MethodPost, target, &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	return req
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(ServerConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Stop() })
	// Handler tests must not depend on the test machine's own network, so they run "offline".
	s.checkNetwork = func() NetworkStatus { return NetworkStatus{Adapters: []NetworkAdapter{}} }
	return s
}

func postVerify(t *testing.T, uploads []uploadFixture) (VerifyResponse, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	newTestServer(t).handleVerify(rec, multipartRequest(t, "/api/verify", uploads, nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp VerifyResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp, rec.Body.String()
}

func findVault(t *testing.T, resp VerifyResponse, vaultID string) VerifyVaultResult {
	t.Helper()
	for _, v := range resp.Vaults {
		if v.VaultID == vaultID {
			return v
		}
	}
	t.Fatalf("vault %s not in response", vaultID)
	return VerifyVaultResult{}
}

func TestHandleVerify_AllUnlocked(t *testing.T) {
	resp, body := postVerify(t, []uploadFixture{
		{filepath.Join(fixtureTestFilesDir, "new_bvn.json"), fixtureMnemonicBvn},
		{filepath.Join(fixtureTestFilesDir, "new_x2q.json"), fixtureMnemonicX2q},
		{filepath.Join(fixtureTestFilesDir, "new_u44.json"), fixtureMnemonicU44},
	})

	require.NotEmpty(t, resp.CheckedAt)
	require.NotNil(t, resp.Warnings)
	require.Len(t, resp.Sources, 3)
	for i, name := range []string{"new_bvn.json", "new_x2q.json", "new_u44.json"} {
		require.Equal(t, name, resp.Sources[i].Name) // the uploaded name, never a temp path
		require.Equal(t, "decrypted", resp.Sources[i].Level, resp.Sources[i].Error)
		require.Equal(t, 1, resp.Sources[i].FileCount)
	}
	require.Len(t, resp.Vaults, 14)

	v := findVault(t, resp, fixtureLqnsVaultID)
	require.Equal(t, "recoverable", v.Status, v.Message)
	require.Equal(t, fixtureLqnsAddress, v.EthereumAddress)
	require.NotEmpty(t, v.EdDSAPublicKey)
	require.NotEmpty(t, v.SolanaAddress)
	require.True(t, v.HasEdDSA)

	// Bitcoin and XRP Ledger addresses must be the ones the recovered keys give, worked out here
	// from the fixture's known private keys rather than from the shares' public keys.
	ecdsaSK, err := hex.DecodeString(fixtureLqnsECDSAKey)
	require.NoError(t, err)
	compressed := secp256k1.PrivKeyFromBytes(ecdsaSK).PubKey().SerializeCompressed()
	sum := sha256.Sum256(compressed)
	h := ripemd160.New()
	h.Write(sum[:])
	hrp, data, err := bech32.Decode(v.BitcoinAddress)
	require.NoError(t, err)
	require.Equal(t, "bc", hrp)
	program, err := bech32.ConvertBits(data[1:], 5, 8, false)
	require.NoError(t, err)
	require.Equal(t, h.Sum(nil), program)

	eddsaSK, err := hex.DecodeString(fixtureLqnsEdDSAKey)
	require.NoError(t, err)
	_, edPub, err := edwards.PrivKeyFromScalar(eddsaSK)
	require.NoError(t, err)
	wantXRPL, err := xrpl.DeriveXRPLAddress(edPub.SerializeCompressed())
	require.NoError(t, err)
	require.Equal(t, wantXRPL, v.XRPLAddress)
	require.Zero(t, v.PendingSources)
	for _, c := range v.Contributions {
		require.Equal(t, "counted", c.State)
		require.NotNil(t, c.Algorithms)
	}

	// No key material and no mnemonic may leave the server, and no temp path either.
	for _, secret := range []string{fixtureLqnsECDSAKey, fixtureLqnsEdDSAKey, fixtureMnemonicBvn, fixtureMnemonicX2q, fixtureMnemonicU44} {
		require.NotContains(t, body, secret)
	}
	require.NotContains(t, body, tempDirPrefix)
}

// A file without its mnemonic is checked by its header only and counted as pending.
func TestHandleVerify_FileWithoutMnemonicIsHeaderOnly(t *testing.T) {
	resp, _ := postVerify(t, []uploadFixture{
		{filepath.Join(fixtureTestFilesDir, "new_bvn.json"), fixtureMnemonicBvn},
		{filepath.Join(fixtureTestFilesDir, "new_x2q.json"), fixtureMnemonicX2q},
		{filepath.Join(fixtureTestFilesDir, "new_u44.json"), ""},
	})

	require.Equal(t, "decrypted", resp.Sources[0].Level)
	require.Equal(t, "decrypted", resp.Sources[1].Level)
	require.Equal(t, "header", resp.Sources[2].Level)
	require.Empty(t, resp.Sources[2].Error)

	sawHeader := false
	for _, v := range resp.Vaults {
		pending := 0
		for _, c := range v.Contributions {
			if c.Source == 2 {
				require.Equal(t, "header", c.State)
				sawHeader = true
			}
			if c.State == "header" {
				pending++
			}
		}
		require.Equal(t, pending, v.PendingSources)
	}
	require.True(t, sawHeader, "the locked file should name at least one vault")
}

// A wrong mnemonic is that file's error, not a failed request.
func TestHandleVerify_WrongMnemonic(t *testing.T) {
	resp, body := postVerify(t, []uploadFixture{
		{filepath.Join(fixtureTestFilesDir, "new_single.json"), fixtureMnemonicV2},
	})

	require.Len(t, resp.Sources, 1)
	require.Equal(t, "error", resp.Sources[0].Level)
	require.NotEmpty(t, resp.Sources[0].Error)
	require.NotEmpty(t, resp.Vaults)
	for _, v := range resp.Vaults {
		require.Equal(t, "not-checked", v.Status)
		require.Len(t, v.Contributions, 1)
		require.Equal(t, "error", v.Contributions[0].State)
	}
	require.NotContains(t, body, fixtureMnemonicV2)
}

// writeBrokenZip writes a file that is named like a ZIP archive but cannot be opened as one.
func writeBrokenZip(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "broken.zip")
	require.NoError(t, os.WriteFile(path, []byte("PK\x03\x04 truncated"), 0o600))
	return path
}

// A ZIP that cannot be opened is that file's error in the report; the other uploads are checked.
func TestHandleVerify_BrokenZipIsThatFilesError(t *testing.T) {
	resp, body := postVerify(t, append(lqnsUploads(), uploadFixture{path: writeBrokenZip(t)}))

	require.Len(t, resp.Sources, 4)
	for _, src := range resp.Sources[:3] {
		require.Equal(t, "decrypted", src.Level, src.Error)
	}
	broken := resp.Sources[3]
	require.Equal(t, "broken.zip", broken.Name)
	require.Equal(t, sourceKindZipArchive, broken.Kind)
	require.Equal(t, "error", broken.Level)
	require.Contains(t, broken.Error, "broken.zip")
	require.Zero(t, broken.FileCount)
	require.NotContains(t, body, tempDirPrefix, "no temp path may leave the server")

	v := findVault(t, resp, fixtureLqnsVaultID)
	require.Equal(t, "recoverable", v.Status, v.Message)
	for _, vault := range resp.Vaults {
		for _, c := range vault.Contributions {
			require.Less(t, c.Source, 3, "the broken archive holds no shares")
		}
	}

	// Only a broken archive: still a report, with nothing else in it.
	only, _ := postVerify(t, []uploadFixture{{path: writeBrokenZip(t)}})
	require.Len(t, only.Sources, 1)
	require.Equal(t, "error", only.Sources[0].Level)
	require.Empty(t, only.Vaults)
}

// Listing keeps failing the whole request on a ZIP it cannot open.
func TestHandleListVaults_BrokenZipFailsRequest(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer(t).handleListVaults(rec, multipartRequest(t, "/api/list-vaults",
		append(lqnsUploads(), uploadFixture{path: writeBrokenZip(t)}), nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "broken.zip")
}

func TestHandleVerify_NoFiles(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer(t).handleVerify(rec, multipartRequest(t, "/api/verify", nil, func(form *multipart.Writer) {
		require.NoError(t, form.WriteField("unrelated", "value"))
	}))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleVerify_DuplicateFileNames(t *testing.T) {
	path := filepath.Join(fixtureTestFilesDir, "new_single.json")
	rec := httptest.NewRecorder()
	newTestServer(t).handleVerify(rec, multipartRequest(t, "/api/verify", []uploadFixture{{path, ""}, {path, ""}}, nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "two uploaded files are named new_single.json")
}

// The keyed field mnemonic_<name> now reaches a directly uploaded JSON file when listing too.
func TestHandleListVaults_KeyedMnemonic(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer(t).handleListVaults(rec, multipartRequest(t, "/api/list-vaults", []uploadFixture{
		{filepath.Join(fixtureTestFilesDir, "new_single.json"), fixtureMnemonicSingle},
	}, nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var vaults []map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &vaults))
	require.NotEmpty(t, vaults)
}

func TestReadPrivateKeysPEM_ReadsEveryKey(t *testing.T) {
	req := multipartRequest(t, "/api/verify", nil, func(form *multipart.Writer) {
		for _, key := range []string{"first-key", "second-key", "   "} {
			part, err := form.CreateFormFile(formFieldPrivateKey, "key.pem")
			require.NoError(t, err)
			_, err = part.Write([]byte(key))
			require.NoError(t, err)
		}
		require.NoError(t, form.WriteField(formFieldPastedPEMKey, "pasted-key"))
	})
	require.NoError(t, req.ParseMultipartForm(1<<20))

	keys, err := readPrivateKeysPEM(req)
	require.NoError(t, err)
	require.Len(t, keys, 3) // the blank upload is skipped
	require.Equal(t, "first-key", string(keys[0]))
	require.Equal(t, "second-key", string(keys[1]))
	require.Equal(t, "pasted-key", string(keys[2]))
}

func TestReadPrivateKeysPEM_None(t *testing.T) {
	req := multipartRequest(t, "/api/verify", nil, func(form *multipart.Writer) {
		require.NoError(t, form.WriteField("unrelated", "value"))
	})
	require.NoError(t, req.ParseMultipartForm(1<<20))

	keys, err := readPrivateKeysPEM(req)
	require.NoError(t, err)
	require.Nil(t, keys)
}
