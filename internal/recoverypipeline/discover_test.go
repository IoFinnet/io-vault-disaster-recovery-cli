// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package recoverypipeline

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
)

func TestDiscover_PlainFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.dr")
	if err := os.WriteFile(a, []byte(`{"vaults":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("dr-content"), 0o600); err != nil {
		t.Fatal(err)
	}

	files := []ui.VaultsDataFile{
		{File: a, Mnemonics: "word1 word2"},
		{File: b},
	}
	inputs, err := Discover(files, ErrorPresentation{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer inputs.Close()
	if len(inputs.artifacts) != 2 {
		t.Fatalf("want 2 artifacts, got %d", len(inputs.artifacts))
	}
	if inputs.artifacts[0].Path != a {
		t.Errorf("artifacts[0].Path = %q, want %q", inputs.artifacts[0].Path, a)
	}
	if inputs.artifacts[1].Path != b {
		t.Errorf("artifacts[1].Path = %q, want %q", inputs.artifacts[1].Path, b)
	}
	if inputs.artifacts[0].Mnemonics != "word1 word2" {
		t.Errorf("artifacts[0].Mnemonics = %q, want %q", inputs.artifacts[0].Mnemonics, "word1 word2")
	}
	if len(inputs.bundles) != 0 {
		t.Errorf("want 0 bundles, got %d", len(inputs.bundles))
	}
}

func TestClose_NoBundles(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "plain.json")
	if err := os.WriteFile(f, []byte(`{"vaults":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	inputs, err := Discover([]ui.VaultsDataFile{{File: f}}, ErrorPresentation{})
	if err != nil {
		t.Fatal(err)
	}
	if cerr := inputs.Close(); cerr != nil {
		t.Fatalf("Close returned error for no-bundle set: %v", cerr)
	}
}

func TestClose_RemovesBundleTempDir(t *testing.T) {
	payload := []byte("dr-payload-data")
	drPath := "dr/v/s/r.ecdsa.secp256k1.dr"
	man := manifestV2(t, "signer", map[string]map[string][]byte{"v": {drPath: payload}})
	zipPath := buildZip(t, []zipEntry{
		{name: "manifest.json", data: man},
		{name: drPath, data: payload},
	})

	inputs, err := Discover([]ui.VaultsDataFile{{File: zipPath}}, ErrorPresentation{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs.artifacts) == 0 {
		t.Fatal("expected at least one artifact from bundle")
	}

	extractedPath := inputs.artifacts[0].Path
	if _, err := os.Stat(extractedPath); err != nil {
		t.Fatalf("extracted file should exist before Close: %v", err)
	}

	if cerr := inputs.Close(); cerr != nil {
		t.Fatalf("Close returned error: %v", cerr)
	}

	if _, err := os.Stat(extractedPath); !os.IsNotExist(err) {
		t.Fatalf("extracted file should be removed after Close, stat err: %v", err)
	}
}

func TestClose_DoubleClose(t *testing.T) {
	sentinel := errors.New("injected cleanup failure")
	calls := 0
	inputs := &InputSet{cleanup: func() error {
		calls++
		return sentinel
	}}

	err1 := inputs.Close()
	err2 := inputs.Close()

	if calls != 1 {
		t.Fatalf("cleanup called %d times, want 1", calls)
	}
	if !errors.Is(err1, sentinel) {
		t.Fatalf("first Close = %v, want sentinel", err1)
	}
	if !errors.Is(err2, sentinel) {
		t.Fatalf("second Close = %v, want same sentinel error", err2)
	}
}

func TestClose_PreRemovedTempDir(t *testing.T) {
	payload := []byte("good-payload")
	drPath := "dr/v/s/r.ecdsa.secp256k1.dr"
	man := manifestV2(t, "s", map[string]map[string][]byte{"v": {drPath: payload}})
	zipPath := buildZip(t, []zipEntry{
		{name: "manifest.json", data: man},
		{name: drPath, data: payload},
	})

	inputs, err := Discover([]ui.VaultsDataFile{{File: zipPath}}, ErrorPresentation{})
	if err != nil {
		t.Fatal(err)
	}

	// Remove the extracted artifact before Close — os.RemoveAll on a nonexistent
	// path returns nil, so Close should still succeed.
	os.RemoveAll(filepath.Dir(inputs.artifacts[0].Path))

	if cerr := inputs.Close(); cerr != nil {
		t.Fatalf("Close on pre-removed temp dir should return nil, got: %v", cerr)
	}
}

// The set returned alongside an error still carries its cleanup — a (nil, err) return would
// lose it. TMPDIR points at a missing directory to fail the bundle's MkdirTemp.
func TestDiscover_ErrorReturnsClosableSet(t *testing.T) {
	payload := []byte("dr-payload-data")
	drPath := "dr/v/s/r.ecdsa.secp256k1.dr"
	man := manifestV2(t, "signer", map[string]map[string][]byte{"v": {drPath: payload}})
	zipPath := buildZip(t, []zipEntry{
		{name: "manifest.json", data: man},
		{name: drPath, data: payload},
	})
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))

	inputs, err := Discover([]ui.VaultsDataFile{{File: zipPath}}, ErrorPresentation{})
	if err == nil {
		inputs.Close()
		t.Fatal("Discover should have failed to create the bundle temp dir")
	}
	if inputs == nil {
		t.Fatal("Discover must return a non-nil set alongside its error")
	}
	if inputs.cleanup == nil {
		t.Fatal("the set returned with an error must still carry the temp-dir cleanup")
	}
	if cerr := inputs.Close(); cerr != nil {
		t.Fatalf("Close on the error-path set returned: %v", cerr)
	}
}

func TestClose_NilReceiver(t *testing.T) {
	var inputs *InputSet
	if err := inputs.Close(); err != nil {
		t.Fatalf("Close on nil receiver should return nil, got: %v", err)
	}
}

func TestDiscover_TwoPrepareCallsSameInputSet(t *testing.T) {
	files := []ui.VaultsDataFile{
		{File: "../../test-files/new_bvn.json", Mnemonics: "domain damp hill depth label eye erode dutch impulse betray floor donate bonus hover bitter ring unfold poet identify capital combine question profit april"},
		{File: "../../test-files/new_x2q.json", Mnemonics: "found midnight praise exhibit weather neutral inmate strong grass famous blind pet frozen shock avocado ring fringe planet opera license stand coil beauty capable"},
		{File: "../../test-files/new_u44.json", Mnemonics: "aerobic foam smooth immune card tragic window myth planet notice piece agree add target tortoise weather kite track spot dish dignity twice gadget spell"},
	}

	inputs, err := Discover(files, ErrorPresentation{})
	if err != nil {
		t.Fatal(err)
	}
	defer inputs.Close()

	res1, err := Prepare(inputs, Options{})
	if err != nil {
		t.Fatalf("listing Prepare: %v", err)
	}
	if len(res1.OrderedVaults) == 0 {
		t.Fatal("listing pass returned no vaults")
	}

	vaultID := res1.OrderedVaults[0].VaultID
	res2, err := Prepare(inputs, Options{VaultID: vaultID})
	if err != nil {
		t.Fatalf("recover Prepare: %v", err)
	}
	if res2.Vaults[vaultID] == nil {
		t.Fatalf("recover pass did not return vault %s", vaultID)
	}
}

func TestPrepare_DoesNotRemoveTempDir(t *testing.T) {
	payload := []byte("bundle-payload-case7")
	drPath := "dr/v/s/r.ecdsa.secp256k1.dr"
	man := manifestV2(t, "s", map[string]map[string][]byte{"v": {drPath: payload}})
	zipPath := buildZip(t, []zipEntry{
		{name: "manifest.json", data: man},
		{name: drPath, data: payload},
	})

	inputs, err := Discover([]ui.VaultsDataFile{{File: zipPath}}, ErrorPresentation{})
	if err != nil {
		t.Fatal(err)
	}
	defer inputs.Close()

	if len(inputs.artifacts) == 0 {
		t.Fatal("expected artifacts from bundle")
	}
	extractedPath := inputs.artifacts[0].Path

	// Prepare fails (the .dr file is not a real DR envelope), but the temp dir must
	// still exist afterwards — only Close removes it.
	if _, err := Prepare(inputs, Options{}); err == nil {
		t.Fatal("Prepare should have failed on a .dr file that is not a DR envelope")
	}

	if _, err := os.Stat(extractedPath); err != nil {
		t.Fatalf("extracted file should still exist after Prepare returns: %v", err)
	}

	inputs.Close()
	if _, err := os.Stat(extractedPath); !os.IsNotExist(err) {
		t.Fatalf("extracted file should be removed after Close, stat err: %v", err)
	}
}

func TestBundleCurrentRequestIDs_NilReceiver(t *testing.T) {
	var inputs *InputSet
	if got := inputs.BundleCurrentRequestIDs(); got != nil {
		t.Fatalf("nil receiver: got %v, want nil", got)
	}
}

func TestBundleCurrentRequestIDs_NoBundles(t *testing.T) {
	inputs := &InputSet{}
	got := inputs.BundleCurrentRequestIDs()
	if len(got) != 0 {
		t.Fatalf("no bundles: got %v, want empty", got)
	}
}

func TestBundleCurrentRequestIDs_SingleBundle(t *testing.T) {
	inputs := &InputSet{
		bundles: []BundleInfo{
			{SignerID: "s1", CurrentRequestIDs: map[string]string{
				"vault-a": "req-5",
				"vault-b": "req-3",
			}},
		},
	}
	got := inputs.BundleCurrentRequestIDs()
	if got["vault-a"] != "req-5" || got["vault-b"] != "req-3" {
		t.Fatalf("single bundle: got %v", got)
	}
}

func TestBundleCurrentRequestIDs_TwoBundlesAgree(t *testing.T) {
	inputs := &InputSet{
		bundles: []BundleInfo{
			{SignerID: "s1", CurrentRequestIDs: map[string]string{"vault-a": "req-5"}},
			{SignerID: "s2", CurrentRequestIDs: map[string]string{"vault-a": "req-5"}},
		},
	}
	got := inputs.BundleCurrentRequestIDs()
	if got["vault-a"] != "req-5" {
		t.Fatalf("two bundles agree: got %v", got)
	}
}

func TestBundleCurrentRequestIDs_TwoBundlesDisagree(t *testing.T) {
	inputs := &InputSet{
		bundles: []BundleInfo{
			{SignerID: "s1", CurrentRequestIDs: map[string]string{"vault-a": "req-5", "vault-b": "req-2"}},
			{SignerID: "s2", CurrentRequestIDs: map[string]string{"vault-a": "req-3", "vault-b": "req-2"}},
		},
	}
	got := inputs.BundleCurrentRequestIDs()
	if _, ok := got["vault-a"]; ok {
		t.Fatalf("conflicting vault should be absent, got %v", got)
	}
	if got["vault-b"] != "req-2" {
		t.Fatalf("non-conflicting vault: got %v", got)
	}
}
