// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package recoverypipeline

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
)

type zipEntry struct {
	name string
	data []byte
	mode os.FileMode // zero means regular 0644
}

func buildZip(t *testing.T, entries []zipEntry) string {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			hdr.SetMode(e.mode)
		}
		fw, err := w.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("create %s: %v", e.name, err)
		}
		if _, err := fw.Write(e.data); err != nil {
			t.Fatalf("write %s: %v", e.name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}

	zipPath := filepath.Join(t.TempDir(), "bundle.zip")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	return zipPath
}

func manifestV2(t *testing.T, signerID string, vaults map[string]map[string][]byte) []byte {
	t.Helper()
	return manifestV2Raw(t, signerID, vaults, nil)
}

func manifestV2Raw(t *testing.T, signerID string, vaults map[string]map[string][]byte, mutate func(map[string]any)) []byte {
	t.Helper()

	m := map[string]any{"formatVersion": 2, "signerId": signerID}
	var vs []map[string]any
	for vaultID, files := range vaults {
		var fs []map[string]any
		for p, data := range files {
			sum := sha256.Sum256(data)
			fs = append(fs, map[string]any{
				"path": p, "sha256": hex.EncodeToString(sum[:]), "bytes": len(data),
			})
		}
		vs = append(vs, map[string]any{"vaultId": vaultID, "currentRequestId": "req-" + vaultID, "files": fs})
	}
	m["vaults"] = vs
	if mutate != nil {
		mutate(m)
	}

	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return raw
}

func hasCode(warnings []Warning, code WarningCode) bool {
	return countCode(warnings, code) > 0
}

func countCode(warnings []Warning, code WarningCode) int {
	n := 0
	for _, w := range warnings {
		if w.Code == code {
			n++
		}
	}
	return n
}

func TestExpandBundle(t *testing.T) {
	const drPath = "dr/v/s/r.ecdsa.secp256k1.dr"
	payload := []byte("ciphertext")

	t.Run("healthy v2", func(t *testing.T) {
		pathA := "dr/vault-a/signer/req.ecdsa.secp256k1.dr"
		pathB := "dr/vault-a/signer/req.eddsa.ed25519.dr"
		a, b := []byte("ciphertext-a"), []byte("ciphertext-b")
		man := manifestV2(t, "signer-1", map[string]map[string][]byte{
			"vault-a": {pathA: a, pathB: b},
		})
		zipPath := buildZip(t, []zipEntry{
			{name: "manifest.json", data: man},
			{name: pathA, data: a},
			{name: pathB, data: b},
		})
		tempDir := t.TempDir()

		artifacts, info, warnings, err := expandBundle(zipPath, tempDir, ErrorPresentation{})
		if err != nil {
			t.Fatal(err)
		}
		if hasCode(warnings, WarningManifestIgnored) || len(artifacts) != 2 {
			t.Fatalf("artifacts=%d warnings=%v", len(artifacts), warnings)
		}
		if info == nil || info.SignerID != "signer-1" || info.CurrentRequestIDs["vault-a"] != "req-vault-a" {
			t.Fatalf("BundleInfo: %+v", info)
		}
		for _, art := range artifacts {
			if art.SourceID != filepath.Base(zipPath) || art.Mnemonics != "" || !strings.HasPrefix(art.Path, tempDir) {
				t.Fatalf("artifact: %+v", art)
			}
		}
	})

	t.Run("bad manifest still expands", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			man  []byte
		}{
			{name: "v1", man: []byte(`{"formatVersion":1,"signerId":"s","vaults":[]}`)},
			{name: "v3", man: []byte(`{"formatVersion":3,"signerId":"s","vaults":[]}`)},
			{name: "corrupt", man: []byte(`{not-json`)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				zipPath := buildZip(t, []zipEntry{
					{name: "manifest.json", data: tc.man},
					{name: drPath, data: payload},
				})
				artifacts, info, warnings, err := expandBundle(zipPath, t.TempDir(), ErrorPresentation{})
				if err != nil {
					t.Fatal(err)
				}
				if info != nil || len(artifacts) != 1 || !hasCode(warnings, WarningManifestIgnored) {
					t.Fatalf("info=%v artifacts=%d warnings=%v", info, len(artifacts), warnings)
				}
			})
		}
	})

	t.Run("reconcile warns but keeps", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			code WarningCode
			mut  func(map[string]any)
		}{
			{
				name: "problems",
				code: WarningBundleFileProblem,
				mut: func(m map[string]any) {
					m["vaults"].([]map[string]any)[0]["files"].([]map[string]any)[0]["problems"] = []string{"envelope-parse-failed"}
				},
			},
			{
				name: "hash mismatch",
				code: WarningBundleFileMismatch,
				mut: func(m map[string]any) {
					m["vaults"].([]map[string]any)[0]["files"].([]map[string]any)[0]["sha256"] = strings.Repeat("0", 64)
				},
			},
			{
				name: "bytes mismatch",
				code: WarningBundleFileMismatch,
				mut: func(m map[string]any) {
					f := m["vaults"].([]map[string]any)[0]["files"].([]map[string]any)[0]
					f["bytes"] = len(payload) + 1
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				man := manifestV2Raw(t, "s", map[string]map[string][]byte{"v": {drPath: payload}}, tc.mut)
				zipPath := buildZip(t, []zipEntry{{name: "manifest.json", data: man}, {name: drPath, data: payload}})
				artifacts, _, warnings, err := expandBundle(zipPath, t.TempDir(), ErrorPresentation{})
				if err != nil {
					t.Fatal(err)
				}
				if len(artifacts) != 1 || !hasCode(warnings, tc.code) {
					t.Fatalf("artifacts=%d warnings=%v", len(artifacts), warnings)
				}
			})
		}
	})

	t.Run("declared absent and undeclared extra", func(t *testing.T) {
		keptPath := "dr/v/s/kept.ecdsa.secp256k1.dr"
		missingPath := "dr/v/s/missing.ecdsa.secp256k1.dr"
		extraPath := "dr/v/s/extra.ecdsa.secp256k1.dr"
		kept, extra := []byte("kept"), []byte("extra")
		man := manifestV2(t, "s", map[string]map[string][]byte{
			"v": {keptPath: kept, missingPath: []byte("absent")},
		})
		zipPath := buildZip(t, []zipEntry{
			{name: "manifest.json", data: man},
			{name: keptPath, data: kept},
			{name: extraPath, data: extra},
		})

		artifacts, _, warnings, err := expandBundle(zipPath, t.TempDir(), ErrorPresentation{})
		if err != nil {
			t.Fatal(err)
		}
		if len(artifacts) != 2 {
			t.Fatalf("want kept+extra, got %d", len(artifacts))
		}

		var sawAbsent, sawUndeclared bool
		for _, w := range warnings {
			if w.Code != WarningBundleFileMismatch {
				continue
			}
			if strings.Contains(w.Message, missingPath) {
				sawAbsent = true
			}
			if strings.Contains(w.Message, extraPath) {
				sawUndeclared = true
			}
		}
		if !sawAbsent || !sawUndeclared {
			t.Fatalf("absent=%v undeclared=%v warnings=%v", sawAbsent, sawUndeclared, warnings)
		}
	})

	t.Run("classification", func(t *testing.T) {
		drUpper := "dr/v/s/r.ecdsa.secp256k1.DR"
		man := manifestV2(t, "s", map[string]map[string][]byte{"v": {drUpper: payload}})
		zipPath := buildZip(t, []zipEntry{
			{name: "manifest.json", data: man},
			{name: "readme.txt", data: []byte("nope")},
			{name: "__MACOSX/._junk", data: []byte("meta")},
			{name: drUpper, data: payload},
		})

		artifacts, _, warnings, err := expandBundle(zipPath, t.TempDir(), ErrorPresentation{})
		if err != nil {
			t.Fatal(err)
		}
		if len(artifacts) != 1 {
			t.Fatalf("artifacts: got %d, want 1 (.DR kept)", len(artifacts))
		}
		if !hasCode(warnings, WarningBundleEntryIgnored) {
			t.Fatalf("want entry-ignored for readme.txt, got %v", warnings)
		}
		for _, w := range warnings {
			if strings.Contains(w.Message, "__MACOSX") {
				t.Fatalf("macosx should be silent, got %v", w)
			}
		}
	})

	t.Run("rejects unsafe entries", func(t *testing.T) {
		man := manifestV2(t, "s", map[string]map[string][]byte{"v": {drPath: payload}})
		parent := t.TempDir()
		escapeTarget := filepath.Join(parent, "escape.dr")
		zipPath := buildZip(t, []zipEntry{
			{name: "manifest.json", data: man},
			{name: "../escape.dr", data: []byte("evil")},
			{name: `/abs.dr`, data: []byte("evil")},
			{name: `..\evil.dr`, data: []byte("evil")},
			{name: "link.dr", data: []byte("target"), mode: os.ModeSymlink | 0o777},
			{name: drPath, data: payload},
		})
		tempDir := filepath.Join(parent, "out")
		if err := os.MkdirAll(tempDir, 0o700); err != nil {
			t.Fatal(err)
		}

		artifacts, _, warnings, err := expandBundle(zipPath, tempDir, ErrorPresentation{})
		if err != nil {
			t.Fatal(err)
		}
		if len(artifacts) != 1 {
			t.Fatalf("artifacts: got %d, want 1", len(artifacts))
		}
		if countCode(warnings, WarningBundleEntryIgnored) < 4 {
			t.Fatalf("want >=4 entry-ignored, got %v", warnings)
		}
		// Strongest available filesystem assertion: the specific escape target must not exist.
		if _, err := os.Stat(escapeTarget); !os.IsNotExist(err) {
			t.Fatalf("escape target %s exists (err=%v)", escapeTarget, err)
		}
	})

	t.Run("collisions first wins", func(t *testing.T) {
		man := manifestV2(t, "s", map[string]map[string][]byte{"v": {drPath: []byte("first")}})
		zipPath := buildZip(t, []zipEntry{
			{name: "manifest.json", data: man},
			{name: drPath, data: []byte("first")},
			{name: drPath, data: []byte("second")},
			{name: strings.ToUpper(drPath), data: []byte("CASE")},
		})

		artifacts, _, warnings, err := expandBundle(zipPath, t.TempDir(), ErrorPresentation{})
		if err != nil {
			t.Fatal(err)
		}
		if len(artifacts) != 1 {
			t.Fatalf("first wins: got %d artifacts", len(artifacts))
		}
		got, err := os.ReadFile(artifacts[0].Path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "first" {
			t.Fatalf("content=%q, want first", got)
		}
		if countCode(warnings, WarningBundleEntryIgnored) < 2 {
			t.Fatalf("want collision warnings, got %v", warnings)
		}
	})
}

func TestExtractEntry_RespectsLimit(t *testing.T) {
	zipPath := buildZip(t, []zipEntry{{name: "x.dr", data: bytes.Repeat([]byte("a"), 100)}})
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	dest := filepath.Join(t.TempDir(), "x.dr")
	written, _, err := extractEntry(r.File[0], dest, 10)
	if err == nil {
		t.Fatal("expected cap error")
	}
	if written <= 10 {
		t.Fatalf("written=%d, want >10 (limit+1 read)", written)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatal("dest should be removed on failure")
	}
}

func TestDiscoverArtifacts(t *testing.T) {
	payload := []byte("same-bytes")
	drPath := "dr/v/s/r.ecdsa.secp256k1.dr"
	man := manifestV2(t, "s", map[string]map[string][]byte{"v": {drPath: payload}})
	bundle := buildZip(t, []zipEntry{
		{name: "manifest.json", data: man},
		{name: drPath, data: payload},
	})

	t.Run("bundle direct and legacy zip", func(t *testing.T) {
		direct := filepath.Join(t.TempDir(), "loose.dr")
		if err := os.WriteFile(direct, []byte("different-loose"), 0o600); err != nil {
			t.Fatal(err)
		}
		legacyZip := buildZip(t, []zipEntry{{name: "share.json", data: []byte(`{}`)}})

		artifacts, bundles, _, cleanup, err := discoverArtifacts([]ui.VaultsDataFile{
			{File: bundle},
			{File: direct, Mnemonics: "abandon art"},
			{File: legacyZip},
		}, ErrorPresentation{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cleanup() })

		if len(bundles) != 1 || bundles[0].SignerID != "s" {
			t.Fatalf("bundles: %+v", bundles)
		}
		if len(artifacts) != 3 {
			t.Fatalf("artifacts: got %d, want 3", len(artifacts))
		}
		if artifacts[1].Mnemonics != "abandon art" || artifacts[2].Path != legacyZip {
			t.Fatalf("artifacts: %+v", artifacts)
		}
	})

	t.Run("dedup first wins", func(t *testing.T) {
		loose := filepath.Join(t.TempDir(), "copy.dr")
		if err := os.WriteFile(loose, payload, 0o600); err != nil {
			t.Fatal(err)
		}

		artifacts, _, warnings, cleanup, err := discoverArtifacts([]ui.VaultsDataFile{
			{File: bundle},
			{File: loose},
			{File: filepath.Join(t.TempDir(), "other.dr")}, // unreadable: kept for decode
		}, ErrorPresentation{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cleanup() })

		// bundle artifact + unreadable; loose copy dropped
		if len(artifacts) != 2 {
			t.Fatalf("artifacts: got %d, want 2", len(artifacts))
		}
		if !hasCode(warnings, WarningDuplicateArtifact) {
			t.Fatalf("want duplicate warning, got %v", warnings)
		}
	})

	t.Run("two loose copies", func(t *testing.T) {
		dir := t.TempDir()
		a := filepath.Join(dir, "a.dr")
		b := filepath.Join(dir, "b.dr")
		if err := os.WriteFile(a, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(b, payload, 0o600); err != nil {
			t.Fatal(err)
		}

		artifacts, _, warnings, cleanup, err := discoverArtifacts([]ui.VaultsDataFile{
			{File: a}, {File: b},
		}, ErrorPresentation{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cleanup() })

		if len(artifacts) != 1 || artifacts[0].Path != a {
			t.Fatalf("first wins: %+v", artifacts)
		}
		if !hasCode(warnings, WarningDuplicateArtifact) {
			t.Fatalf("want duplicate warning, got %v", warnings)
		}
	})
}

// A hostile archive can hold many entries that each blow their per-entry extraction cap.
// The bytes are decompressed and thrown away, so the walk must still charge them and end.
// Scale is forced by entryCapFloorBytes: the cap has to bind before the bundle budget does.
func TestProcessBundleEntry_ChargesFailedExtractions(t *testing.T) {
	if testing.Short() {
		t.Skip("decompresses ~64 MiB to make the per-entry cap bind")
	}

	payload := bytes.Repeat([]byte("a"), int(entryCapFloorBytes+miB))
	zipPath := buildZip(t, []zipEntry{
		{name: "a.dr", data: payload},
		{name: "b.dr", data: payload},
	})
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	// Declared with a tiny claimed size, so entryCap is the 64 MiB floor and binds first.
	declared := map[string]declaredFile{}
	for _, name := range []string{"a.dr", "b.dr"} {
		declared[name] = declaredFile{vaultID: "v", manifestFile: manifestFile{Path: name, Bytes: 1}}
	}
	st := &expandState{
		tempDir:        t.TempDir(),
		sourceID:       "bundle.zip",
		declared:       declared,
		hasManifest:    true,
		bundleCap:      entryCapFloorBytes + 8*miB,
		extractedByKey: map[string]string{},
	}

	art, warnings, stop := processBundleEntry(r.File[0], st)
	if art != nil || stop {
		t.Fatalf("first entry: art=%v stop=%v, want nil/false", art, stop)
	}
	if !hasCode(warnings, WarningBundleEntryIgnored) {
		t.Fatalf("first entry: want entry-ignored, got %v", warnings)
	}
	if st.readTotal < entryCapFloorBytes {
		t.Fatalf("readTotal=%d, want the failed extract charged >=%d", st.readTotal, entryCapFloorBytes)
	}

	// Charging leaves too little budget for the next entry, so the walk stops.
	if _, _, stop = processBundleEntry(r.File[1], st); !stop {
		t.Fatal("want stop once failed extracts have spent the budget")
	}
}

func TestComputeBundleCap_ClampsByOnDiskSize(t *testing.T) {
	// Sparse file: stat reports the size without writing the bytes.
	const zipSize = 4 * miB
	zipPath := filepath.Join(t.TempDir(), "bundle.zip")
	if err := os.WriteFile(zipPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(zipPath, zipSize); err != nil {
		t.Fatal(err)
	}
	ratioClamp := maxCompressionRatio * zipSize

	t.Run("manifest claiming more than the archive can hold", func(t *testing.T) {
		got := computeBundleCap(&bundleManifest{}, 100*giB, nil, zipPath)
		if got != ratioClamp {
			t.Fatalf("cap=%d, want the %d-byte ratio clamp", got, ratioClamp)
		}
	})

	t.Run("modest manifest keeps the floor", func(t *testing.T) {
		if got := computeBundleCap(&bundleManifest{}, 1*miB, nil, zipPath); got != bundleCapFloorBytes {
			t.Fatalf("cap=%d, want floor %d", got, bundleCapFloorBytes)
		}
	})

	t.Run("overflowing claim falls back to the floor", func(t *testing.T) {
		if got := computeBundleCap(&bundleManifest{}, math.MaxInt64, nil, zipPath); got != bundleCapFloorBytes {
			t.Fatalf("cap=%d, want floor %d", got, bundleCapFloorBytes)
		}
	})
}
