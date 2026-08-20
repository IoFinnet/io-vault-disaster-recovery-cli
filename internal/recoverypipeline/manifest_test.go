// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package recoverypipeline

import (
	"errors"
	"testing"
)

func TestParseBundleManifest(t *testing.T) {
	t.Run("valid v2", func(t *testing.T) {
		raw := []byte(`{
			"formatVersion": 2,
			"createdAt": "2026-08-18T12:32:48.674153Z",
			"signerId": "signer-1",
			"integrity": {"status": "ok", "vaults": {"ok": 1}},
			"vaults": [
				{
					"vaultId": "vault-a",
					"integrity": "ok",
					"currentRequestId": "req-current",
					"files": [
						{
							"path": "dr/vault-a/signer-1/req.ecdsa.secp256k1.dr",
							"sha256": "abc",
							"bytes": 100,
							"envelope": {"formatVersion": 1, "vaultId": "vault-a", "requestId": "req-current", "algo": "ECDSA", "curve": "secp256k1"}
						},
						{
							"path": "dr/vault-a/signer-1/req.eddsa.ed25519.dr",
							"sha256": "def",
							"bytes": 50,
							"problems": ["envelope-parse-failed"]
						}
					]
				},
				{"vaultId": "vault-b", "integrity": "orphan", "files": []}
			]
		}`)

		m, err := parseBundleManifest(raw)
		if err != nil {
			t.Fatal(err)
		}
		if m.FormatVersion != 2 || m.SignerID != "signer-1" || len(m.Vaults) != 2 {
			t.Fatalf("top-level: %+v", m)
		}
		if m.Vaults[0].CurrentRequestID != "req-current" || len(m.Vaults[0].Files) != 2 {
			t.Fatalf("vault-a: %+v", m.Vaults[0])
		}
		if len(m.Vaults[0].Files[1].Problems) != 1 || m.Vaults[1].CurrentRequestID != "" {
			t.Fatalf("problems/orphan: %+v", m.Vaults)
		}
	})

	t.Run("unsupported version", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			raw  string
		}{
			{name: "v1", raw: `{"formatVersion":1,"signerId":"s","vaults":[]}`},
			{name: "v3", raw: `{"formatVersion":3,"signerId":"s","vaults":[]}`},
			{name: "absent", raw: `{"signerId":"s","vaults":[]}`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := parseBundleManifest([]byte(tc.raw))
				if !errors.Is(err, errUnsupportedManifestVersion) {
					t.Fatalf("got %v, want errUnsupportedManifestVersion", err)
				}
			})
		}
	})

	t.Run("parse errors", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			raw  string
		}{
			{name: "malformed", raw: `{not json`},
			{name: "non-numeric version", raw: `{"formatVersion":"two","signerId":"s","vaults":[]}`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := parseBundleManifest([]byte(tc.raw))
				if err == nil {
					t.Fatal("expected error")
				}
				if errors.Is(err, errUnsupportedManifestVersion) {
					t.Fatalf("should be plain parse error, got %v", err)
				}
			})
		}
	})
}
