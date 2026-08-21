// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package recoverypipeline

import (
	"errors"
	"strings"
	"testing"
)

func TestPickLatestDRRequestID(t *testing.T) {
	t.Run("single root, recovery mode: picks it, no error", func(t *testing.T) {
		byRequestID := map[string]*drVaultShares{
			"req-1": {},
		}
		got, err := pickLatestDRRequestID(byRequestID, "vault-a", "", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "req-1" {
			t.Fatalf("got %q, want %q", got, "req-1")
		}
	})

	t.Run("single root, listing mode: picks it, no error", func(t *testing.T) {
		byRequestID := map[string]*drVaultShares{
			"req-1": {},
			"req-2": {previousRequestId: "req-1"},
		}
		got, err := pickLatestDRRequestID(byRequestID, "vault-a", "", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "req-2" {
			t.Fatalf("got %q, want %q", got, "req-2")
		}
	})

	t.Run("several disconnected roots, listing mode: still returns a pick, no error", func(t *testing.T) {
		byRequestID := map[string]*drVaultShares{
			"epoch-a": {},
			"epoch-b": {},
			"epoch-c": {},
		}
		got, err := pickLatestDRRequestID(byRequestID, "vault-a", "", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := byRequestID[got]; !ok {
			t.Fatalf("pick %q is not one of the candidate request ids", got)
		}
	})

	t.Run("several disconnected roots, recovery mode: names every candidate id, sorted", func(t *testing.T) {
		byRequestID := map[string]*drVaultShares{
			"epoch-c": {},
			"epoch-a": {},
			"epoch-b": {},
		}
		_, err := pickLatestDRRequestID(byRequestID, "vault-a", "", false)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "candidates: epoch-a, epoch-b, epoch-c") {
			t.Fatalf("error does not name sorted candidates: %v", err)
		}
	})

	t.Run("several disconnected roots, recovery mode: still matches the sentinel via errors.Is", func(t *testing.T) {
		byRequestID := map[string]*drVaultShares{
			"epoch-a": {},
			"epoch-b": {},
		}
		_, err := pickLatestDRRequestID(byRequestID, "vault-a", "", false)
		if !errors.Is(err, ErrAmbiguousRootRequestID) {
			t.Fatalf("got %v, want errors.Is match against ErrAmbiguousRootRequestID", err)
		}
	})

	t.Run("request id override present: returns it directly, no ambiguity check", func(t *testing.T) {
		byRequestID := map[string]*drVaultShares{
			"epoch-a": {},
			"epoch-b": {},
		}
		got, err := pickLatestDRRequestID(byRequestID, "vault-a", "epoch-b", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "epoch-b" {
			t.Fatalf("got %q, want %q", got, "epoch-b")
		}
	})

	t.Run("request id override absent: not a show stopper, empty pick and no error", func(t *testing.T) {
		byRequestID := map[string]*drVaultShares{
			"epoch-a": {},
		}
		got, err := pickLatestDRRequestID(byRequestID, "vault-a", "epoch-missing", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Fatalf("got %q, want empty pick", got)
		}
	})
}
