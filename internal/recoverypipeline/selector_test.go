// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package recoverypipeline

import (
	"errors"
	"testing"

	ecdsa_keygen "github.com/binance-chain/tss-lib/ecdsa/keygen"
	eddsa_keygen "github.com/binance-chain/tss-lib/eddsa/keygen"
)

func TestHasQuorum(t *testing.T) {
	t.Run("threshold met with .dr shares alone", func(t *testing.T) {
		entry := &drVaultShares{threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 2)}
		if !hasQuorum(entry, 0, 0) {
			t.Fatal("should be viable")
		}
	})
	t.Run("threshold not met", func(t *testing.T) {
		entry := &drVaultShares{threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 1)}
		if hasQuorum(entry, 0, 0) {
			t.Fatal("should not be viable")
		}
	})
	t.Run("threshold met with extra shares from JSON path", func(t *testing.T) {
		entry := &drVaultShares{threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 1)}
		if !hasQuorum(entry, 1, 0) {
			t.Fatal("should be viable with extra ECDSA")
		}
	})
	t.Run("EdDSA present but below threshold", func(t *testing.T) {
		entry := &drVaultShares{
			threshold: 2,
			ecdsa:     make([]*ecdsa_keygen.LocalPartySaveData, 2),
			eddsa:     make([]*eddsa_keygen.LocalPartySaveData, 1),
			hasEdDSA:  true,
		}
		if hasQuorum(entry, 0, 0) {
			t.Fatal("EdDSA below threshold should not be viable")
		}
	})
	t.Run("EdDSA absent is fine", func(t *testing.T) {
		entry := &drVaultShares{threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 2)}
		if !hasQuorum(entry, 0, 0) {
			t.Fatal("no EdDSA means only ECDSA matters")
		}
	})
	t.Run("threshold zero is not viable", func(t *testing.T) {
		entry := &drVaultShares{threshold: 0, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 5)}
		if hasQuorum(entry, 0, 0) {
			t.Fatal("threshold 0 should never be viable")
		}
	})
}

func TestChainHead(t *testing.T) {
	t.Run("single entry", func(t *testing.T) {
		c := drReshareChain{"req-1": {}}
		ordered, roots := chainHead(c)
		if len(roots) != 1 || roots[0] != "req-1" {
			t.Fatalf("roots = %v, want [req-1]", roots)
		}
		if len(ordered) != 1 || ordered[0] != "req-1" {
			t.Fatalf("ordered = %v, want [req-1]", ordered)
		}
	})

	t.Run("linear chain of 3", func(t *testing.T) {
		c := drReshareChain{
			"req-1": {},
			"req-2": {previousRequestId: "req-1"},
			"req-3": {previousRequestId: "req-2"},
		}
		ordered, roots := chainHead(c)
		if len(roots) != 1 || roots[0] != "req-3" {
			t.Fatalf("roots = %v, want [req-3]", roots)
		}
		if len(ordered) != 3 || ordered[0] != "req-3" || ordered[1] != "req-2" || ordered[2] != "req-1" {
			t.Fatalf("ordered = %v, want [req-3 req-2 req-1]", ordered)
		}
	})

	t.Run("disconnected roots", func(t *testing.T) {
		c := drReshareChain{
			"branch-a": {},
			"branch-b": {},
		}
		_, roots := chainHead(c)
		if len(roots) != 2 {
			t.Fatalf("roots = %v, want 2 roots", roots)
		}
	})

	t.Run("cycle detection", func(t *testing.T) {
		c := drReshareChain{
			"req-1": {previousRequestId: "req-2"},
			"req-2": {previousRequestId: "req-1"},
		}
		ordered, roots := chainHead(c)
		if len(roots) != 2 {
			t.Fatalf("cycle should produce all nodes as roots, got %v", roots)
		}
		if len(ordered) != 2 {
			t.Fatalf("ordered should visit both nodes, got %v", ordered)
		}
	})
}

func TestDRReshareChain_Pick(t *testing.T) {
	t.Run("single reshare, viable", func(t *testing.T) {
		c := drReshareChain{
			"req-1": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 2)},
		}
		got, warns, err := c.pick("", "", jsonContribution{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "req-1" {
			t.Fatalf("got %q, want req-1", got)
		}
		if len(warns) != 0 {
			t.Fatalf("unexpected warnings: %v", warns)
		}
	})

	t.Run("linear chain, head viable", func(t *testing.T) {
		c := drReshareChain{
			"req-1": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 2)},
			"req-2": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 2), previousRequestId: "req-1"},
		}
		got, _, err := c.pick("", "", jsonContribution{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "req-2" {
			t.Fatalf("got %q, want req-2", got)
		}
	})

	t.Run("linear chain, head not viable, older is", func(t *testing.T) {
		c := drReshareChain{
			"req-1": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 2)},
			"req-2": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 1), previousRequestId: "req-1"},
		}
		got, warns, err := c.pick("", "", jsonContribution{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "req-1" {
			t.Fatalf("got %q, want req-1 (fallback)", got)
		}
		if len(warns) == 0 {
			t.Fatal("expected a fallback warning")
		}
		if warns[0].Code != WarningReshareFallback {
			t.Fatalf("warning code = %q, want %q", warns[0].Code, WarningReshareFallback)
		}
	})

	t.Run("no viable reshare", func(t *testing.T) {
		c := drReshareChain{
			"req-1": {threshold: 3, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 1)},
		}
		_, _, err := c.pick("", "", jsonContribution{})
		if err == nil {
			t.Fatal("expected error when nothing is viable")
		}
	})

	t.Run("override bypasses chain walk", func(t *testing.T) {
		c := drReshareChain{
			"req-1": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 1)},
			"req-2": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 2), previousRequestId: "req-1"},
		}
		got, _, err := c.pick("req-1", "", jsonContribution{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "req-1" {
			t.Fatalf("override should pick req-1, got %q", got)
		}
	})

	t.Run("override not in chain returns empty", func(t *testing.T) {
		c := drReshareChain{
			"req-1": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 2)},
		}
		got, _, err := c.pick("req-missing", "", jsonContribution{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Fatalf("override not in chain should return empty, got %q", got)
		}
	})

	t.Run("manifest hint viable", func(t *testing.T) {
		c := drReshareChain{
			"req-1": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 2)},
			"req-2": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 2), previousRequestId: "req-1"},
		}
		got, _, err := c.pick("", "req-1", jsonContribution{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "req-1" {
			t.Fatalf("manifest hint should pick req-1, got %q", got)
		}
	})

	t.Run("manifest hint not viable falls through to chain walk", func(t *testing.T) {
		c := drReshareChain{
			"req-1": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 2)},
			"req-2": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 1), previousRequestId: "req-1"},
		}
		got, _, err := c.pick("", "req-2", jsonContribution{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "req-1" {
			t.Fatalf("should fall back to viable req-1, got %q", got)
		}
	})

	t.Run("JSON path shares make older reshare viable", func(t *testing.T) {
		c := drReshareChain{
			"req-1": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 1)},
			"req-2": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 1), previousRequestId: "req-1"},
		}
		got, _, err := c.pick("", "", jsonContribution{RequestID: "req-1", ECDSA: 1})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "req-1" {
			t.Fatalf("JSON extras should make req-1 viable, got %q", got)
		}
	})

	t.Run("JSON path alone has quorum at different reshare: skip .dr", func(t *testing.T) {
		c := drReshareChain{
			"req-2": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 1)},
		}
		got, _, err := c.pick("", "", jsonContribution{RequestID: "req-1", ECDSA: 2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Fatalf("should skip .dr when JSON alone has quorum at different reshare, got %q", got)
		}
	})

	t.Run("disconnected roots: error", func(t *testing.T) {
		c := drReshareChain{
			"branch-a": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 2)},
			"branch-b": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 2)},
		}
		_, warns, err := c.pick("", "", jsonContribution{})
		if err == nil {
			t.Fatal("expected error for ambiguous roots")
		}
		if !errors.Is(err, ErrAmbiguousRootRequestID) {
			t.Fatalf("error should wrap ErrAmbiguousRootRequestID, got: %v", err)
		}
		if len(warns) == 0 || warns[0].Code != WarningReshareAmbiguousRoot {
			t.Fatalf("expected ambiguous root warning, got %v", warns)
		}
	})
}

func TestDRReshareChain_PickForListing(t *testing.T) {
	t.Run("picks head of chain", func(t *testing.T) {
		c := drReshareChain{
			"req-1": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 1)},
			"req-2": {threshold: 2, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 1), previousRequestId: "req-1"},
		}
		got := c.pickForListing()
		if got != "req-2" {
			t.Fatalf("got %q, want req-2", got)
		}
	})

	t.Run("empty chain returns empty", func(t *testing.T) {
		c := drReshareChain{}
		if got := c.pickForListing(); got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})

	t.Run("disconnected roots: picks lex-max", func(t *testing.T) {
		c := drReshareChain{
			"aaa": {threshold: 2},
			"zzz": {threshold: 2},
		}
		got := c.pickForListing()
		if got != "zzz" {
			t.Fatalf("got %q, want zzz (lex-max)", got)
		}
	})

	t.Run("not viable is fine for listing", func(t *testing.T) {
		c := drReshareChain{
			"req-1": {threshold: 3, ecdsa: make([]*ecdsa_keygen.LocalPartySaveData, 1)},
		}
		got := c.pickForListing()
		if got != "req-1" {
			t.Fatalf("listing should still return something, got %q", got)
		}
	})
}
