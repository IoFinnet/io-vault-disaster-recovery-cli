// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package config

type AppConfig struct {
	Filenames      []string
	NonceOverride  int
	QuorumOverride int
	ExportKSFile   string
	PasswordForKS  string
	// New options for XRPL
	XRPLMode       bool
	XRPLDestAddr   string
	XRPLAmount     string
	XRPLTestnet    bool
	// New options for Bittensor
	BitTensorMode  bool
	BitTensorDest  string
	BitTensorAmt   string
	BitTensorEndpt string
	// New options for Solana
	SolanaMode     bool
	SolanaDestAddr string
	SolanaAmount   string
}
