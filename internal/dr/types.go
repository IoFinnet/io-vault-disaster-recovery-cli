// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package dr

import "math/big"

// ECPoint mirrors tss-lib/v4's crypto.ECPoint JSON encoding: {"Curve": "...", "Coords": [X, Y]}.
// This is a deliberate local copy, not an import of tss-lib/v4 -- see package doc in curve.go.
type ECPoint struct {
	Curve  string
	Coords [2]*big.Int
}

// ECDSAShare mirrors the fields of tss-lib/v4's tss/ecdsa/keygen.LocalPartySaveData
// needed for Shamir/Feldman VSS reconstruction.
type ECDSAShare struct {
	Xi, ShareID *big.Int
	ECDSAPub    *ECPoint
}

// EdDSAShare mirrors the fields of tss-lib/v4's tss/schnorr/keygen.LocalPartySaveData
// needed for Shamir/Feldman VSS reconstruction.
type EdDSAShare struct {
	Xi, ShareID *big.Int
	EDDSAPub    *ECPoint
}

// ECDSASharesAndVaultId mirrors the Virtual Signer's common.PrivateECDSASharesAndVaultId.
type ECDSASharesAndVaultId struct {
	Data      []*ECDSAShare
	VaultId   string
	Threshold int
}

// EdDSASharesAndVaultId mirrors the Virtual Signer's common.PrivateEdDSASharesAndVaultId.
type EdDSASharesAndVaultId struct {
	Data      []*EdDSAShare
	VaultId   string
	Threshold int
}
