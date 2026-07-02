// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package dr

import (
	"crypto/elliptic"
	"fmt"

	"github.com/binance-chain/tss-lib/tss"
)

// ResolveCurve maps a tss-lib/v4 curve name (from a decrypted ECPoint's "Curve" field) to the
// matching curve from the legacy tss-lib fork this CLI already reconstructs with. Both libraries
// wrap the same underlying packages (btcec secp256k1, dcrd edwards), so coordinates decoded from
// v4's JSON plug directly into the existing vss.Shares.ReConstruct(curve) call.
func ResolveCurve(name string) (elliptic.Curve, error) {
	switch name {
	case "secp256k1":
		return tss.S256(), nil
	case "ed25519":
		return tss.Edwards(), nil
	default:
		return nil, fmt.Errorf("unsupported curve %q in .dr file", name)
	}
}
