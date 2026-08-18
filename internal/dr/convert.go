// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package dr

import (
	"fmt"

	"github.com/binance-chain/tss-lib/crypto"
	ecdsa_keygen "github.com/binance-chain/tss-lib/ecdsa/keygen"
	eddsa_keygen "github.com/binance-chain/tss-lib/eddsa/keygen"
)

// ToECDSASaveData converts decrypted .dr ECDSA shares into the legacy tss-lib LocalPartySaveData
// type this CLI's existing Shamir/Feldman VSS reconstruction path already operates on.
func (s *ECDSASharesAndVaultId) ToECDSASaveData() ([]*ecdsa_keygen.LocalPartySaveData, error) {
	out := make([]*ecdsa_keygen.LocalPartySaveData, 0, len(s.Data))
	for _, share := range s.Data {
		pub, err := share.ECDSAPub.toCryptoECPoint()
		if err != nil {
			return nil, fmt.Errorf("vault %s: %w", s.VaultId, err)
		}
		out = append(out, &ecdsa_keygen.LocalPartySaveData{
			LocalSecrets: ecdsa_keygen.LocalSecrets{Xi: share.Xi, ShareID: share.ShareID},
			ECDSAPub:     pub,
		})
	}
	return out, nil
}

// ToEdDSASaveData converts decrypted .dr EdDSA shares into the legacy tss-lib LocalPartySaveData
// type this CLI's existing Shamir/Feldman VSS reconstruction path already operates on.
func (s *EdDSASharesAndVaultId) ToEdDSASaveData() ([]*eddsa_keygen.LocalPartySaveData, error) {
	out := make([]*eddsa_keygen.LocalPartySaveData, 0, len(s.Data))
	for _, share := range s.Data {
		pub, err := share.EDDSAPub.toCryptoECPoint()
		if err != nil {
			return nil, fmt.Errorf("vault %s: %w", s.VaultId, err)
		}
		out = append(out, &eddsa_keygen.LocalPartySaveData{
			LocalSecrets: eddsa_keygen.LocalSecrets{Xi: share.Xi, ShareID: share.ShareID},
			EDDSAPub:     pub,
		})
	}
	return out, nil
}

func (p *ECPoint) toCryptoECPoint() (*crypto.ECPoint, error) {
	if p == nil {
		return nil, fmt.Errorf("missing public key in .dr share")
	}
	curve, err := ResolveCurve(p.Curve)
	if err != nil {
		return nil, err
	}
	return crypto.NewECPoint(curve, p.Coords[0], p.Coords[1])
}
