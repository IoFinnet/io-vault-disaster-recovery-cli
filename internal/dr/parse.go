// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package dr

import (
	"encoding/json"
	"fmt"
)

type Kind int

const (
	KindUnknown Kind = iota
	KindECDSA
	KindEdDSA
)

// Parsed holds the outcome of decrypting and classifying one .dr file.
type Parsed struct {
	Kind  Kind
	ECDSA *ECDSASharesAndVaultId
	EdDSA *EdDSASharesAndVaultId
}

// probe sniffs which of ECDSAPub/EDDSAPub is present in the first share, without
// committing to a concrete share type up front.
type probe struct {
	Data []struct {
		ECDSAPub json.RawMessage `json:"ECDSAPub"`
		EDDSAPub json.RawMessage `json:"EDDSAPub"`
	} `json:"Data"`
}

// DecryptAndParse decrypts a .dr file with the given ML-KEM-768 private key PEM, then classifies
// it as ECDSA or EdDSA by inspecting the decrypted content -- not the filename -- and unmarshals
// it into the matching mirror type.
func DecryptAndParse(pemBytes, raw []byte) (*Parsed, error) {
	plaintext, err := DecryptFile(pemBytes, raw)
	if err != nil {
		return nil, err
	}

	var p probe
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, fmt.Errorf("invalid .dr payload format: %w", err)
	}
	if len(p.Data) == 0 {
		return nil, fmt.Errorf(".dr payload contains no share data")
	}

	switch {
	case len(p.Data[0].ECDSAPub) > 0 && len(p.Data[0].EDDSAPub) == 0:
		var shares ECDSASharesAndVaultId
		if err := json.Unmarshal(plaintext, &shares); err != nil {
			return nil, fmt.Errorf("invalid ECDSA .dr payload: %w", err)
		}
		return &Parsed{Kind: KindECDSA, ECDSA: &shares}, nil
	case len(p.Data[0].EDDSAPub) > 0 && len(p.Data[0].ECDSAPub) == 0:
		var shares EdDSASharesAndVaultId
		if err := json.Unmarshal(plaintext, &shares); err != nil {
			return nil, fmt.Errorf("invalid EdDSA .dr payload: %w", err)
		}
		return &Parsed{Kind: KindEdDSA, EdDSA: &shares}, nil
	default:
		return nil, fmt.Errorf("could not determine algorithm (ECDSA/EdDSA) of .dr payload")
	}
}
