// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package dr

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	ecdsa_keygen "github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
	eddsa_keygen "github.com/iofinnet/tss-lib/v3/tss/schnorr/keygen"
)

// MobileShare is one opaque share blob in a mobile backup's decrypted request payload. Data is the
// base64 of the SAME PrivateECDSASharesAndVaultId / PrivateEdDSASharesAndVaultId JSON a Virtual
// Signer .dr file carries after decryption, keyed by (Algorithm, Curve). This is why a mobile
// share reconstructs through the identical path as a .dr share (see ECDSASharesAndVaultId).
type MobileShare struct {
	Algorithm string `json:"algorithm"`
	Curve     string `json:"curve"`
	Data      string `json:"data"`
}

// MobileSharePayload is the v5 decrypted per-request payload: the epoch's Threshold wrapped around
// its share blobs. v5 bakes the threshold in (mirroring the .dr payload's own Threshold) so the
// offline recovery tool no longer needs it from an API; legacy v4 payloads are the bare share
// array with no threshold (see ParseMobileSharePayload).
type MobileSharePayload struct {
	Threshold int           `json:"threshold"`
	Shares    []MobileShare `json:"shares"`
}

// MobileParsed is the reconstruction-ready result of decoding a mobile request payload: tss-lib
// save data plus the epoch threshold when the payload carried one.
type MobileParsed struct {
	// HasThreshold is false for a legacy v4 payload (bare share array, no threshold); the caller
	// must then source the threshold from a flag or fail — it must NOT borrow one from a .dr file.
	HasThreshold bool
	Threshold    int
	// VaultId is the vault ID embedded in every share's own AEAD-authenticated payload. The
	// caller MUST compare this against the outer vault key it filed the payload under (e.g. the
	// mobile backup's vault map key) and reject a mismatch, so a payload that decrypts correctly
	// but was mislabelled (or maliciously relabelled) can't reconstruct the wrong vault's key
	// under the selected vault's identity.
	VaultId  string
	ECDSA    []*ecdsa_keygen.LocalPartySaveData
	EdDSA    []*eddsa_keygen.LocalPartySaveData
	HasEdDSA bool
}

// ParseMobileSharePayload decodes a decrypted mobile-backup request payload into tss-lib save data.
// It accepts both shapes a mobile export can produce:
//   - v5 object: {"threshold": N, "shares": [{"algorithm","curve","data"}, ...]}
//   - legacy v4: the bare [{"algorithm","curve","data"}, ...] array (no threshold)
//
// Each share's Data is base64 of a PrivateECDSASharesAndVaultId (algorithm "ECDSA") or
// PrivateEdDSASharesAndVaultId (algorithm "EDDSA") JSON, decoded via ECDSASharesAndVaultId /
// EdDSASharesAndVaultId — the same types the .dr path unmarshals — so mobile and VS shares merge
// into one reconstruction. Callers should only pass payloads from v4/v5 mobile vault entries;
// legacy flat-nonce entries decrypt to a ClearVault object and are handled elsewhere.
func ParseMobileSharePayload(plaintext []byte) (*MobileParsed, error) {
	trimmed := bytes.TrimSpace(plaintext)
	var payload MobileSharePayload
	if len(trimmed) > 0 && trimmed[0] == '[' {
		// Legacy v4: the payload is the bare shares array, with no surrounding threshold.
		if err := json.Unmarshal(trimmed, &payload.Shares); err != nil {
			return nil, fmt.Errorf("invalid mobile v4 share array: %w", err)
		}
	} else {
		// v5: {threshold, shares}.
		if err := json.Unmarshal(trimmed, &payload); err != nil {
			return nil, fmt.Errorf("invalid mobile v5 share payload: %w", err)
		}
	}
	if len(payload.Shares) == 0 {
		return nil, fmt.Errorf("mobile share payload carries no shares")
	}

	out := &MobileParsed{}
	if payload.Threshold > 0 {
		out.HasThreshold = true
		out.Threshold = payload.Threshold
	}

	for _, sh := range payload.Shares {
		raw, err := base64.StdEncoding.DecodeString(sh.Data)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 in mobile share data (%s/%s): %w", sh.Algorithm, sh.Curve, err)
		}
		var shareVaultId string
		switch strings.ToUpper(sh.Algorithm) {
		case "ECDSA":
			var s ECDSASharesAndVaultId
			if err := json.Unmarshal(raw, &s); err != nil {
				return nil, fmt.Errorf("invalid ECDSA mobile share payload: %w", err)
			}
			saves, err := s.ToECDSASaveData()
			if err != nil {
				return nil, err
			}
			out.ECDSA = append(out.ECDSA, saves...)
			shareVaultId = s.VaultId
		case "EDDSA":
			var s EdDSASharesAndVaultId
			if err := json.Unmarshal(raw, &s); err != nil {
				return nil, fmt.Errorf("invalid EdDSA mobile share payload: %w", err)
			}
			saves, err := s.ToEdDSASaveData()
			if err != nil {
				return nil, err
			}
			out.EdDSA = append(out.EdDSA, saves...)
			out.HasEdDSA = true
			shareVaultId = s.VaultId
		default:
			return nil, fmt.Errorf("unknown mobile share algorithm %q (expected ECDSA or EDDSA)", sh.Algorithm)
		}
		if shareVaultId == "" {
			return nil, fmt.Errorf("mobile share (%s/%s) does not carry a vault id", sh.Algorithm, sh.Curve)
		}
		if out.VaultId == "" {
			out.VaultId = shareVaultId
		} else if out.VaultId != shareVaultId {
			return nil, fmt.Errorf("mobile share payload carries disagreeing vault ids (%s vs %s)", out.VaultId, shareVaultId)
		}
	}
	return out, nil
}
