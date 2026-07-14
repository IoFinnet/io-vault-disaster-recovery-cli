// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package dr

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type Kind int

const (
	KindUnknown Kind = iota
	KindECDSA
	KindEdDSA
)

// FileEnvelope is the on-disk JSON structure Virtual Signer writes for a .dr file: vaultId,
// requestId, previousRequestId, algo, and curve are plaintext so operators/tooling can identify a
// DR file's epoch and algorithm without decrypting it; dataB64 is the opaque base64-encoded
// ML-KEM+AES-GCM ciphertext produced by EncryptingMarshallerForDR, decrypted out-of-band during an
// actual DR event. PreviousRequestId is the request id of the operation (keygen or prior reshare)
// that produced the shares this reshare replaced, empty for a keygen-originated file. A consumer
// walks this chain across a vault's .dr files (rather than comparing an integer nonce) to
// determine its most recent epoch.
type FileEnvelope struct {
	VaultId           string `json:"vaultId"`
	RequestId         string `json:"requestId"`
	PreviousRequestId string `json:"previousRequestId,omitempty"`
	Algo              string `json:"algo"`
	Curve             string `json:"curve"`
	DataB64           string `json:"dataB64"`
}

// Parsed holds the outcome of decrypting and classifying one .dr file.
type Parsed struct {
	Kind     Kind
	ECDSA    *ECDSASharesAndVaultId
	EdDSA    *EdDSASharesAndVaultId
	Envelope FileEnvelope
}

// DecryptAndParse parses a .dr file's JSON envelope, decrypts its dataB64 ciphertext with the
// given ML-KEM-768 private key PEM, and unmarshals the plaintext into the type matching the
// envelope's plaintext algo field.
//
// The envelope's vaultId/requestId/previousRequestId/algo/curve fields are plaintext and not
// covered by the AES-GCM authentication tag, so callers must treat them as unauthenticated
// metadata (fine for grouping/display) and rely on the decrypted payload's own VaultId/Threshold, which is
// authenticated, for anything security-relevant.
func DecryptAndParse(pemBytes, raw []byte) (*Parsed, error) {
	var envelope FileEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("invalid .dr file (not a JSON envelope): %w", err)
	}
	if envelope.DataB64 == "" {
		return nil, fmt.Errorf("invalid .dr file: missing dataB64")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(envelope.DataB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in .dr file dataB64: %w", err)
	}

	plaintext, err := DecryptFile(pemBytes, ciphertext)
	if err != nil {
		return nil, err
	}

	switch envelope.Algo {
	case "ECDSA":
		var shares ECDSASharesAndVaultId
		if err := json.Unmarshal(plaintext, &shares); err != nil {
			return nil, fmt.Errorf("invalid ECDSA .dr payload: %w", err)
		}
		return &Parsed{Kind: KindECDSA, ECDSA: &shares, Envelope: envelope}, nil
	case "EDDSA":
		var shares EdDSASharesAndVaultId
		if err := json.Unmarshal(plaintext, &shares); err != nil {
			return nil, fmt.Errorf("invalid EdDSA .dr payload: %w", err)
		}
		return &Parsed{Kind: KindEdDSA, EdDSA: &shares, Envelope: envelope}, nil
	default:
		return nil, fmt.Errorf("unknown .dr algo %q", envelope.Algo)
	}
}
