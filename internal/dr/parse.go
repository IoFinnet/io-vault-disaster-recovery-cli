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

const (
	// SupportedFormatVersion is the .dr envelope revision this build understands. Virtual Signer
	// stamps its own revision into the envelope's formatVersion field; files written before that
	// field existed omit it entirely and are treated as version 1 (see resolveEnvelopeFormat).
	SupportedFormatVersion = 1

	// SupportedKEMSuite is the only KEM+AEAD combination this build can decrypt: an ML-KEM-768
	// encapsulation whose 32-byte shared secret keys AES-256-GCM. Files written before the
	// kemSuite field existed omit it and are assumed to use this suite, which is correct — it is
	// the only suite Virtual Signer has ever produced.
	SupportedKEMSuite = "ML-KEM-768+AES-256-GCM"
)

// FileEnvelope is the on-disk JSON structure Virtual Signer writes for a .dr file: vaultId,
// requestId, previousRequestId, algo, and curve are plaintext so operators/tooling can identify a
// DR file's epoch and algorithm without decrypting it; dataB64 is the opaque base64-encoded
// ML-KEM+AES-GCM ciphertext produced by EncryptingMarshallerForDR, decrypted out-of-band during an
// actual DR event. PreviousRequestId is the request id of the operation (keygen or prior reshare)
// that produced the shares this reshare replaced, empty for a keygen-originated file. A consumer
// walks this chain across a vault's .dr files (rather than comparing an integer nonce) to
// determine its most recent epoch.
//
// FormatVersion and KEMSuite describe the envelope revision and the cryptographic suite that
// produced DataB64. Both are omitempty because .dr files predating these fields must keep
// parsing; resolveEnvelopeFormat fills in the legacy defaults. Like every other plaintext field
// here they sit outside the AES-GCM tag and are therefore unauthenticated — they exist so an
// honest reader can fail with a precise message, not as a security control.
type FileEnvelope struct {
	FormatVersion     int    `json:"formatVersion,omitempty"`
	KEMSuite          string `json:"kemSuite,omitempty"`
	VaultId           string `json:"vaultId"`
	RequestId         string `json:"requestId"`
	PreviousRequestId string `json:"previousRequestId,omitempty"`
	Algo              string `json:"algo"`
	Curve             string `json:"curve"`
	DataB64           string `json:"dataB64"`
}

// resolveEnvelopeFormat applies the defaults for .dr files written before formatVersion/kemSuite
// existed, then rejects anything this build cannot decrypt.
//
// Doing this check *before* decryption is the whole point of the fields. A future Virtual Signer
// that rotates to, say, ML-KEM-1024 produces a 1568-byte KEM capsule where this build expects
// 1088; without an explicit suite check that mismatch reaches Decapsulate and surfaces as
// "ML-KEM decapsulation failed (wrong private key or corrupted file)" — sending an operator who
// is already mid-incident off to hunt for a key problem that does not exist. The envelope is
// unauthenticated, so a mismatch here is advisory: it tells an honest reader which tool it needs,
// and a tampered value can only cause a refusal to decrypt, never a wrong decryption.
func resolveEnvelopeFormat(envelope *FileEnvelope) error {
	if envelope.FormatVersion == 0 {
		envelope.FormatVersion = 1
	}
	if envelope.KEMSuite == "" {
		envelope.KEMSuite = SupportedKEMSuite
	}
	if envelope.FormatVersion != SupportedFormatVersion {
		return fmt.Errorf(
			".dr file declares envelope format version %d, but this recovery tool supports version %d; use a recovery tool build matching the Virtual Signer that produced this file",
			envelope.FormatVersion, SupportedFormatVersion)
	}
	if envelope.KEMSuite != SupportedKEMSuite {
		return fmt.Errorf(
			".dr file declares KEM suite %q, but this recovery tool only supports %q; use a recovery tool build matching the Virtual Signer that produced this file",
			envelope.KEMSuite, SupportedKEMSuite)
	}
	return nil
}

// Parsed holds the outcome of decrypting and classifying one .dr file.
type Parsed struct {
	Kind     Kind
	ECDSA    *ECDSASharesAndVaultId
	EdDSA    *EdDSASharesAndVaultId
	Envelope FileEnvelope
}

// DecryptAndParse parses a .dr file's JSON envelope, verifies the tool supports the envelope
// format and KEM suite it declares, decrypts its dataB64 ciphertext with the given ML-KEM-768
// private key PEM, and unmarshals the plaintext into the type matching the envelope's plaintext
// algo field. The returned Parsed.Envelope carries the resolved format fields, so a caller
// displaying it sees the effective values rather than the legacy blanks.
//
// The envelope's formatVersion/kemSuite/vaultId/requestId/previousRequestId/algo/curve fields are
// plaintext and not covered by the AES-GCM authentication tag, so callers must treat them as
// unauthenticated metadata (fine for grouping/display/diagnostics) and rely on the decrypted
// payload's own VaultId/Threshold, which is authenticated, for anything security-relevant.
func DecryptAndParse(pemBytes, raw []byte) (*Parsed, error) {
	var envelope FileEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("invalid .dr file (not a JSON envelope): %w", err)
	}
	if envelope.DataB64 == "" {
		return nil, fmt.Errorf("invalid .dr file: missing dataB64")
	}
	// Check the declared format before spending a decapsulation on it, so an unsupported suite
	// reports itself instead of masquerading as a wrong-key error.
	if err := resolveEnvelopeFormat(&envelope); err != nil {
		return nil, err
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
