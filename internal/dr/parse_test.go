// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package dr

import (
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// envelopeForTest builds a .dr file around a freshly generated key pair, returning the private key
// PEM and the marshalled envelope. Callers mutate the envelope before marshalling via mutate, which
// is how the legacy/unsupported-format cases are constructed.
func envelopeForTest(t *testing.T, payload []byte, algo string, mutate func(*FileEnvelope)) (privPEM, file []byte) {
	t.Helper()

	priv, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	privPEM = mlkemPrivateKeyPEM(t, priv.Bytes())

	envelope := FileEnvelope{
		FormatVersion: SupportedFormatVersion,
		KEMSuite:      SupportedKEMSuite,
		VaultId:       "vault-1",
		RequestId:     "req-1",
		Algo:          algo,
		Curve:         "secp256k1",
		DataB64:       base64.StdEncoding.EncodeToString(encryptForTest(t, priv.EncapsulationKey(), payload)),
	}
	if mutate != nil {
		mutate(&envelope)
	}

	file, err = json.Marshal(envelope)
	require.NoError(t, err)
	return privPEM, file
}

const ecdsaPayloadJSON = `{"Data":[{"Xi":1,"ShareID":2}],"VaultId":"vault-1","Threshold":2}`
const eddsaPayloadJSON = `{"Data":[{"Xi":3,"ShareID":4}],"VaultId":"vault-1","Threshold":2}`

func TestDecryptAndParse_ECDSAWithFormatFields(t *testing.T) {
	privPEM, file := envelopeForTest(t, []byte(ecdsaPayloadJSON), "ECDSA", nil)

	parsed, err := DecryptAndParse(privPEM, file)
	require.NoError(t, err)
	require.Equal(t, KindECDSA, parsed.Kind)
	require.NotNil(t, parsed.ECDSA)
	require.Equal(t, "vault-1", parsed.ECDSA.VaultId)
	require.Equal(t, SupportedFormatVersion, parsed.Envelope.FormatVersion)
	require.Equal(t, SupportedKEMSuite, parsed.Envelope.KEMSuite)
}

func TestDecryptAndParse_EdDSAWithFormatFields(t *testing.T) {
	privPEM, file := envelopeForTest(t, []byte(eddsaPayloadJSON), "EDDSA", nil)

	parsed, err := DecryptAndParse(privPEM, file)
	require.NoError(t, err)
	require.Equal(t, KindEdDSA, parsed.Kind)
	require.NotNil(t, parsed.EdDSA)
	require.Equal(t, SupportedKEMSuite, parsed.Envelope.KEMSuite)
}

// A .dr file written before formatVersion/kemSuite existed has neither field. It must still
// decrypt, and the resolved envelope must report the legacy defaults rather than blanks.
func TestDecryptAndParse_LegacyEnvelopeWithoutFormatFields(t *testing.T) {
	privPEM, file := envelopeForTest(t, []byte(ecdsaPayloadJSON), "ECDSA", func(e *FileEnvelope) {
		e.FormatVersion = 0
		e.KEMSuite = ""
	})

	// Guard the premise: omitempty must actually keep both keys out of the JSON, otherwise this
	// test would silently stop covering the legacy shape.
	var asMap map[string]any
	require.NoError(t, json.Unmarshal(file, &asMap))
	require.NotContains(t, asMap, "formatVersion")
	require.NotContains(t, asMap, "kemSuite")

	parsed, err := DecryptAndParse(privPEM, file)
	require.NoError(t, err)
	require.Equal(t, KindECDSA, parsed.Kind)
	require.Equal(t, 1, parsed.Envelope.FormatVersion)
	require.Equal(t, SupportedKEMSuite, parsed.Envelope.KEMSuite)
}

func TestDecryptAndParse_RejectsUnsupportedFormatVersion(t *testing.T) {
	privPEM, file := envelopeForTest(t, []byte(ecdsaPayloadJSON), "ECDSA", func(e *FileEnvelope) {
		e.FormatVersion = SupportedFormatVersion + 1
	})

	_, err := DecryptAndParse(privPEM, file)
	require.Error(t, err)
	require.Contains(t, err.Error(), "envelope format version 2")
	require.Contains(t, err.Error(), "supports version 1")
}

// The key regression this field set exists to prevent: a future parameter-set rotation must not
// be reported as a key problem. The error has to name the suite and must not mention
// decapsulation, which is what an operator would otherwise chase.
func TestDecryptAndParse_RejectsUnsupportedKEMSuiteWithoutDecapError(t *testing.T) {
	privPEM, file := envelopeForTest(t, []byte(ecdsaPayloadJSON), "ECDSA", func(e *FileEnvelope) {
		e.KEMSuite = "ML-KEM-1024+AES-256-GCM"
	})

	_, err := DecryptAndParse(privPEM, file)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ML-KEM-1024+AES-256-GCM")
	require.Contains(t, err.Error(), SupportedKEMSuite)
	require.NotContains(t, err.Error(), "decapsulation")
	require.NotContains(t, err.Error(), "wrong private key")
}

// A wrong key must still report as a wrong key -- i.e. adding the format gate did not swallow the
// pre-existing diagnostic for the case it was always meant to describe.
func TestDecryptAndParse_WrongKeyStillReportsKeyError(t *testing.T) {
	_, file := envelopeForTest(t, []byte(ecdsaPayloadJSON), "ECDSA", nil)

	other, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	otherPEM := mlkemPrivateKeyPEM(t, other.Bytes())

	_, err = DecryptAndParse(otherPEM, file)
	require.Error(t, err)
	require.Contains(t, err.Error(), "wrong private key")
}

func TestResolveEnvelopeFormat_Defaults(t *testing.T) {
	tests := []struct {
		name        string
		in          FileEnvelope
		wantVersion int
		wantSuite   string
		wantErr     bool
	}{
		{"both absent", FileEnvelope{}, 1, SupportedKEMSuite, false},
		{"both present", FileEnvelope{FormatVersion: 1, KEMSuite: SupportedKEMSuite}, 1, SupportedKEMSuite, false},
		{"version only", FileEnvelope{FormatVersion: 1}, 1, SupportedKEMSuite, false},
		{"suite only", FileEnvelope{KEMSuite: SupportedKEMSuite}, 1, SupportedKEMSuite, false},
		{"future version", FileEnvelope{FormatVersion: 99}, 0, "", true},
		{"future suite", FileEnvelope{KEMSuite: "X25519+ML-KEM-768+AES-256-GCM"}, 0, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			envelope := tc.in
			err := resolveEnvelopeFormat(&envelope)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantVersion, envelope.FormatVersion)
			require.Equal(t, tc.wantSuite, envelope.KEMSuite)
		})
	}
}
