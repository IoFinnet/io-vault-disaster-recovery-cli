// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package data

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecodeGcmField covers both encoding eras of the mobile app's GCM iv/tag fields:
// legacy (react-native-aes-gcm-crypto) hex and current (expo-crypto) base64.
func TestDecodeGcmField(t *testing.T) {
	iv := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c} // 12 bytes
	tag := []byte{
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	} // 16 bytes

	t.Run("legacy hex iv", func(t *testing.T) {
		got, err := DecodeGcmField(hex.EncodeToString(iv), GcmIVBytes)
		require.NoError(t, err)
		assert.Equal(t, iv, got)
	})

	t.Run("current base64 iv", func(t *testing.T) {
		got, err := DecodeGcmField(base64.StdEncoding.EncodeToString(iv), GcmIVBytes)
		require.NoError(t, err)
		assert.Equal(t, iv, got)
	})

	t.Run("legacy hex tag", func(t *testing.T) {
		got, err := DecodeGcmField(hex.EncodeToString(tag), GcmTagBytes)
		require.NoError(t, err)
		assert.Equal(t, tag, got)
	})

	t.Run("current base64 tag", func(t *testing.T) {
		got, err := DecodeGcmField(base64.StdEncoding.EncodeToString(tag), GcmTagBytes)
		require.NoError(t, err)
		assert.Equal(t, tag, got)
	})

	// The regression that motivated the length-based decode: this 16-char value is BOTH
	// valid base64 (of 12 bytes) and valid hex (of 8 bytes). A "looks like hex" heuristic
	// would wrongly decode it to 8 bytes; disambiguating by length (iv hex would be 24
	// chars, not 16) correctly decodes it as the 12-byte base64 nonce.
	t.Run("all-hex base64 iv is not misread as hex", func(t *testing.T) {
		const ambiguous = "abcdef0123456789"
		wantBase64, err := base64.StdEncoding.DecodeString(ambiguous)
		require.NoError(t, err)
		require.Len(t, wantBase64, GcmIVBytes)

		got, err := DecodeGcmField(ambiguous, GcmIVBytes)
		require.NoError(t, err)
		assert.Equal(t, wantBase64, got, "must decode as base64, not hex")
		assert.Len(t, got, GcmIVBytes)
	})

	t.Run("surrounding whitespace is trimmed", func(t *testing.T) {
		got, err := DecodeGcmField("  "+base64.StdEncoding.EncodeToString(iv)+"\n", GcmIVBytes)
		require.NoError(t, err)
		assert.Equal(t, iv, got)
	})

	t.Run("malformed value errors rather than corrupting", func(t *testing.T) {
		_, err := DecodeGcmField("not*valid*base64!", GcmIVBytes)
		assert.Error(t, err)
	})

	// A well-formed but short base64 value (e.g. "AA==" decodes to a single zero byte) must
	// not silently return a wrong-length slice: that would later reach aesGCM.Open, which
	// panics rather than erroring on an incorrect nonce/tag length.
	t.Run("valid base64 decoding to the wrong length errors", func(t *testing.T) {
		_, err := DecodeGcmField("AA==", GcmIVBytes)
		assert.Error(t, err)
	})
}
