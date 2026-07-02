// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package dr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/pem"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func encryptForTest(t *testing.T, pub *mlkem.EncapsulationKey768, plaintext []byte) []byte {
	t.Helper()
	sharedSecret, cipherTextKEM := pub.Encapsulate()

	blk, err := aes.NewCipher(sharedSecret)
	require.NoError(t, err)
	aesGCM, err := cipher.NewGCM(blk)
	require.NoError(t, err)
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	require.NoError(t, err)
	sealed := aesGCM.Seal(nonce, nonce, plaintext, nil)

	return append(cipherTextKEM, sealed...)
}

func TestDecryptFile_RoundTrip(t *testing.T) {
	priv, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv.Bytes()})

	want := []byte(`{"Data":[{"Xi":1,"ShareID":2}],"VaultId":"vault-1","Threshold":2}`)
	raw := encryptForTest(t, priv.EncapsulationKey(), want)

	got, err := DecryptFile(privPEM, raw)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestDecryptFile_WrongKey(t *testing.T) {
	priv1, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	priv2, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	priv2PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv2.Bytes()})

	raw := encryptForTest(t, priv1.EncapsulationKey(), []byte("secret"))

	_, err = DecryptFile(priv2PEM, raw)
	require.Error(t, err)
}
