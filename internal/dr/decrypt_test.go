// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package dr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/asn1"
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

// mlkemPrivateKeyPEM wraps a raw ML-KEM-768 seed in the standard PKCS#8
// PrivateKeyInfo DER structure (RFC 9935), matching what OpenSSL 3.5+ and
// current key-generation tooling produce.
func mlkemPrivateKeyPEM(t *testing.T, seed []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(mlkemPKCS8PrivateKeyInfo{
		Algo:       mlkemAlgorithmIdentifier{Algorithm: oidMLKEM768},
		PrivateKey: seed,
	})
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestDecryptFile_RoundTrip(t *testing.T) {
	priv, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	privPEM := mlkemPrivateKeyPEM(t, priv.Bytes())

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
	priv2PEM := mlkemPrivateKeyPEM(t, priv2.Bytes())

	raw := encryptForTest(t, priv1.EncapsulationKey(), []byte("secret"))

	_, err = DecryptFile(priv2PEM, raw)
	require.Error(t, err)
}
