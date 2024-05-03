package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"github.com/binance-chain/go-sdk/common/uuid"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

type cipherParams struct {
	IV string `json:"iv"`
}

type CryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherParams           `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type EncryptedKey struct {
	Crypto  CryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version int        `json:"version"`
}

func exportKeyStore(privKey []byte, password string) (*EncryptedKey, error) {
	salt, err := generateRandomBytes(32)
	if err != nil {
		return nil, err
	}
	iv, err := generateRandomBytes(16)
	if err != nil {
		return nil, err
	}
	scryptParamsJSON := make(map[string]interface{}, 4)
	scryptParamsJSON["prf"] = "hmac-sha256"
	scryptParamsJSON["dklen"] = 32
	scryptParamsJSON["salt"] = hex.EncodeToString(salt)
	scryptParamsJSON["c"] = 662144

	cipherParamsJSON := cipherParams{IV: hex.EncodeToString(iv)}
	derivedKey := pbkdf2.Key([]byte(password), salt, 662144, 32, sha256.New)
	encryptKey := derivedKey[:32]
	cipherText, err := aesCTRXOR(encryptKey, privKey, iv)
	if err != nil {
		return nil, err
	}

	hasher := sha3.NewLegacyKeccak512()
	_, err = hasher.Write(derivedKey[16:32])
	if err != nil {
		return nil, err
	}
	_, err = hasher.Write(cipherText)
	if err != nil {
		return nil, err
	}
	mac := hasher.Sum(nil)

	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	cryptoStruct := CryptoJSON{
		Cipher:       "aes-256-ctr",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          "pbkdf2",
		KDFParams:    scryptParamsJSON,
		MAC:          hex.EncodeToString(mac),
	}
	return &EncryptedKey{
		Crypto:  cryptoStruct,
		Id:      id.String(),
		Version: 1,
	}, nil
}

func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	// AES-128 is selected due to size of encryptKey.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}
	return b, nil
}
