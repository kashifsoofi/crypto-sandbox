// Package aescrypto contains utility functions for aes encryption/decryption
package aescrypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    base64 "encoding/base64"
	"io"
)

type CipherMode int

const (
	CBC CipherMode = iota
	GCM
)

type Padding int

const (
	NoPadding Padding = iota
	PKCS7
)

type AesCrypto struct {
	CipherMode CipherMode
	Padding Padding
}

func (aesCrypto AesCrypto) Encrypt(plainText string, key []byte) (string, error) {
	// create a new aes cipher using key
	aes, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error)
	}

	plainTextBytes := []byte(plainText)
	cipherText := gcm.Seal(nil, nonce, plainTextBytes, nil)

	nonceSize := gcm.NonceSize()
	dataLength := 1 + nonceSize + len(cipherText)
	data := make([]byte, dataLength)
	data[0] = byte(nonceSize)
	copy(data[1:], nonce[0:nonceSize])
	copy(data[1+nonceSize:], cipherText)

	return base64.StdEncoding.EncodeToString(data), nil
}

func (crypto AesCrypto) Decrypt(cipherText string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	// unpack data
	ivSize := int(data[0])
	index := 1
	tagSize := 0
	if crypto.CipherMode == GCM {
		tagSize = int(data[index])
		index += 1
	}
	iv, encryptedBytes := data[index:index+ivSize], data[index+ivSize:]

	aes, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(aes, tagSize) // only used for compatibility, NewGCM recomended
	if err != nil {
		return "", err
	}

	decryptedBytes, err := aesgcm.Open(nil, iv, encryptedBytes, nil)
	if err != nil {
		return "", err
	}

	return string(decryptedBytes[:len(decryptedBytes)]), nil
}