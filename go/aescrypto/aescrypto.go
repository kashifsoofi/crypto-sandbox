// Package aescrypto contains utility functions for aes encryption/decryption
package aescrypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    base64 "encoding/base64"
    "io"
)

func Encrypt(plainText string, key []byte) string {
	// create a new aes cipher using key
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err.Error)
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
	copy(data[1:nonceSize], nonce)
	copy(data[1+nonceSize:], cipherText)

	return base64.StdEncoding.EncodeToString(data)
}

func Decrypt(cipherText string, key []byte) string {
	data, _ := base64.StdEncoding.DecodeString(cipherText)

	nonceSize := int(data[0])
	nonce := make([]byte, nonceSize)
	copy(nonce[0:nonceSize], data[1:nonceSize])

	encryptedBytesSize := len(data) - nonceSize - 1
	encryptedBytes := make([]byte, encryptedBytesSize)
	copy(encryptedBytes[0:encryptedBytesSize], data[nonceSize + 1:encryptedBytesSize])

	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err.Error)
	}

	plainText, err := gcm.Open(nil, nonce, encryptedBytes, nil)
	if err != nil {
		panic(err.Error)
	}

	return string(plainText[:len(plainText)])
}