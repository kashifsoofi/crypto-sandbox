// Package aescrypto contains utility functions for aes encryption/decryption
package aescrypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    base64 "encoding/base64"
	"io"
	"strings"
	"bytes"
	"fmt"
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
	tagSize := gcm.Overhead()
	dataLength := 2 + nonceSize + len(cipherText)	
	data := make([]byte, dataLength)
	// set first 2 bytes as nonceSize, to make cipher data compatible with crypto methods in other languages in this repo
	data[0] = byte(nonceSize)
	data[1] = byte(tagSize)
	copy(data[2:], nonce[0:nonceSize])
	copy(data[2+nonceSize:], cipherText)

	return base64.StdEncoding.EncodeToString(data), nil
}

func (crypto AesCrypto) Decrypt(cipherText string, key []byte, provider string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	
	iv, encryptedBytes, tagSize := crypto.UnpackCipherData(data)

	aes, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if crypto.CipherMode == GCM {
		return DecryptGcm(aes, iv, tagSize, encryptedBytes, provider)
	} else {
		return DecryptCbc(aes, iv, encryptedBytes)
	}
}

func DecryptGcm(aes cipher.Block, iv []byte, tagSize int, encrypted []byte, provider string) (string, error) {
	var aesgcm cipher.AEAD
	var err error
	if strings.EqualFold("go", provider) {
		aesgcm, err = cipher.NewGCM(aes)
	} else {
		aesgcm, err = cipher.NewGCMWithNonceSize(aes, tagSize) // only used for compatibility, NewGCM recomended
	}
	
	if err != nil {
		return "", err
	}

	decryptedBytes, err := aesgcm.Open(nil, iv, encrypted, nil)
	if err != nil {
		return "", err
	}

	return string(decryptedBytes[:len(decryptedBytes)]), nil
}

func DecryptCbc(aes cipher.Block, iv []byte, encrypted []byte) (string, error) {
	decryptor := cipher.NewCBCDecrypter(aes, iv)

	decryptedBytes := make([]byte, len(encrypted))
	decryptor.CryptBlocks(decryptedBytes, encrypted)

	decryptedBytes, err := pkcs7Unpad(decryptedBytes, 8)
	if err != nil {
		return "", err
	}

	return string(decryptedBytes[:len(decryptedBytes)]), nil
}

func (crypto AesCrypto) UnpackCipherData(data []byte) ([]byte, []byte, int) {
	ivSize := int(data[0])
	index := 1
	tagSize := 0
	if crypto.CipherMode == GCM {
		tagSize = int(data[index])
		index += 1
	}
	iv, encryptedBytes := data[index:index+ivSize], data[index+ivSize:]

	return iv, encryptedBytes, tagSize
}

// ref: https://golang-examples.tumblr.com/post/98350728789/pkcs7-padding
// Appends padding.
func pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
    if blocklen <= 0 {
        return nil, fmt.Errorf("Invalid block length %d", blocklen)
    }
    padlen := 1
    for ((len(data) + padlen) % blocklen) != 0 {
        padlen = padlen + 1
    }

    pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
    return append(data, pad...), nil
}

// Returns slice of the original data without padding.
func pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
    if blocklen <= 0 {
        return nil, fmt.Errorf("Invalid block length %d", blocklen)
    }
    if len(data)%blocklen != 0 || len(data) == 0 {
        return nil, fmt.Errorf("Invalid data length %d", len(data))
    }
    padlen := int(data[len(data)-1])
    if padlen > blocklen || padlen == 0 {
        return nil, fmt.Errorf("Invalid padding")
    }
    // check padding
    pad := data[len(data)-padlen:]
    for i := 0; i < padlen; i++ {
        if pad[i] != byte(padlen) {
            return nil, fmt.Errorf("Invalid padding")
        }
    }

    return data[:len(data)-padlen], nil
}