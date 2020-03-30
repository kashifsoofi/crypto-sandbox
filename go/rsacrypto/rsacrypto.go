// Package rsacrypto contains utility functions for rsa encryption/decryption
package rsacrypto

import (
	"bytes"
	"crypto/rand"
    "crypto/rsa"
	"crypto/sha512"
    base64 "encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
)

type CipherMode int

const (
	ECB CipherMode = iota
)

type Padding int

const (
	SHA512WITHRSA Padding = iota
)

type RsaCrypto struct {
	CipherMode CipherMode
	Padding Padding
}

type RsaPrivateKey rsa.PrivateKey
type RsaPublicKey rsa.PublicKey

type RsaPrivateKeyParameters struct {
	D []byte
	P []byte
	Q []byte
	DP []byte
	DQ []byte
	InverseQ []byte
	Modulus []byte
	Exponent []byte
}

func (privateKey *RsaPrivateKey) toRsaPrivateKeyParameters() (*RsaPrivateKeyParameters) {
	return &RsaPrivateKeyParameters {
		D: privateKey.D.Bytes(),
		// TODO: P: privateKey.P,
		// TODO: DP: privateKey.DP,
	}
}

func (keyParameters RsaPrivateKeyParameters) toRsaPrivateKey() *rsa.PrivateKey {
	modulus := new(big.Int)
	modulus.SetBytes(keyParameters.Modulus)
	var exponent int
	buf := bytes.NewReader(keyParameters.Exponent)
	_ = binary.Read(buf, binary.LittleEndian, &exponent)

	return &rsa.PrivateKey {
		// TODO: set values
	}
}

func (keyParameters RsaPrivateKeyParameters) toJson() string {
	jsonBytes, _ := json.Marshal(keyParameters)
	return string(jsonBytes)
}

type RsaPublicKeyParameters struct {
	Modulus []byte
	Exponent []byte
}

func (publicKey *RsaPublicKey) toRsaPublicKeyParameters() (*RsaPublicKeyParameters, error) {
	exponent := new(bytes.Buffer)
	err := binary.Write(exponent, binary.LittleEndian, publicKey.E)
	if err != nil {
    	return nil, err
	}

	return &RsaPublicKeyParameters {
		Modulus: publicKey.N.Bytes(),
		Exponent: exponent.Bytes(),
	}, nil
}

func (keyParameters RsaPublicKeyParameters) toRsaPublicKey() *rsa.PublicKey {
	modulus := new(big.Int)
	modulus.SetBytes(keyParameters.Modulus)
	var exponent int
	buf := bytes.NewReader(keyParameters.Exponent)
	_ = binary.Read(buf, binary.LittleEndian, &exponent)

	return &rsa.PublicKey {
		N: modulus,
		E: exponent,
	}
}

func (keyParameters RsaPublicKeyParameters) toJson() string {
	jsonBytes, _ := json.Marshal(keyParameters)
	return string(jsonBytes)
}

func (crypto RsaCrypto) GenerateKeyPair(keySize int) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return "", "", err
	}
		
	var rsaPrivateKey RsaPrivateKey = RsaPrivateKey(*privateKey)
	rsaPrivateKeyParameters := rsaPrivateKey.toRsaPrivateKeyParameters()
	if err != nil {
		return "", "", err
	}

	var rsaPublicKey RsaPublicKey = RsaPublicKey(privateKey.PublicKey)
	rsaPublicKeyParameters, err := rsaPublicKey.toRsaPublicKeyParameters()
	if err != nil {
		return "", "", err
	}

	return rsaPrivateKeyParameters.toJson(), rsaPublicKeyParameters.toJson(), nil
}

func (crypto RsaCrypto) Encrypt(plainText string, publicKeyJson string) (string, error) {
	// create a new aes cipher using key
	var rsaPublicKeyParameters RsaPublicKeyParameters
	jsonBytes := []byte(publicKeyJson)
	err := json.Unmarshal(jsonBytes, &rsaPublicKeyParameters)
	publicKey := rsaPublicKeyParameters.toRsaPublicKey()

	hash := sha512.New()
	plainTextBytes := []byte(plainText)
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, plainTextBytes, nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (crypto RsaCrypto) Decrypt(cipherText string, privateKeyJson string, provider string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	var rsaPrivateKeyParameters RsaPrivateKeyParameters
	jsonBytes := []byte(privateKeyJson)
	err = json.Unmarshal(jsonBytes, &rsaPrivateKeyParameters)
	privateKey := rsaPrivateKeyParameters.toRsaPrivateKey()
	
	hash := sha512.New()
	plainText, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, data, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
