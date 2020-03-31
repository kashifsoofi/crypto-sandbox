// Package rsacrypto contains utility functions for rsa encryption/decryption
package rsacrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	base64 "encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
)

type RsaCrypto struct {
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

func (privateKey *RsaPrivateKey) toRsaPrivateKeyParameters() *RsaPrivateKeyParameters {
	exponent := make([]byte, 4)
	binary.BigEndian.PutUint32(exponent, uint32(privateKey.PublicKey.E))
	for i := range exponent {
	  if exponent[i] != 0 {
		  exponent = exponent[i:]
		  break
	   }
	}

	return &RsaPrivateKeyParameters {
		D: privateKey.D.Bytes(),		
		P: privateKey.Primes[0].Bytes(),
		Q: privateKey.Primes[1].Bytes(),
		DP: privateKey.Precomputed.Dp.Bytes(),
		DQ: privateKey.Precomputed.Dq.Bytes(),
		InverseQ: privateKey.Precomputed.Qinv.Bytes(),
		Modulus: privateKey.PublicKey.N.Bytes(),
		Exponent: exponent,
	}
}

func (keyParameters RsaPrivateKeyParameters) toRsaPrivateKey() (*rsa.PrivateKey, error) {
	d, p, q := new(big.Int), new(big.Int), new(big.Int)
	d.SetBytes(keyParameters.D)
	p.SetBytes(keyParameters.P)
	q.SetBytes(keyParameters.Q)
	dp, dq, inverseQ, modulus := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	dp.SetBytes(keyParameters.DP)
	dq.SetBytes(keyParameters.DQ)
	inverseQ.SetBytes(keyParameters.InverseQ)
	modulus.SetBytes(keyParameters.Modulus)

	buffer := make([]byte, 4)
	copy(buffer[4 - len(keyParameters.Exponent):], keyParameters.Exponent)
	e := binary.BigEndian.Uint32(buffer)

	return &rsa.PrivateKey {
		PublicKey: rsa.PublicKey {
			N: modulus,
			E: int(e),
		},
		D: d,
		Primes: []*big.Int { p, q },
		Precomputed: rsa.PrecomputedValues {
			Dp: dp,
			Dq: dq,
			Qinv: inverseQ,
		},
	}, nil
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
	exponent := make([]byte, 4)
	binary.BigEndian.PutUint32(exponent, uint32(publicKey.E))
	for i := range exponent {
	  if exponent[i] != 0 {
		  exponent = exponent[i:]
		  break
	   }
	}

	return &RsaPublicKeyParameters {
		Modulus: publicKey.N.Bytes(),
		Exponent: exponent,
	}, nil
}

func (keyParameters RsaPublicKeyParameters) toRsaPublicKey() (*rsa.PublicKey, error) {
	modulus := new(big.Int)
	modulus.SetBytes(keyParameters.Modulus)

	buffer := make([]byte, 4)
	copy(buffer[4 - len(keyParameters.Exponent):], keyParameters.Exponent)
	e := binary.BigEndian.Uint32(buffer)

	return &rsa.PublicKey {
		N: modulus,
		E: int(e),
	}, nil
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

	var rsaPublicKey RsaPublicKey = RsaPublicKey(privateKey.PublicKey)
	rsaPublicKeyParameters, err := rsaPublicKey.toRsaPublicKeyParameters()
	if err != nil {
		return "", "", err
	}

	return rsaPrivateKeyParameters.toJson(), rsaPublicKeyParameters.toJson(), nil
}

func (crypto RsaCrypto) Encrypt(plainText string, publicKeyJson string) (string, error) {
	var rsaPublicKeyParameters RsaPublicKeyParameters
	jsonBytes := []byte(publicKeyJson)
	err := json.Unmarshal(jsonBytes, &rsaPublicKeyParameters)
	publicKey, err := rsaPublicKeyParameters.toRsaPublicKey()
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	plainTextBytes := []byte(plainText)
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, plainTextBytes, nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (crypto RsaCrypto) Decrypt(cipherText string, privateKeyJson string, provider string) (string, error) {
	var rsaPrivateKeyParameters RsaPrivateKeyParameters
	jsonBytes := []byte(privateKeyJson)
	err := json.Unmarshal(jsonBytes, &rsaPrivateKeyParameters)
	privateKey, err := rsaPrivateKeyParameters.toRsaPrivateKey()
	if err != nil {
		return "", err
	}
	
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	plainText, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, data, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func (rsaCrypto RsaCrypto) SignData(data string, privateKeyJson string) (string, error) {
	var rsaPrivateKeyParameters RsaPrivateKeyParameters
	jsonBytes := []byte(privateKeyJson)
	err := json.Unmarshal(jsonBytes, &rsaPrivateKeyParameters)
	signatureKey, err := rsaPrivateKeyParameters.toRsaPrivateKey()
	if err != nil {
		return "", err
	}

	dataToSign := []byte(data)
	hashed := sha512.Sum512(dataToSign)
	signature, err := rsa.SignPKCS1v15(rand.Reader, signatureKey, crypto.SHA512, hashed[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func (rsaCrypto RsaCrypto) VerifySignature(data string, signature string, publicKeyJson string) (bool, error) {
	var rsaPublicKeyParameters RsaPublicKeyParameters
	jsonBytes := []byte(publicKeyJson)
	err := json.Unmarshal(jsonBytes, &rsaPublicKeyParameters)
	signatureKey, err := rsaPublicKeyParameters.toRsaPublicKey()
	if err != nil {
		return false, err
	}

	dataToVerify := []byte(data)
	hashed := sha256.Sum256(dataToVerify)
	binarySignature, _ := base64.StdEncoding.DecodeString(signature)

	verifyErr := rsa.VerifyPKCS1v15(signatureKey, crypto.SHA512, hashed[:], binarySignature)
	if verifyErr != nil {
		return false, err
	}

	return true, nil
}
