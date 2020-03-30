package rsacrypto

import (
	"testing"
	"fmt"
	// "strings"
	// "github.com/google/uuid"
)

const plainText = "Here is some data to encrypt!"

func TestGenerateKeyPair(t *testing.T) {
	rsaCrypto := RsaCrypto { }
	privateKeyJson, publicKeyJson, err := rsaCrypto.GenerateKeyPair(2048)
	if err != nil {
		t.Errorf("%s", err);
	}
	
	fmt.Printf("PrivateKeyJson: %s", privateKeyJson)
	fmt.Println()
	fmt.Printf("PublicKeyJson: %s", publicKeyJson)
	if "" == privateKeyJson || "" == publicKeyJson {
		t.Errorf("Error generating key pair")
	}
}

func TestEncryptAndDecryptWithGeneratedKey(t *testing.T) {
	rsaCrypto := RsaCrypto { }
	privateKeyJson, publicKeyJson, err := rsaCrypto.GenerateKeyPair(2048)
	if err != nil {
		t.Errorf("%s", err);
	}

	encrypted, err := rsaCrypto.Encrypt(plainText, publicKeyJson)
	if err != nil {
		t.Errorf("%s", err);
	}

	decrypted, err := rsaCrypto.Decrypt(encrypted, privateKeyJson, "go")
	if err != nil {
		t.Errorf("%s", err);
	}

	if decrypted != plainText {
		t.Errorf("Decrypt error, got: %s, want: %s", decrypted, plainText)
	}
}
