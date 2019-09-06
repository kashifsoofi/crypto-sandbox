package aescrypto

import (
	"testing"
	"strings"
	"github.com/google/uuid"
)

const plainText = "Here is some data to encrypt!"

func TestEncryptAndDecryptWithGcmNoPadding(t *testing.T) {
	keyUuid := uuid.New().String()
	key := []byte(strings.Replace(keyUuid, "-", "", -1))

	aesCrypto := AesCrypto {
		CipherMode: GCM,
		Padding: NoPadding,
	}
	encrypted, err := aesCrypto.Encrypt(plainText, key)
	if err != nil {
		t.Errorf("%s", err);
	}

	decrypted, err := aesCrypto.Decrypt(encrypted, key, "go")
	if err != nil {
		t.Errorf("%s", err);
	}

	if decrypted != plainText {
		t.Errorf("Decrypt error, got: %s, want: %s", decrypted, plainText)
	}
}

func TestDecryptWithGcmNoPadding(t *testing.T) {
	var testData = []struct {
		CipherText string
		KeyUuid string
		Provider string
	} {
		// Encrypted with BC AES/GCM/NoPadding
		{ "EBA6cMY4KY9Ry9xR6U5TZlCGqHpFSIEOqvxIkFX4QvSotaWj6XztRRTsUa+FQTKICat7RU+CIGR5VS+J9uvh", "40f5dca1-81a8-44a0-8667-dbe2d5393a65", "BouncyCastle.Net" },
		// Encrypted with Java AES/GCM/NoPadding
		{ "EBBnZdJcwfZxC9kdwRMt8YVADEXHa0VOpb3HkImm7nytjHsFiQs09Cfv48vZ9fJTX/oot6saYFPkoMDSScM7", "9b71be77-c730-47c6-841c-d597282792ef", "Java" },
		// Encrypted with Go NewGCM
		{ "DBBJlLBym6tNgE5vMT2Vz45ChQLqsYFwXM4jKXVtRsLKbySgM5bkdxUjhwEjEVgzAALmthebr3bZWs8=", "c1b7232d-cd93-4baa-b6a0-64dccb3f1583", "go" },
	}

	aesCrypto := AesCrypto {
		CipherMode: GCM,
		Padding: NoPadding,
	}

	for _, testData := range testData {
		key := []byte(strings.Replace(testData.KeyUuid, "-", "", -1))

		decrypted, err := aesCrypto.Decrypt(testData.CipherText, key, testData.Provider)
		if err != nil {
			t.Errorf("%s", err);
		}
	
		if decrypted != plainText {
			t.Errorf("Decrypt error for provider: %s, got: %s, want: %s", testData.Provider, decrypted, plainText)
		}
	}
}