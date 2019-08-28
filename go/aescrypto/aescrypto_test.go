package aescrypto

import "testing"

func TestEncrypt(t *testing.T) {
	plainText := "Here is some data to encrypt!"
	key := []byte("2E77A9E4120E486097E1200E2C73879A")

	encrypted := Encrypt(plainText, key)
	t.Logf("Encrypted: %s\n", encrypted)

	decrypted := Decrypt(encrypted, key)
	t.Logf("Decrypted: %s\n", decrypted)

	if (decrypted != plainText) {
		t.Errorf("Decrypt error, got: %s, want: %s", decrypted, plainText)
	}
}

func TestDecrypt(t *testing.T) {
	plainText := "Here is some data to encrypt!"
	cipherText := "DFpDJASoINV+fEdymPvnzJBwedDuLCtv6ElcM2N7ba+Nalq6V+RVqe0CzBSpCGqruCO4Fd/DBFGBxw=="
	key := []byte("1015DDA61AD6497BAD00582CDC10B537")

	decrypted := Decrypt(cipherText, key)

	if (decrypted != plainText) {
		t.Errorf("Decrypt error, got: %s, want: %s", decrypted, plainText)
	}
}