package symmetric

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestAES256CTRHMACEncryptDecrypt(t *testing.T) {
	a := &AES256CTRHMAC{}
	key := make([]byte, a.KeySize())
	rand.Read(key)
	plaintext := []byte("AES-256-CTR+HMAC test - encrypt-then-mac")

	result, err := a.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := a.Decrypt(result.Ciphertext, key, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted text does not match original")
	}
}

func TestAES256CTRHMACWrongKey(t *testing.T) {
	a := &AES256CTRHMAC{}
	key := make([]byte, a.KeySize())
	rand.Read(key)
	wrongKey := make([]byte, a.KeySize())
	rand.Read(wrongKey)

	result, err := a.Encrypt([]byte("test data"), key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = a.Decrypt(result.Ciphertext, wrongKey, result.Nonce)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestAES256CTRHMACTamperedCiphertext(t *testing.T) {
	a := &AES256CTRHMAC{}
	key := make([]byte, a.KeySize())
	rand.Read(key)

	result, err := a.Encrypt([]byte("test data"), key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result.Ciphertext[0] ^= 0xFF

	_, err = a.Decrypt(result.Ciphertext, key, result.Nonce)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestAES256CTRHMACWrongKeySize(t *testing.T) {
	a := &AES256CTRHMAC{}
	_, err := a.Encrypt([]byte("test"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}
