package symmetric

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSecretBoxEncryptDecrypt(t *testing.T) {
	s := &SecretBox{}
	key := make([]byte, s.KeySize())
	rand.Read(key)
	plaintext := []byte("NaCl SecretBox test - XSalsa20-Poly1305")

	result, err := s.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := s.Decrypt(result.Ciphertext, key, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted text does not match original")
	}
}

func TestSecretBoxWrongKey(t *testing.T) {
	s := &SecretBox{}
	key := make([]byte, s.KeySize())
	rand.Read(key)
	wrongKey := make([]byte, s.KeySize())
	rand.Read(wrongKey)

	result, err := s.Encrypt([]byte("test"), key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = s.Decrypt(result.Ciphertext, wrongKey, result.Nonce)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}
