package symmetric

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestChaCha20EncryptDecrypt(t *testing.T) {
	c := &ChaCha20Poly1305{}
	key := make([]byte, c.KeySize())
	rand.Read(key)
	plaintext := []byte("ChaCha20-Poly1305 test message")

	result, err := c.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := c.Decrypt(result.Ciphertext, key, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted text does not match original")
	}
}

func TestChaCha20WrongKey(t *testing.T) {
	c := &ChaCha20Poly1305{}
	key := make([]byte, c.KeySize())
	rand.Read(key)
	wrongKey := make([]byte, c.KeySize())
	rand.Read(wrongKey)

	result, err := c.Encrypt([]byte("test"), key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = c.Decrypt(result.Ciphertext, wrongKey, result.Nonce)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}
