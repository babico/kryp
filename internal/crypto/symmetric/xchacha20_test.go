package symmetric

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestXChaCha20EncryptDecrypt(t *testing.T) {
	x := &XChaCha20{}
	key := make([]byte, x.KeySize())
	rand.Read(key)
	plaintext := []byte("Hello, World! This is a test message for XChaCha20-Poly1305.")

	result, err := x.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := x.Decrypt(result.Ciphertext, key, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted text does not match original")
	}
}

func TestXChaCha20WrongKey(t *testing.T) {
	x := &XChaCha20{}
	key := make([]byte, x.KeySize())
	rand.Read(key)
	wrongKey := make([]byte, x.KeySize())
	rand.Read(wrongKey)

	result, err := x.Encrypt([]byte("test data"), key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = x.Decrypt(result.Ciphertext, wrongKey, result.Nonce)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestXChaCha20TamperedCiphertext(t *testing.T) {
	x := &XChaCha20{}
	key := make([]byte, x.KeySize())
	rand.Read(key)

	result, err := x.Encrypt([]byte("test data"), key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result.Ciphertext[0] ^= 0xFF

	_, err = x.Decrypt(result.Ciphertext, key, result.Nonce)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}
