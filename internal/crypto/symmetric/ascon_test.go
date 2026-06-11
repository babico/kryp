package symmetric

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestASCON128EncryptDecrypt(t *testing.T) {
	a := &ASCON128{}
	key := make([]byte, a.KeySize())
	rand.Read(key)
	plaintext := []byte("ASCON-128 test - NIST lightweight cipher")

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

func TestASCON128WrongKey(t *testing.T) {
	a := &ASCON128{}
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

func TestASCON128TamperedCiphertext(t *testing.T) {
	a := &ASCON128{}
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

func TestASCON128EmptyPlaintext(t *testing.T) {
	a := &ASCON128{}
	key := make([]byte, a.KeySize())
	rand.Read(key)

	result, err := a.Encrypt([]byte{}, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := a.Decrypt(result.Ciphertext, key, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatal("expected empty plaintext")
	}
}
