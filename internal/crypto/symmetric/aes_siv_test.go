package symmetric

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestAES256SIVEncryptDecrypt(t *testing.T) {
	a := &AES256SIV{}
	key := make([]byte, a.KeySize())
	rand.Read(key)
	plaintext := []byte("AES-256-SIV test - nonce-misuse resistant")

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

func TestAES256SIVWrongKey(t *testing.T) {
	a := &AES256SIV{}
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

func TestAES256SIVTamperedCiphertext(t *testing.T) {
	a := &AES256SIV{}
	key := make([]byte, a.KeySize())
	rand.Read(key)

	result, err := a.Encrypt([]byte("sensitive data"), key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result.Ciphertext[0] ^= 0xFF

	_, err = a.Decrypt(result.Ciphertext, key, result.Nonce)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestAES256SIVInvalidKeySize(t *testing.T) {
	a := &AES256SIV{}
	_, err := a.Encrypt([]byte("data"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestAES256SIVEmptyPlaintext(t *testing.T) {
	a := &AES256SIV{}
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
