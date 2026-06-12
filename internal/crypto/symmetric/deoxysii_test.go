package symmetric

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDeoxysIIEncryptDecrypt(t *testing.T) {
	d := &DeoxysII{}
	key := make([]byte, d.KeySize())
	rand.Read(key)
	plaintext := []byte("Deoxys-II test - authenticated encryption")

	result, err := d.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := d.Decrypt(result.Ciphertext, key, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted text does not match original")
	}
}

func TestDeoxysIIWrongKey(t *testing.T) {
	d := &DeoxysII{}
	key := make([]byte, d.KeySize())
	rand.Read(key)
	wrongKey := make([]byte, d.KeySize())
	rand.Read(wrongKey)

	result, err := d.Encrypt([]byte("test data"), key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = d.Decrypt(result.Ciphertext, wrongKey, result.Nonce)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestDeoxysIITamperedCiphertext(t *testing.T) {
	d := &DeoxysII{}
	key := make([]byte, d.KeySize())
	rand.Read(key)

	result, err := d.Encrypt([]byte("sensitive data"), key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result.Ciphertext[0] ^= 0xFF

	_, err = d.Decrypt(result.Ciphertext, key, result.Nonce)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestDeoxysIIInvalidKeySize(t *testing.T) {
	d := &DeoxysII{}
	_, err := d.Encrypt([]byte("data"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestDeoxysIIEmptyPlaintext(t *testing.T) {
	d := &DeoxysII{}
	key := make([]byte, d.KeySize())
	rand.Read(key)

	result, err := d.Encrypt([]byte{}, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := d.Decrypt(result.Ciphertext, key, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatal("expected empty plaintext")
	}
}
