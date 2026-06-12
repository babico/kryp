package symmetric

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestXoodyakEncryptDecrypt(t *testing.T) {
	x := &Xoodyak{}
	key := make([]byte, x.KeySize())
	rand.Read(key)
	plaintext := []byte("Xoodyak test - lightweight AEAD")

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

func TestXoodyakWrongKey(t *testing.T) {
	x := &Xoodyak{}
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

func TestXoodyakTamperedCiphertext(t *testing.T) {
	x := &Xoodyak{}
	key := make([]byte, x.KeySize())
	rand.Read(key)

	result, err := x.Encrypt([]byte("sensitive data"), key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result.Ciphertext[0] ^= 0xFF

	_, err = x.Decrypt(result.Ciphertext, key, result.Nonce)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestXoodyakInvalidKeySize(t *testing.T) {
	x := &Xoodyak{}
	_, err := x.Encrypt([]byte("data"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}

	_, err = x.Decrypt([]byte("data"), []byte("short"), make([]byte, x.NonceSize()))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestXoodyakInvalidNonceSize(t *testing.T) {
	x := &Xoodyak{}
	key := make([]byte, x.KeySize())
	rand.Read(key)

	_, err := x.Decrypt([]byte("data"), key, []byte("short"))
	if err == nil {
		t.Fatal("expected error for invalid nonce size")
	}
}

func TestXoodyakCiphertextTooShort(t *testing.T) {
	x := &Xoodyak{}
	key := make([]byte, x.KeySize())
	rand.Read(key)
	nonce := make([]byte, x.NonceSize())
	rand.Read(nonce)

	_, err := x.Decrypt([]byte("short"), key, nonce)
	if err == nil {
		t.Fatal("expected error for too short ciphertext")
	}
}

func TestXoodyakEmptyPlaintext(t *testing.T) {
	x := &Xoodyak{}
	key := make([]byte, x.KeySize())
	rand.Read(key)

	result, err := x.Encrypt([]byte{}, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := x.Decrypt(result.Ciphertext, key, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatal("expected empty plaintext")
	}
}
