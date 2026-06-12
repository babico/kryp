package symmetric

import (
	"bytes"
	"crypto/rand"
	"testing"

	core "github.com/babico/kryp/internal/crypto/core"
)

func TestAEGIS128LEncryptDecrypt(t *testing.T) {
	a := &AEGIS128L{}
	key := make([]byte, a.KeySize())
	rand.Read(key)
	plaintext := []byte("AEGIS-128L test - fast authenticated encryption")

	result, err := a.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if result.Algorithm != core.AlgoAEGIS128L {
		t.Errorf("Algorithm = %d, want %d", result.Algorithm, core.AlgoAEGIS128L)
	}

	decrypted, err := a.Decrypt(result.Ciphertext, key, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted text does not match original")
	}
}

func TestAEGIS128LWrongKey(t *testing.T) {
	a := &AEGIS128L{}
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

func TestAEGIS128LTamperedCiphertext(t *testing.T) {
	a := &AEGIS128L{}
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

func TestAEGIS128LInvalidKeySize(t *testing.T) {
	a := &AEGIS128L{}
	_, err := a.Encrypt([]byte("data"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestAEGIS128LEmptyPlaintext(t *testing.T) {
	a := &AEGIS128L{}
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

func TestAEGIS256EncryptDecrypt(t *testing.T) {
	a := &AEGIS256{}
	key := make([]byte, a.KeySize())
	rand.Read(key)
	plaintext := []byte("AEGIS-256 test - 256-bit key variant")

	result, err := a.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if result.Algorithm != core.AlgoAEGIS256 {
		t.Errorf("Algorithm = %d, want %d", result.Algorithm, core.AlgoAEGIS256)
	}

	decrypted, err := a.Decrypt(result.Ciphertext, key, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted text does not match original")
	}
}

func TestAEGIS256WrongKey(t *testing.T) {
	a := &AEGIS256{}
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

func TestAEGIS256TamperedCiphertext(t *testing.T) {
	a := &AEGIS256{}
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

func TestAEGIS256InvalidKeySize(t *testing.T) {
	a := &AEGIS256{}
	_, err := a.Encrypt([]byte("data"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestAEGIS256EmptyPlaintext(t *testing.T) {
	a := &AEGIS256{}
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
