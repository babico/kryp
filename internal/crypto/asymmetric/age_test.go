package asymmetric

import (
	"testing"

	core "github.com/babico/data-encrypter-decrypter/internal/crypto/core"
)

func TestAgeEncryptorProperties(t *testing.T) {
	e := &AgeEncryptor{}
	if e.ID() != core.AlgoAge {
		t.Errorf("ID = %d, want %d", e.ID(), core.AlgoAge)
	}
	if e.KeySize() != 0 {
		t.Errorf("KeySize = %d, want 0", e.KeySize())
	}
	if e.NonceSize() != 0 {
		t.Errorf("NonceSize = %d, want 0", e.NonceSize())
	}
}

func TestAgeEncryptorEncryptNotSupported(t *testing.T) {
	e := &AgeEncryptor{}
	_, err := e.Encrypt([]byte("test"), []byte("key"))
	if err == nil {
		t.Fatal("expected error: age.Encrypt should not be called directly")
	}
}

func TestAgeEncryptorDecryptNotSupported(t *testing.T) {
	e := &AgeEncryptor{}
	_, err := e.Decrypt([]byte("test"), []byte("key"), []byte("nonce"))
	if err == nil {
		t.Fatal("expected error: age.Decrypt should not be called directly")
	}
}
