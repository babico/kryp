package crypto

import (
	"bytes"
	"testing"
)

func TestKeyDerivationArgon2id(t *testing.T) {
	salt := []byte("0123456789abcdef")
	params := EncodeArgon2Params(2, 65536, 4)

	key1, err := DeriveKey([]byte("password"), KDFArgon2id, salt, params, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	key2, err := DeriveKey([]byte("password"), KDFArgon2id, salt, params, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("same inputs should produce same key")
	}

	key3, err := DeriveKey([]byte("different"), KDFArgon2id, salt, params, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if bytes.Equal(key1, key3) {
		t.Fatal("different passwords should produce different keys")
	}
}

func TestKeyDerivationScrypt(t *testing.T) {
	salt := []byte("0123456789abcdef")
	params := EncodeScryptParams(16384, 8, 1)

	key, err := DeriveKey([]byte("password"), KDFScrypt, salt, params, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}

func TestKeyDerivationPBKDF2(t *testing.T) {
	salt := []byte("0123456789abcdef")
	params := EncodePBKDF2Params(100000)

	key, err := DeriveKey([]byte("password"), KDFPBKDF2, salt, params, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}

func TestDeriveKeyInvalidKDF(t *testing.T) {
	_, err := DeriveKey([]byte("pass"), KDFNone, []byte("salt1234567890"), nil, 32)
	if err == nil {
		t.Fatal("expected error for KDFNone")
	}
}

func TestDeriveKeyUnknownKDF(t *testing.T) {
	_, err := DeriveKey([]byte("pass"), 99, []byte("salt1234567890"), nil, 32)
	if err == nil {
		t.Fatal("expected error for unknown KDF")
	}
}

func TestDeriveKeyArgon2idInvalidParams(t *testing.T) {
	_, err := DeriveKey([]byte("pass"), KDFArgon2id, []byte("salt1234567890"), []byte{1, 2}, 32)
	if err == nil {
		t.Fatal("expected error for invalid params")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt(16)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}
	if len(salt) != 16 {
		t.Errorf("salt length = %d, want 16", len(salt))
	}

	salt2, err := GenerateSalt(32)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}
	if len(salt2) != 32 {
		t.Errorf("salt length = %d, want 32", len(salt2))
	}

	if bytes.Equal(salt, salt2) {
		t.Fatal("consecutive salts should differ")
	}
}

func TestGenerateSaltZeroSize(t *testing.T) {
	salt, err := GenerateSalt(0)
	if err != nil {
		t.Fatalf("GenerateSalt(0) failed: %v", err)
	}
	if len(salt) != 0 {
		t.Errorf("salt length = %d, want 0", len(salt))
	}
}
