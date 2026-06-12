package pqc

import (
	"bytes"
	"testing"

	go_frodokem "github.com/kuking/go-frodokem"

	core "github.com/babico/kryp/internal/crypto/core"
)

func frodoTestKeypair(t *testing.T) (privKey, pubKey []byte) {
	t.Helper()
	fk := go_frodokem.Frodo640SHAKE()
	pk, sk := fk.Keygen()
	return sk, pk
}

func TestFrodo640SHAKEEncryptDecrypt(t *testing.T) {
	privKey, pubKey := frodoTestKeypair(t)

	if len(pubKey) != 9616 {
		t.Fatalf("expected public key 9616 bytes, got %d", len(pubKey))
	}

	enc := &Frodo640SHAKE{}
	plaintext := []byte("FrodoKEM-640-SHAKE test")

	result, err := enc.Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if result.Algorithm != core.AlgoFrodo640SHAKE {
		t.Errorf("Algorithm = %d, want %d", result.Algorithm, core.AlgoFrodo640SHAKE)
	}

	decrypted, err := enc.Decrypt(result.Ciphertext, privKey, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted text mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestFrodo640SHAKEWrongKey(t *testing.T) {
	_, pubKey1 := frodoTestKeypair(t)
	privKey2, _ := frodoTestKeypair(t)

	enc := &Frodo640SHAKE{}
	plaintext := []byte("test data")

	result, err := enc.Encrypt(plaintext, pubKey1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = enc.Decrypt(result.Ciphertext, privKey2, result.Nonce)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestFrodo640SHAKEInvalidPublicKey(t *testing.T) {
	enc := &Frodo640SHAKE{}
	_, err := enc.Encrypt([]byte("data"), []byte("too-short-key"))
	if err == nil {
		t.Fatal("expected error with invalid public key")
	}
}

func TestFrodo640SHAKETamperedCiphertext(t *testing.T) {
	privKey, pubKey := frodoTestKeypair(t)

	enc := &Frodo640SHAKE{}
	plaintext := []byte("sensitive data")

	result, err := enc.Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result.Ciphertext[0] ^= 0xFF

	_, err = enc.Decrypt(result.Ciphertext, privKey, result.Nonce)
	if err == nil {
		t.Fatal("expected error with tampered ciphertext")
	}
}

func TestFrodo640SHAKEPrivateKeySize(t *testing.T) {
	privKey, _ := frodoTestKeypair(t)
	fk := go_frodokem.Frodo640SHAKE()
	if len(privKey) != fk.SecretKeyLen() {
		t.Errorf("expected private key %d bytes, got %d", fk.SecretKeyLen(), len(privKey))
	}
}

func TestFrodo640SHAKECiphertextTooShort(t *testing.T) {
	privKey, pubKey := frodoTestKeypair(t)
	enc := &Frodo640SHAKE{}

	result, err := enc.Encrypt([]byte("hello"), pubKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = enc.Decrypt([]byte{0x00}, privKey, result.Nonce)
	if err == nil {
		t.Fatal("expected error for ciphertext too short")
	}
}
