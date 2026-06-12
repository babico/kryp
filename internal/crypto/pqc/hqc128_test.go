package pqc

import (
	"bytes"
	"testing"

	"github.com/shurlinet/go-hqc"

	core "github.com/babico/kryp/internal/crypto/core"
)

func hqc128TestKeypair(t *testing.T) (privKey, pubKey []byte) {
	t.Helper()
	dk, err := hqc.GenerateKey128()
	if err != nil {
		t.Fatalf("GenerateKey128 failed: %v", err)
	}
	return dk.Bytes(), dk.EncapsulationKey().Bytes()
}

func TestHQC128EncryptDecrypt(t *testing.T) {
	privKey, pubKey := hqc128TestKeypair(t)

	enc := &HQC128{}
	plaintext := []byte("HQC-128 test - code-based cryptography")

	result, err := enc.Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if result.Algorithm != core.AlgoHQC128 {
		t.Errorf("Algorithm = %d, want %d", result.Algorithm, core.AlgoHQC128)
	}

	decrypted, err := enc.Decrypt(result.Ciphertext, privKey, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted text mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestHQC128WrongKey(t *testing.T) {
	_, pubKey1 := hqc128TestKeypair(t)
	privKey2, _ := hqc128TestKeypair(t)

	enc := &HQC128{}
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

func TestHQC128InvalidPublicKey(t *testing.T) {
	enc := &HQC128{}
	_, err := enc.Encrypt([]byte("data"), []byte("too-short-key"))
	if err == nil {
		t.Fatal("expected error with invalid public key")
	}
}

func TestHQC128TamperedCiphertext(t *testing.T) {
	privKey, pubKey := hqc128TestKeypair(t)

	enc := &HQC128{}
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

func TestHQC128PrivateKeySize(t *testing.T) {
	privKey, _ := hqc128TestKeypair(t)
	if len(privKey) != hqc.SecretKeySize128 {
		t.Errorf("expected private key %d bytes, got %d", hqc.SecretKeySize128, len(privKey))
	}
}

func TestHQC128PublicKeySize(t *testing.T) {
	_, pubKey := hqc128TestKeypair(t)
	expected := hqc.PublicKeySize128
	if len(pubKey) != expected {
		t.Errorf("expected public key %d bytes, got %d", expected, len(pubKey))
	}
}

func TestHQC128CiphertextTooShort(t *testing.T) {
	privKey, pubKey := hqc128TestKeypair(t)
	enc := &HQC128{}

	result, err := enc.Encrypt([]byte("hello"), pubKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = enc.Decrypt([]byte{0x00}, privKey, result.Nonce)
	if err == nil {
		t.Fatal("expected error for ciphertext too short")
	}
}

func TestHQC128EmptyPlaintext(t *testing.T) {
	privKey, pubKey := hqc128TestKeypair(t)
	enc := &HQC128{}

	result, err := enc.Encrypt([]byte{}, pubKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := enc.Decrypt(result.Ciphertext, privKey, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatal("expected empty plaintext")
	}
}
