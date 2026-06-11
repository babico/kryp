package pqc

import (
	"bytes"
	"testing"

	"filippo.io/mlkem768/xwing"

	core "github.com/babico/data-encrypter-decrypter/internal/crypto/core"
)

func TestXWingEncryptDecrypt(t *testing.T) {
	dk, err := xwing.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	privSeed := dk.Bytes()
	pubKey := dk.EncapsulationKey()

	if len(privSeed) != xwing.SeedSize {
		t.Fatalf("expected seed %d bytes, got %d", xwing.SeedSize, len(privSeed))
	}
	if len(pubKey) != xwing.EncapsulationKeySize {
		t.Fatalf("expected pub key %d bytes, got %d", xwing.EncapsulationKeySize, len(pubKey))
	}

	enc := &HybridXWing{}
	plaintext := []byte("Hello, Hybrid World! X-Wing test")

	result, err := enc.Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(result.Nonce) != xwing.CiphertextSize {
		t.Errorf("expected nonce (KEM ct) %d bytes, got %d", xwing.CiphertextSize, len(result.Nonce))
	}

	if result.Algorithm != core.AlgoHybridXWing {
		t.Errorf("Algorithm = %d, want %d", result.Algorithm, core.AlgoHybridXWing)
	}

	decrypted, err := enc.Decrypt(result.Ciphertext, privSeed, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted text mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestXWingWrongKey(t *testing.T) {
	dk1, _ := xwing.GenerateKey()
	dk2, _ := xwing.GenerateKey()

	pubKey1 := dk1.EncapsulationKey()
	privSeed2 := dk2.Bytes()

	enc := &HybridXWing{}
	plaintext := []byte("test data")

	result, err := enc.Encrypt(plaintext, pubKey1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = enc.Decrypt(result.Ciphertext, privSeed2, result.Nonce)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestXWingInvalidPublicKey(t *testing.T) {
	enc := &HybridXWing{}
	_, err := enc.Encrypt([]byte("data"), []byte("too-short-key"))
	if err == nil {
		t.Fatal("expected error with invalid public key")
	}
}

func TestXWingTamperedCiphertext(t *testing.T) {
	dk, err := xwing.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	privSeed := dk.Bytes()
	pubKey := dk.EncapsulationKey()

	enc := &HybridXWing{}
	plaintext := []byte("sensitive data")

	result, err := enc.Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result.Ciphertext[0] ^= 0xFF

	_, err = enc.Decrypt(result.Ciphertext, privSeed, result.Nonce)
	if err == nil {
		t.Fatal("expected error with tampered ciphertext")
	}
}
