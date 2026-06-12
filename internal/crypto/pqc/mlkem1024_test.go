package pqc

import (
	"bytes"
	"crypto/mlkem"
	"testing"

	core "github.com/babico/kryp/internal/crypto/core"
)

func TestMLKEM1024EncryptDecrypt(t *testing.T) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatalf("GenerateKey1024 failed: %v", err)
	}

	privSeed := dk.Bytes()
	pubKey := dk.EncapsulationKey().Bytes()

	if len(privSeed) != mlkem.SeedSize {
		t.Fatalf("expected seed %d bytes, got %d", mlkem.SeedSize, len(privSeed))
	}
	if len(pubKey) != mlkem.EncapsulationKeySize1024 {
		t.Fatalf("expected pub key %d bytes, got %d", mlkem.EncapsulationKeySize1024, len(pubKey))
	}

	enc := &MLKEM1024{}
	plaintext := []byte("Hello, Post-Quantum World! ML-KEM-1024 test")

	result, err := enc.Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(result.Nonce) != mlkem.CiphertextSize1024 {
		t.Errorf("expected nonce (KEM ct) %d bytes, got %d", mlkem.CiphertextSize1024, len(result.Nonce))
	}

	if result.Algorithm != core.AlgoMLKEM1024 {
		t.Errorf("Algorithm = %d, want %d", result.Algorithm, core.AlgoMLKEM1024)
	}

	decrypted, err := enc.Decrypt(result.Ciphertext, privSeed, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted text mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestMLKEM1024WrongKey(t *testing.T) {
	dk1, _ := mlkem.GenerateKey1024()
	dk2, _ := mlkem.GenerateKey1024()

	pubKey1 := dk1.EncapsulationKey().Bytes()
	privSeed2 := dk2.Bytes()

	enc := &MLKEM1024{}
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

func TestMLKEM1024InvalidPublicKey(t *testing.T) {
	enc := &MLKEM1024{}
	_, err := enc.Encrypt([]byte("data"), []byte("too-short-key"))
	if err == nil {
		t.Fatal("expected error with invalid public key")
	}
}

func TestMLKEM1024TamperedCiphertext(t *testing.T) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatalf("GenerateKey1024 failed: %v", err)
	}

	privSeed := dk.Bytes()
	pubKey := dk.EncapsulationKey().Bytes()

	enc := &MLKEM1024{}
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
