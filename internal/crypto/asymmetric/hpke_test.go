package asymmetric

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/hpke"

	core "github.com/babico/kryp/internal/crypto/core"
)

func hpkeTestKeypair(t *testing.T) (privSeed, pubKey []byte) {
	t.Helper()
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	kemID, _, _ := suite.Params()
	scheme := kemID.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	privSeed, err = sk.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	pubKey, err = pk.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	return
}

func TestHPKEEncryptDecrypt(t *testing.T) {
	privSeed, pubKey := hpkeTestKeypair(t)

	if len(privSeed) != 32 {
		t.Fatalf("expected private key 32 bytes, got %d", len(privSeed))
	}
	if len(pubKey) != 32 {
		t.Fatalf("expected public key 32 bytes, got %d", len(pubKey))
	}

	enc := &HPKEEncryptor{}
	plaintext := []byte("Hello, HPKE World! test")

	result, err := enc.Encrypt(plaintext, pubKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(result.Nonce) != 32 {
		t.Errorf("expected nonce (enc) 32 bytes, got %d", len(result.Nonce))
	}

	if result.Algorithm != core.AlgoHPKE {
		t.Errorf("Algorithm = %d, want %d", result.Algorithm, core.AlgoHPKE)
	}

	decrypted, err := enc.Decrypt(result.Ciphertext, privSeed, result.Nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted text mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestHPKEWrongKey(t *testing.T) {
	_, pubKey1 := hpkeTestKeypair(t)
	privSeed2, _ := hpkeTestKeypair(t)

	enc := &HPKEEncryptor{}
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

func TestHPKEInvalidPublicKey(t *testing.T) {
	enc := &HPKEEncryptor{}
	_, err := enc.Encrypt([]byte("data"), []byte("too-short"))
	if err == nil {
		t.Fatal("expected error with invalid public key")
	}
}

func TestHPKETamperedCiphertext(t *testing.T) {
	privSeed, pubKey := hpkeTestKeypair(t)

	enc := &HPKEEncryptor{}
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
