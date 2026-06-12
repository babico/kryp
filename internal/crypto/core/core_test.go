package core

import (
	"testing"
)

func TestAlgorithmIDString(t *testing.T) {
	tests := []struct {
		id   AlgorithmID
		want string
	}{
		{0, "unknown"},
		{AlgoXChaCha20Poly1305, "XChaCha20-Poly1305"},
		{AlgoChaCha20Poly1305, "ChaCha20-Poly1305"},
		{AlgoAES256GCM, "AES-256-GCM"},
		{AlgoSecretBox, "NaCl SecretBox (XSalsa20-Poly1305)"},
		{AlgoAES256CTRHMAC, "AES-256-CTR+HMAC-SHA256"},
		{AlgoAge, "age (X25519+ChaCha20-Poly1305)"},
		{AlgoMLKEM768, "ML-KEM-768 (FIPS 203)"},
		{AlgoMLKEM1024, "ML-KEM-1024 (FIPS 203)"},
		{AlgoHybridXWing, "Hybrid X-Wing (X25519+ML-KEM-768)"},
		{AlgoHPKE, "HPKE (X25519+HKDF-SHA256+ChaCha20-Poly1305)"},
		{AlgoASCON128, "ASCON-128 (NIST Lightweight)"},
		{AlgoAEGIS128L, "AEGIS-128L"},
		{AlgoAEGIS256, "AEGIS-256"},
		{AlgoAES256GCMSIV, "AES-256-GCM-SIV (RFC 8452)"},
		{AlgoHQC128, "HQC-128 (FIPS 207)"},
		{AlgoXoodyak, "Xoodyak (NIST LWC)"},
		{AlgoDeoxysII, "Deoxys-II-256-128 (CAESAR)"},
		{AlgoAES256SIV, "AES-256-SIV (RFC 5297)"},
		{AlgoFrodo640SHAKE, "FrodoKEM-640-SHAKE (NIST PQC)"},
		{255, "unknown"},
	}
	for _, tt := range tests {
		got := tt.id.String()
		if got != tt.want {
			t.Errorf("AlgorithmID(%d).String() = %q, want %q", byte(tt.id), got, tt.want)
		}
	}
}

func TestKDFMethodString(t *testing.T) {
	tests := []struct {
		k    KDFMethod
		want string
	}{
		{KDFNone, "none"},
		{KDFArgon2id, "Argon2id"},
		{KDFScrypt, "scrypt"},
		{KDFPBKDF2, "PBKDF2"},
		{99, "unknown"},
	}
	for _, tt := range tests {
		got := tt.k.String()
		if got != tt.want {
			t.Errorf("KDFMethod(%d).String() = %q, want %q", byte(tt.k), got, tt.want)
		}
	}
}

func TestEncryptionResultStruct(t *testing.T) {
	r := &EncryptionResult{
		Algorithm:  AlgoAES256GCM,
		Ciphertext: []byte("encrypted-data"),
		Nonce:      []byte("unique-nonce"),
	}
	if r.Algorithm != AlgoAES256GCM {
		t.Errorf("Algorithm = %d, want %d", r.Algorithm, AlgoAES256GCM)
	}
	if string(r.Ciphertext) != "encrypted-data" {
		t.Errorf("Ciphertext = %q, want %q", r.Ciphertext, "encrypted-data")
	}
	if string(r.Nonce) != "unique-nonce" {
		t.Errorf("Nonce = %q, want %q", r.Nonce, "unique-nonce")
	}
}

func TestEncryptionResultEmptyFields(t *testing.T) {
	r := &EncryptionResult{}
	if r.Algorithm != 0 {
		t.Errorf("default Algorithm = %d, want 0", r.Algorithm)
	}
	if r.Ciphertext != nil {
		t.Errorf("default Ciphertext = %v, want nil", r.Ciphertext)
	}
	if r.Nonce != nil {
		t.Errorf("default Nonce = %v, want nil", r.Nonce)
	}
}

func TestAlgorithmIDComparisons(t *testing.T) {
	if AlgoNone != 0 {
		t.Errorf("AlgoNone should be 0")
	}
	if AlgoXChaCha20Poly1305 != 1 {
		t.Errorf("AlgoXChaCha20Poly1305 should be 1")
	}
	if AlgoFrodo640SHAKE != 19 {
		t.Errorf("AlgoFrodo640SHAKE should be 19")
	}
	if AlgoAES256SIV >= AlgoFrodo640SHAKE {
		t.Errorf("AlgoAES256SIV (%d) should be < AlgoFrodo640SHAKE (%d)", AlgoAES256SIV, AlgoFrodo640SHAKE)
	}
}

func TestEncryptorInterface(t *testing.T) {
	var _ Encryptor = nil
	_ = struct{ Encryptor }{}
}
