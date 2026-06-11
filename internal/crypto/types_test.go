package crypto

import (
	"testing"
)

func TestParseAlgorithmValid(t *testing.T) {
	tests := []struct {
		input string
		want  AlgorithmID
	}{
		{"xchacha20-poly1305", AlgoXChaCha20Poly1305},
		{"xchacha20", AlgoXChaCha20Poly1305},
		{"1", AlgoXChaCha20Poly1305},
		{"chacha20-poly1305", AlgoChaCha20Poly1305},
		{"chacha20", AlgoChaCha20Poly1305},
		{"2", AlgoChaCha20Poly1305},
		{"aes-256-gcm", AlgoAES256GCM},
		{"aes-gcm", AlgoAES256GCM},
		{"aes", AlgoAES256GCM},
		{"3", AlgoAES256GCM},
		{"secretbox", AlgoSecretBox},
		{"nacl", AlgoSecretBox},
		{"xsalsa20", AlgoSecretBox},
		{"4", AlgoSecretBox},
		{"aes-256-ctr-hmac", AlgoAES256CTRHMAC},
		{"aes-ctr-hmac", AlgoAES256CTRHMAC},
		{"5", AlgoAES256CTRHMAC},
		{"age", AlgoAge},
		{"6", AlgoAge},
		{"XCHACHA20-POLY1305", AlgoXChaCha20Poly1305},
		{"AES-256-GCM", AlgoAES256GCM},
		{"Age", AlgoAge},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseAlgorithm(tt.input)
			if err != nil {
				t.Fatalf("ParseAlgorithm(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ParseAlgorithm(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseAlgorithmInvalid(t *testing.T) {
	_, err := ParseAlgorithm("invalid-algo")
	if err == nil {
		t.Fatal("expected error for invalid algorithm")
	}

	_, err = ParseAlgorithm("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}

func TestParseKDFValid(t *testing.T) {
	tests := []struct {
		input string
		want  KDFMethod
	}{
		{"argon2id", KDFArgon2id},
		{"argon2", KDFArgon2id},
		{"scrypt", KDFScrypt},
		{"pbkdf2", KDFPBKDF2},
		{"none", KDFNone},
		{"raw", KDFNone},
		{"ARGON2ID", KDFArgon2id},
		{"SCRYPT", KDFScrypt},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseKDF(tt.input)
			if err != nil {
				t.Fatalf("ParseKDF(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ParseKDF(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseKDFInvalid(t *testing.T) {
	_, err := ParseKDF("invalid-kdf")
	if err == nil {
		t.Fatal("expected error for invalid KDF")
	}
}

func TestAlgorithmIDString(t *testing.T) {
	if AlgoNone.String() != "unknown" {
		t.Errorf("AlgoNone.String() = %q, want unknown", AlgoNone.String())
	}
	if AlgoXChaCha20Poly1305.String() != "XChaCha20-Poly1305" {
		t.Errorf("got %q", AlgoXChaCha20Poly1305.String())
	}
	if AlgoAge.String() != "age (X25519+ChaCha20-Poly1305)" {
		t.Errorf("got %q", AlgoAge.String())
	}
	if AlgorithmID(99).String() != "unknown" {
		t.Errorf("unknown algo should return unknown")
	}
}

func TestKDFMethodString(t *testing.T) {
	if KDFNone.String() != "none" {
		t.Errorf("KDFNone.String() = %q", KDFNone.String())
	}
	if KDFArgon2id.String() != "Argon2id" {
		t.Errorf("KDFArgon2id.String() = %q", KDFArgon2id.String())
	}
	if KDFMethod(99).String() != "unknown" {
		t.Errorf("unknown KDF should return unknown")
	}
}

func TestListAlgorithms(t *testing.T) {
	algos := ListAlgorithms()
	if len(algos) == 0 {
		t.Fatal("ListAlgorithms returned empty list")
	}
	if len(algos) < 6 {
		t.Errorf("got %d algorithms, want at least 6", len(algos))
	}
}
