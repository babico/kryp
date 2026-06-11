package crypto

import (
	"bytes"
	"testing"
)

func TestHeaderRoundtrip(t *testing.T) {
	tests := []struct {
		name   string
		header *Header
	}{
		{
			name: "XChaCha20 with Argon2id",
			header: &Header{
				Version:   1,
				Algorithm: AlgoXChaCha20Poly1305,
				KDFMethod: KDFArgon2id,
				KDFSalt:   []byte("0123456789abcdef"),
				KDFParams: EncodeArgon2Params(3, 65536, 4),
				Nonce:     make([]byte, 24),
			},
		},
		{
			name: "AES-GCM with raw key",
			header: &Header{
				Version:   1,
				Algorithm: AlgoAES256GCM,
				KDFMethod: KDFNone,
				Nonce:     make([]byte, 12),
			},
		},
		{
			name: "ChaCha20 with scrypt",
			header: &Header{
				Version:   1,
				Algorithm: AlgoChaCha20Poly1305,
				KDFMethod: KDFScrypt,
				KDFSalt:   []byte("0123456789abcdef"),
				KDFParams: EncodeScryptParams(32768, 8, 1),
				Nonce:     make([]byte, 12),
			},
		},
		{
			name: "SecretBox with PBKDF2",
			header: &Header{
				Version:   1,
				Algorithm: AlgoSecretBox,
				KDFMethod: KDFPBKDF2,
				KDFSalt:   []byte("0123456789abcdef"),
				KDFParams: EncodePBKDF2Params(600000),
				Nonce:     make([]byte, 24),
			},
		},
		{
			name: "AES-CTR+HMAC no KDF",
			header: &Header{
				Version:   1,
				Algorithm: AlgoAES256CTRHMAC,
				KDFMethod: KDFNone,
				Nonce:     make([]byte, 16),
			},
		},
		{
			name: "Age no KDF no nonce",
			header: &Header{
				Version:   1,
				Algorithm: AlgoAge,
				KDFMethod: KDFNone,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.header.Encode()
			decoded, err := DecodeHeader(encoded)
			if err != nil {
				t.Fatalf("DecodeHeader failed: %v", err)
			}
			if decoded.Version != tt.header.Version {
				t.Errorf("Version = %d, want %d", decoded.Version, tt.header.Version)
			}
			if decoded.Algorithm != tt.header.Algorithm {
				t.Errorf("Algorithm = %d, want %d", decoded.Algorithm, tt.header.Algorithm)
			}
			if decoded.KDFMethod != tt.header.KDFMethod {
				t.Errorf("KDFMethod = %d, want %d", decoded.KDFMethod, tt.header.KDFMethod)
			}
			if !bytes.Equal(decoded.Nonce, tt.header.Nonce) {
				t.Errorf("Nonce mismatch")
			}
			if !bytes.Equal(decoded.KDFSalt, tt.header.KDFSalt) {
				t.Errorf("KDFSalt mismatch")
			}
			if !bytes.Equal(decoded.KDFParams, tt.header.KDFParams) {
				t.Errorf("KDFParams mismatch")
			}
		})
	}
}

func TestHeaderInvalidMagic(t *testing.T) {
	_, err := DecodeHeader([]byte("XXXX\x01\x00\x00\x00\x00\x00"))
	if err == nil {
		t.Fatal("expected error for invalid magic")
	}
}

func TestHeaderTooShort(t *testing.T) {
	_, err := DecodeHeader([]byte("ENC"))
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestHeaderMetadataRoundTrip(t *testing.T) {
	h := &Header{
		Version:      1,
		Algorithm:    AlgoXChaCha20Poly1305,
		KDFMethod:    KDFArgon2id,
		KDFSalt:      []byte("0123456789abcdef"),
		KDFParams:    EncodeArgon2Params(3, 65536, 4),
		Nonce:        make([]byte, 24),
		OriginalName: "myfile.txt",
		OriginalPath: "/home/user/docs/myfile.txt",
	}

	encoded := h.Encode()
	decoded, err := DecodeHeader(encoded)
	if err != nil {
		t.Fatalf("DecodeHeader failed: %v", err)
	}

	if decoded.OriginalName != "myfile.txt" {
		t.Errorf("OriginalName = %q, want %q", decoded.OriginalName, "myfile.txt")
	}
	if decoded.OriginalPath != "/home/user/docs/myfile.txt" {
		t.Errorf("OriginalPath = %q, want %q", decoded.OriginalPath, "/home/user/docs/myfile.txt")
	}
	if decoded.Algorithm != AlgoXChaCha20Poly1305 {
		t.Errorf("Algorithm = %d, want %d", decoded.Algorithm, AlgoXChaCha20Poly1305)
	}
}

func TestHeaderMetadataOnlyName(t *testing.T) {
	h := &Header{
		Version:      1,
		Algorithm:    AlgoAge,
		KDFMethod:    KDFNone,
		OriginalName: "document.pdf",
	}

	encoded := h.Encode()
	decoded, err := DecodeHeader(encoded)
	if err != nil {
		t.Fatalf("DecodeHeader failed: %v", err)
	}

	if decoded.OriginalName != "document.pdf" {
		t.Errorf("OriginalName = %q, want %q", decoded.OriginalName, "document.pdf")
	}
	if decoded.OriginalPath != "" {
		t.Errorf("OriginalPath should be empty, got %q", decoded.OriginalPath)
	}
}

func TestHeaderMetadataOnlyPath(t *testing.T) {
	h := &Header{
		Version:      1,
		Algorithm:    AlgoAES256GCM,
		KDFMethod:    KDFNone,
		Nonce:        make([]byte, 12),
		OriginalPath: "/var/log/app/data.db",
	}

	encoded := h.Encode()
	decoded, err := DecodeHeader(encoded)
	if err != nil {
		t.Fatalf("DecodeHeader failed: %v", err)
	}

	if decoded.OriginalName != "" {
		t.Errorf("OriginalName should be empty, got %q", decoded.OriginalName)
	}
	if decoded.OriginalPath != "/var/log/app/data.db" {
		t.Errorf("OriginalPath = %q, want %q", decoded.OriginalPath, "/var/log/app/data.db")
	}
}

func TestHeaderMetadataUnicode(t *testing.T) {
	h := &Header{
		Version:      1,
		Algorithm:    AlgoSecretBox,
		KDFMethod:    KDFNone,
		Nonce:        make([]byte, 24),
		OriginalName: "résumé🔐.pdf",
		OriginalPath: "/数据/机密/file.txt",
	}

	encoded := h.Encode()
	decoded, err := DecodeHeader(encoded)
	if err != nil {
		t.Fatalf("DecodeHeader failed: %v", err)
	}

	if decoded.OriginalName != "résumé🔐.pdf" {
		t.Errorf("OriginalName = %q", decoded.OriginalName)
	}
	if decoded.OriginalPath != "/数据/机密/file.txt" {
		t.Errorf("OriginalPath = %q", decoded.OriginalPath)
	}
}

func TestHeaderOverhead(t *testing.T) {
	h := &Header{
		Version:   1,
		Algorithm: AlgoXChaCha20Poly1305,
		KDFMethod: KDFArgon2id,
		KDFSalt:   make([]byte, 16),
		KDFParams: EncodeArgon2Params(3, 65536, 4),
		Nonce:     make([]byte, 24),
	}
	overhead := HeaderOverhead(h)
	encodedLen := len(h.Encode())
	if overhead != encodedLen {
		t.Errorf("HeaderOverhead = %d, Encode length = %d", overhead, encodedLen)
	}
}
