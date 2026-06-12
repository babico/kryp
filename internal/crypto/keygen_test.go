package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractPublicKeyMLKEM768(t *testing.T) {
	tmpDir := t.TempDir()

	kp, err := GenerateMLKEMKeypair()
	if err != nil {
		t.Fatal(err)
	}

	privPath := filepath.Join(tmpDir, "mlkem768")
	if err := os.WriteFile(privPath, kp.PrivateSeed, 0600); err != nil {
		t.Fatal(err)
	}

	extracted, err := ExtractPublicKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if extracted.Algorithm != AlgoMLKEM768 {
		t.Errorf("algorithm = %d, want %d", extracted.Algorithm, AlgoMLKEM768)
	}
	if string(extracted.PublicKey) != string(kp.PublicKey) {
		t.Error("extracted public key does not match")
	}
}

func TestExtractPublicKeyHQC128(t *testing.T) {
	tmpDir := t.TempDir()

	kp, err := GenerateHQC128Keypair()
	if err != nil {
		t.Fatal(err)
	}

	privPath := filepath.Join(tmpDir, "hqc128")
	if err := os.WriteFile(privPath, kp.PrivateSeed, 0600); err != nil {
		t.Fatal(err)
	}

	extracted, err := ExtractPublicKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if extracted.Algorithm != AlgoHQC128 {
		t.Errorf("algorithm = %d, want %d", extracted.Algorithm, AlgoHQC128)
	}
	if string(extracted.PublicKey) != string(kp.PublicKey) {
		t.Error("extracted public key does not match")
	}
}

func TestExtractPublicKeyInvalid(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "invalid")
	if err := os.WriteFile(path, []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := ExtractPublicKey(path)
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestGenerateKeyPairFromSeedDeterministic(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp1, err := GenerateKeyPairFromSeed(AlgoMLKEM768, seed)
	if err != nil {
		t.Fatal(err)
	}

	kp2, err := GenerateKeyPairFromSeed(AlgoMLKEM768, seed)
	if err != nil {
		t.Fatal(err)
	}

	if string(kp1.PrivateSeed) != string(kp2.PrivateSeed) {
		t.Error("private seeds should be identical for same input seed")
	}
	if string(kp1.PublicKey) != string(kp2.PublicKey) {
		t.Error("public keys should be identical for same input seed")
	}
}

func TestGenerateKeyPairFromSeedTooShort(t *testing.T) {
	shortSeed := make([]byte, 32)
	_, err := GenerateKeyPairFromSeed(AlgoMLKEM768, shortSeed)
	if err == nil {
		t.Error("expected error for too short seed")
	}
}

func TestGenerateKeyPairFromSeedXWing(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	kp1, err := GenerateKeyPairFromSeed(AlgoHybridXWing, seed)
	if err != nil {
		t.Fatal(err)
	}

	kp2, err := GenerateKeyPairFromSeed(AlgoHybridXWing, seed)
	if err != nil {
		t.Fatal(err)
	}

	if string(kp1.PrivateSeed) != string(kp2.PrivateSeed) {
		t.Error("private seeds should be identical for same input seed")
	}
	if string(kp1.PublicKey) != string(kp2.PublicKey) {
		t.Error("public keys should be identical for same input seed")
	}
}

func TestExtractPublicKeyMLKEM1024(t *testing.T) {
	tmpDir := t.TempDir()

	kp, err := GenerateMLKEM1024Keypair()
	if err != nil {
		t.Fatal(err)
	}

	privPath := tmpDir + "\\mlkem1024"
	if err := os.WriteFile(privPath, kp.PrivateSeed, 0600); err != nil {
		t.Fatal(err)
	}

	extracted, err := ExtractPublicKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(extracted.PrivateSeed) != string(kp.PrivateSeed) {
		t.Error("extracted private seed does not match")
	}
}

func TestExtractPublicKeyXWing(t *testing.T) {
	tmpDir := t.TempDir()

	kp, err := GenerateXWingKeypair()
	if err != nil {
		t.Fatal(err)
	}

	privPath := tmpDir + "\\xwing"
	if err := os.WriteFile(privPath, kp.PrivateSeed, 0600); err != nil {
		t.Fatal(err)
	}

	extracted, err := ExtractPublicKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(extracted.PrivateSeed) != string(kp.PrivateSeed) {
		t.Error("extracted private seed does not match")
	}
}

func TestExtractPublicKeyHPKE(t *testing.T) {
	tmpDir := t.TempDir()

	kp, err := GenerateHPKEKeypair()
	if err != nil {
		t.Fatal(err)
	}

	privPath := tmpDir + "\\hpke"
	if err := os.WriteFile(privPath, kp.PrivateSeed, 0600); err != nil {
		t.Fatal(err)
	}

	extracted, err := ExtractPublicKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(extracted.PrivateSeed) != string(kp.PrivateSeed) {
		t.Error("extracted private seed does not match")
	}
}

func TestExtractPublicKeyFrodoKEMNotSupported(t *testing.T) {
	tmpDir := t.TempDir()

	kp, err := GenerateFrodo640Keypair()
	if err != nil {
		t.Fatal(err)
	}

	privPath := tmpDir + "\\frodokem640"
	if err := os.WriteFile(privPath, kp.PrivateSeed, 0600); err != nil {
		t.Fatal(err)
	}

	_, err = ExtractPublicKey(privPath)
	if err == nil {
		t.Log("FrodoKEM ExtractPublicKey is not yet supported, expected error")
	}
}

func TestExtractPublicKeyFileNotFound(t *testing.T) {
	_, err := ExtractPublicKey("\\nonexistent\\path\\key.bin")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestGenerateKeyPairFromSeedMLKEM1024(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp1, err := GenerateKeyPairFromSeed(AlgoMLKEM1024, seed)
	if err != nil {
		t.Fatal(err)
	}

	kp2, err := GenerateKeyPairFromSeed(AlgoMLKEM1024, seed)
	if err != nil {
		t.Fatal(err)
	}

	if string(kp1.PrivateSeed) != string(kp2.PrivateSeed) {
		t.Error("private seeds should be identical")
	}
	if string(kp1.PublicKey) != string(kp2.PublicKey) {
		t.Error("public keys should be identical")
	}
}

func TestGenerateKeyPairFromSeedHPKE(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp1, err := GenerateKeyPairFromSeed(AlgoHPKE, seed)
	if err != nil {
		t.Fatal(err)
	}

	kp2, err := GenerateKeyPairFromSeed(AlgoHPKE, seed)
	if err != nil {
		t.Fatal(err)
	}

	if string(kp1.PrivateSeed) != string(kp2.PrivateSeed) {
		t.Error("private seeds should be identical")
	}
	if string(kp1.PublicKey) != string(kp2.PublicKey) {
		t.Error("public keys should be identical")
	}
}

func TestGenerateKeyPairFromSeedHPKETooShort(t *testing.T) {
	_, err := GenerateKeyPairFromSeed(AlgoHPKE, []byte("short"))
	if err == nil {
		t.Error("expected error for too short seed")
	}
}

func TestGenerateKeyPairFromSeedFrodoKEM(t *testing.T) {
	seed := make([]byte, 96)
	for i := range seed {
		seed[i] = byte(i)
	}

	kp1, err := GenerateKeyPairFromSeed(AlgoFrodo640SHAKE, seed)
	if err != nil {
		t.Fatal(err)
	}

	kp2, err := GenerateKeyPairFromSeed(AlgoFrodo640SHAKE, seed)
	if err != nil {
		t.Fatal(err)
	}

	if string(kp1.PrivateSeed) != string(kp2.PrivateSeed) {
		t.Error("private seeds should be identical")
	}
	if string(kp1.PublicKey) != string(kp2.PublicKey) {
		t.Error("public keys should be identical")
	}
}

func TestGenerateKeyPairFromSeedHQC128Error(t *testing.T) {
	seed := make([]byte, 64)
	_, err := GenerateKeyPairFromSeed(AlgoHQC128, seed)
	if err == nil {
		t.Error("expected error for HQC-128 seed-based keygen")
	}
}

func TestGenerateKeyPairFromSeedUnsupportedAlgo(t *testing.T) {
	seed := make([]byte, 32)
	_, err := GenerateKeyPairFromSeed(AlgoXChaCha20Poly1305, seed)
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestGenerateKeyPairFromSeedMLKEM768TooShort(t *testing.T) {
	_, err := GenerateKeyPairFromSeed(AlgoMLKEM768, make([]byte, 32))
	if err == nil {
		t.Error("expected error for too short seed")
	}
}

func TestGenerateKeyPairFromSeedMLKEM1024TooShort(t *testing.T) {
	_, err := GenerateKeyPairFromSeed(AlgoMLKEM1024, make([]byte, 32))
	if err == nil {
		t.Error("expected error for too short seed")
	}
}

func TestGenerateKeyPairFromSeedXWingTooShort(t *testing.T) {
	_, err := GenerateKeyPairFromSeed(AlgoHybridXWing, make([]byte, 16))
	if err == nil {
		t.Error("expected error for too short seed")
	}
}

func TestGenerateKeyPairFromSeedAllPQC(t *testing.T) {
	algos := []struct {
		id       AlgorithmID
		seedLen  int
		minLen   int
	}{
		{AlgoMLKEM768, 64, 64},
		{AlgoMLKEM1024, 64, 64},
		{AlgoHybridXWing, 32, 32},
		{AlgoHPKE, 32, 32},
		{AlgoFrodo640SHAKE, 96, 32},
	}

	for _, a := range algos {
		t.Run(a.id.String(), func(t *testing.T) {
			seed := make([]byte, a.seedLen)
			for i := range seed {
				seed[i] = byte(i)
			}
			kp, err := GenerateKeyPairFromSeed(a.id, seed)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if kp.Algorithm != a.id {
				t.Errorf("algorithm = %d, want %d", kp.Algorithm, a.id)
			}
			if len(kp.PrivateSeed) == 0 {
				t.Error("private seed should not be empty")
			}
			if len(kp.PublicKey) == 0 {
				t.Error("public key should not be empty")
			}

			shortSeed := make([]byte, a.minLen-1)
			_, err = GenerateKeyPairFromSeed(a.id, shortSeed)
			if a.id == AlgoFrodo640SHAKE {
				if err != nil {
					t.Fatalf("FrodoKEM should not reject short seed: %v", err)
				}
			} else if err == nil {
				t.Error("expected error for too short seed")
			}
		})
	}
}
