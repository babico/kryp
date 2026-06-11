package crypto

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestGetEncryptor(t *testing.T) {
	if _, err := GetEncryptor(AlgoXChaCha20Poly1305); err != nil {
		t.Errorf("GetEncryptor for XChaCha20: %v", err)
	}
	if _, err := GetEncryptor(AlgoAES256GCM); err != nil {
		t.Errorf("GetEncryptor for AES256GCM: %v", err)
	}
	if _, err := GetEncryptor(AlgoAge); err != nil {
		t.Errorf("GetEncryptor for age: %v", err)
	}
	if _, err := GetEncryptor(99); err == nil {
		t.Error("expected error for unknown algorithm")
	}
}

func TestGetEncryptorAge(t *testing.T) {
	e, err := GetEncryptor(AlgoAge)
	if err != nil {
		t.Fatalf("GetEncryptor(AlgoAge): %v", err)
	}
	if e.ID() != AlgoAge {
		t.Errorf("ID = %d, want %d", e.ID(), AlgoAge)
	}
	if e.KeySize() != 0 {
		t.Errorf("age KeySize should be 0, got %d", e.KeySize())
	}
}

func TestAllAlgorithmsEmptyData(t *testing.T) {
	algos := []AlgorithmID{AlgoXChaCha20Poly1305, AlgoChaCha20Poly1305, AlgoAES256GCM, AlgoSecretBox, AlgoAES256CTRHMAC, AlgoASCON128}
	algorithms := make([]Encryptor, len(algos))
	for i, id := range algos {
		var err error
		algorithms[i], err = GetEncryptor(id)
		if err != nil {
			t.Fatalf("GetEncryptor(%d): %v", id, err)
		}
	}

	for _, algo := range algorithms {
		t.Run(algo.ID().String(), func(t *testing.T) {
			key := make([]byte, algo.KeySize())
			rand.Read(key)

			result, err := algo.Encrypt(nil, key)
			if err != nil {
				t.Fatalf("Encrypt empty failed: %v", err)
			}

			decrypted, err := algo.Decrypt(result.Ciphertext, key, result.Nonce)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if len(decrypted) != 0 {
				t.Fatal("decrypted empty data should be empty")
			}
		})
	}
}

func TestAllAlgorithmsLargeData(t *testing.T) {
	algos := []AlgorithmID{AlgoXChaCha20Poly1305, AlgoChaCha20Poly1305, AlgoAES256GCM, AlgoSecretBox, AlgoAES256CTRHMAC, AlgoASCON128}
	algorithms := make([]Encryptor, len(algos))
	for i, id := range algos {
		var err error
		algorithms[i], err = GetEncryptor(id)
		if err != nil {
			t.Fatalf("GetEncryptor(%d): %v", id, err)
		}
	}

	plaintext := make([]byte, 10*1024*1024)
	rand.Read(plaintext)

	for _, algo := range algorithms {
		t.Run(algo.ID().String(), func(t *testing.T) {
			key := make([]byte, algo.KeySize())
			rand.Read(key)

			result, err := algo.Encrypt(plaintext, key)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := algo.Decrypt(result.Ciphertext, key, result.Nonce)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Fatal("decrypted large data does not match original")
			}
		})
	}
}

func TestEncryptFileSmallFile(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "test.txt")
	dstPath := filepath.Join(dir, "test.enc")

	err := os.WriteFile(srcPath, []byte("small file test data"), 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	opts := &EncryptFileOptions{
		Algorithm:  AlgoXChaCha20Poly1305,
		Passphrase: []byte("test-passphrase-123"),
		KDFMethod:  KDFArgon2id,
	}

	encData, err := EncryptFile(srcPath, opts)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	err = os.WriteFile(dstPath, encData, 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	decOpts := &DecryptFileOptions{
		Passphrase: []byte("test-passphrase-123"),
	}

	plaintext, header, err := DecryptFile(dstPath, decOpts)
	if err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	if header.Algorithm != AlgoXChaCha20Poly1305 {
		t.Errorf("Algorithm = %d, want %d", header.Algorithm, AlgoXChaCha20Poly1305)
	}

	if string(plaintext) != "small file test data" {
		t.Fatalf("decrypted content mismatch: got %q", string(plaintext))
	}
}

func TestEncryptFileAllAlgorithms(t *testing.T) {
	algorithms := []struct {
		name AlgorithmID
		kdf  KDFMethod
	}{
		{AlgoXChaCha20Poly1305, KDFArgon2id},
		{AlgoChaCha20Poly1305, KDFScrypt},
		{AlgoAES256GCM, KDFPBKDF2},
		{AlgoSecretBox, KDFArgon2id},
		{AlgoAES256CTRHMAC, KDFArgon2id},
	}

	for _, algo := range algorithms {
		t.Run(algo.name.String(), func(t *testing.T) {
			dir := t.TempDir()
			srcPath := filepath.Join(dir, "test.txt")
			dstPath := filepath.Join(dir, "test.enc")

			content := []byte("Algorithm test: " + algo.name.String())
			err := os.WriteFile(srcPath, content, 0644)
			if err != nil {
				t.Fatalf("WriteFile failed: %v", err)
			}

			opts := &EncryptFileOptions{
				Algorithm:  algo.name,
				Passphrase: []byte("test-pass-123"),
				KDFMethod:  algo.kdf,
			}

			encData, err := EncryptFile(srcPath, opts)
			if err != nil {
				t.Fatalf("EncryptFile failed: %v", err)
			}

			err = os.WriteFile(dstPath, encData, 0644)
			if err != nil {
				t.Fatalf("WriteFile failed: %v", err)
			}

			decOpts := &DecryptFileOptions{
				Passphrase: []byte("test-pass-123"),
			}

			plaintext, header, err := DecryptFile(dstPath, decOpts)
			if err != nil {
				t.Fatalf("DecryptFile failed: %v", err)
			}

			if header.Algorithm != algo.name {
				t.Errorf("algorithm mismatch in header: got %d, want %d", header.Algorithm, algo.name)
			}

			if !bytes.Equal(plaintext, content) {
				t.Fatal("decrypted content mismatch")
			}
		})
	}
}

func TestEncryptFileRawKey(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "test.txt")
	dstPath := filepath.Join(dir, "test.enc")
	keyPath := filepath.Join(dir, "key.bin")

	err := os.WriteFile(srcPath, []byte("raw key test"), 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)
	err = os.WriteFile(keyPath, key, 0600)
	if err != nil {
		t.Fatalf("WriteFile key failed: %v", err)
	}

	opts := &EncryptFileOptions{
		Algorithm: AlgoXChaCha20Poly1305,
		KeyFile:   keyPath,
	}

	encData, err := EncryptFile(srcPath, opts)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	err = os.WriteFile(dstPath, encData, 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	decOpts := &DecryptFileOptions{
		KeyFile: keyPath,
	}

	plaintext, _, err := DecryptFile(dstPath, decOpts)
	if err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	if string(plaintext) != "raw key test" {
		t.Fatal("decrypted content mismatch")
	}
}

func TestEncryptFileWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "test.txt")
	dstPath := filepath.Join(dir, "test.enc")

	err := os.WriteFile(srcPath, []byte("secret data"), 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	opts := &EncryptFileOptions{
		Algorithm:  AlgoAES256GCM,
		Passphrase: []byte("correct-passphrase"),
		KDFMethod:  KDFArgon2id,
	}

	encData, err := EncryptFile(srcPath, opts)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	err = os.WriteFile(dstPath, encData, 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	decOpts := &DecryptFileOptions{
		Passphrase: []byte("wrong-passphrase"),
	}

	_, _, err = DecryptFile(dstPath, decOpts)
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestEncryptFileCorruptedHeader(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "corrupt.enc")

	err := os.WriteFile(filePath, []byte("NOTANENCRFILE"), 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, _, err = DecryptFile(filePath, &DecryptFileOptions{Passphrase: []byte("test")})
	if err == nil {
		t.Fatal("expected error for corrupted file")
	}
}

func TestEncryptFileBytesRoundtrip(t *testing.T) {
	plaintext := []byte("in-memory encryption test data")

	opts := &EncryptFileOptions{
		Algorithm:  AlgoXChaCha20Poly1305,
		Passphrase: []byte("test-pass"),
		KDFMethod:  KDFArgon2id,
	}

	encData, err := EncryptFileBytes(plaintext, opts)
	if err != nil {
		t.Fatalf("EncryptFileBytes failed: %v", err)
	}

	decOpts := &DecryptFileOptions{
		Passphrase: []byte("test-pass"),
	}

	decrypted, header, err := DecryptFileBytes(encData, decOpts)
	if err != nil {
		t.Fatalf("DecryptFileBytes failed: %v", err)
	}

	if header.Algorithm != AlgoXChaCha20Poly1305 {
		t.Errorf("algorithm mismatch: got %d, want %d", header.Algorithm, AlgoXChaCha20Poly1305)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted content mismatch")
	}
}

func TestEncryptFileWithEmbeddedMetadata(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "subdir", "secret.txt")
	encPath := filepath.Join(dir, "output", "secret.enc")

	err := os.MkdirAll(filepath.Dir(srcPath), 0755)
	if err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	content := []byte("file with embedded metadata test")
	err = os.WriteFile(srcPath, content, 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	opts := &EncryptFileOptions{
		Algorithm:     AlgoXChaCha20Poly1305,
		Passphrase:    []byte("test-pass"),
		KDFMethod:     KDFArgon2id,
		EmbedMetadata: true,
	}

	encData, err := EncryptFile(srcPath, opts)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	err = os.MkdirAll(filepath.Dir(encPath), 0755)
	if err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	err = os.WriteFile(encPath, encData, 0644)
	if err != nil {
		t.Fatalf("WriteFile encrypted failed: %v", err)
	}

	decOpts := &DecryptFileOptions{
		Passphrase: []byte("test-pass"),
	}

	plaintext, header, err := DecryptFile(encPath, decOpts)
	if err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	if header.OriginalName != "secret.txt" {
		t.Errorf("OriginalName = %q, want %q", header.OriginalName, "secret.txt")
	}
	if !strings.HasSuffix(header.OriginalPath, "subdir\\secret.txt") && !strings.HasSuffix(header.OriginalPath, "subdir/secret.txt") {
		t.Errorf("OriginalPath = %q, should end with subdir/secret.txt", header.OriginalPath)
	}
	if !bytes.Equal(content, plaintext) {
		t.Fatal("decrypted content mismatch")
	}
}

func TestEncryptFileNoMetadata(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "plain.txt")

	err := os.WriteFile(srcPath, []byte("no metadata"), 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	opts := &EncryptFileOptions{
		Algorithm:     AlgoXChaCha20Poly1305,
		Passphrase:    []byte("test-pass"),
		KDFMethod:     KDFArgon2id,
		EmbedMetadata: false,
	}

	encData, err := EncryptFile(srcPath, opts)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	encPath := filepath.Join(dir, "test.enc")
	err = os.WriteFile(encPath, encData, 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, header, err := DecryptFile(encPath, &DecryptFileOptions{Passphrase: []byte("test-pass")})
	if err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	if header.OriginalName != "" {
		t.Errorf("OriginalName should be empty when no metadata, got %q", header.OriginalName)
	}
	if header.OriginalPath != "" {
		t.Errorf("OriginalPath should be empty when no metadata, got %q", header.OriginalPath)
	}
}

func TestEncryptFileWrongAlgorithm(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "test.txt")
	err := os.WriteFile(srcPath, []byte("test"), 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	opts := &EncryptFileOptions{
		Algorithm:  99,
		Passphrase: []byte("pass"),
		KDFMethod:  KDFArgon2id,
	}

	_, err = EncryptFile(srcPath, opts)
	if err == nil {
		t.Fatal("expected error for invalid algorithm")
	}
}

func TestEncryptFileBytesWrongAlgorithm(t *testing.T) {
	opts := &EncryptFileOptions{
		Algorithm:  99,
		Passphrase: []byte("pass"),
		KDFMethod:  KDFArgon2id,
	}
	_, err := EncryptFileBytes([]byte("test"), opts)
	if err == nil {
		t.Fatal("expected error for invalid algorithm")
	}
}

func TestEncryptFileBytesWithEmbeddedMetadata(t *testing.T) {
	opts := &EncryptFileOptions{
		Algorithm:       AlgoXChaCha20Poly1305,
		Passphrase:      []byte("test-pass"),
		KDFMethod:       KDFArgon2id,
		EmbedMetadata:   true,
		OriginalNameHint: "document.txt",
		OriginalPathHint: "/docs/document.txt",
	}

	encData, err := EncryptFileBytes([]byte("test content"), opts)
	if err != nil {
		t.Fatalf("EncryptFileBytes failed: %v", err)
	}

	decrypted, header, err := DecryptFileBytes(encData, &DecryptFileOptions{Passphrase: []byte("test-pass")})
	if err != nil {
		t.Fatalf("DecryptFileBytes failed: %v", err)
	}

	if header.OriginalName != "document.txt" {
		t.Errorf("OriginalName = %q, want %q", header.OriginalName, "document.txt")
	}
	if header.OriginalPath != "/docs/document.txt" {
		t.Errorf("OriginalPath = %q, want %q", header.OriginalPath, "/docs/document.txt")
	}
	if string(decrypted) != "test content" {
		t.Errorf("content mismatch: got %q", string(decrypted))
	}
}

func TestEncryptFileOptionsDefaults(t *testing.T) {
	opts := &EncryptFileOptions{}
	if opts.Algorithm != 0 {
		t.Errorf("Algorithm default should be 0 (AlgoNone), got %d", opts.Algorithm)
	}
	if opts.KDFMethod != 0 {
		t.Errorf("KDFMethod default should be 0 (KDFNone), got %d", opts.KDFMethod)
	}
	if opts.Passphrase != nil {
		t.Errorf("Passphrase should be nil")
	}
}

func TestDetectAlgorithm(t *testing.T) {
	dir := t.TempDir()

	for _, algoID := range []AlgorithmID{AlgoXChaCha20Poly1305, AlgoChaCha20Poly1305, AlgoAES256GCM, AlgoSecretBox, AlgoAES256CTRHMAC} {
		t.Run(algoID.String(), func(t *testing.T) {
			filePath := filepath.Join(dir, "test.enc")
			content := []byte("detect test")
			err := os.WriteFile(filepath.Join(dir, "plain.txt"), content, 0644)
			if err != nil {
				t.Fatalf("WriteFile failed: %v", err)
			}

			opts := &EncryptFileOptions{
				Algorithm:  algoID,
				Passphrase: []byte("test"),
				KDFMethod:  KDFArgon2id,
			}

			encData, err := EncryptFile(filepath.Join(dir, "plain.txt"), opts)
			if err != nil {
				t.Fatalf("EncryptFile failed: %v", err)
			}

			err = os.WriteFile(filePath, encData, 0644)
			if err != nil {
				t.Fatalf("WriteFile failed: %v", err)
			}

			detected, err := DetectAlgorithm(filePath)
			if err != nil {
				t.Fatalf("DetectAlgorithm failed: %v", err)
			}

			if detected != algoID {
				t.Errorf("detected = %d, want %d", detected, algoID)
			}
		})
	}
}

func TestDetectAlgorithmInvalidFile(t *testing.T) {
	_, err := DetectAlgorithm("/nonexistent/file.enc")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey(AlgoAES256GCM)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}

	key, err = GenerateKey(AlgoAES256CTRHMAC)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(key) != 64 {
		t.Fatalf("key length = %d, want 64", len(key))
	}
}

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.bin")

	key := make([]byte, 32)
	rand.Read(key)
	err := os.WriteFile(keyPath, key, 0600)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loaded, err := loadKey(keyPath, 32)
	if err != nil {
		t.Fatalf("loadKey failed: %v", err)
	}

	if !bytes.Equal(key, loaded) {
		t.Fatal("loaded key doesn't match original")
	}
}

func TestLoadKeyTooShort(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "short.key")
	err := os.WriteFile(keyPath, []byte{1, 2, 3}, 0600)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err = loadKey(keyPath, 32)
	if err == nil {
		t.Fatal("expected error for too-short key file")
	}
}

func TestLoadKeyFileNotFound(t *testing.T) {
	_, err := loadKey("/nonexistent/key.bin", 32)
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestEncryptFileWithUUIDRenameAndMetadata(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	encDir := filepath.Join(dir, "enc")
	decDir := filepath.Join(dir, "dec")

	err := os.MkdirAll(srcDir, 0755)
	if err != nil {
		t.Fatalf("MkdirAll src failed: %v", err)
	}

	content := []byte("uuid rename with metadata")
	err = os.WriteFile(filepath.Join(srcDir, "mydata.txt"), content, 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	opts := &EncryptFileOptions{
		Algorithm:       AlgoXChaCha20Poly1305,
		Passphrase:      []byte("test-pass"),
		KDFMethod:       KDFArgon2id,
		UUIDRename:      true,
		EmbedMetadata:   true,
		OriginalPathHint: "mydata.txt",
	}

	encData, err := EncryptFile(filepath.Join(srcDir, "mydata.txt"), opts)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	err = os.MkdirAll(encDir, 0755)
	if err != nil {
		t.Fatalf("MkdirAll enc failed: %v", err)
	}
	uuidName := "550e8400-e29b-41d4-a716-446655440000.enc"
	err = os.WriteFile(filepath.Join(encDir, uuidName), encData, 0644)
	if err != nil {
		t.Fatalf("WriteFile enc failed: %v", err)
	}

	decrypted, header, err := DecryptFile(filepath.Join(encDir, uuidName), &DecryptFileOptions{Passphrase: []byte("test-pass")})
	if err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	if header.OriginalName != "mydata.txt" {
		t.Errorf("OriginalName = %q, want %q", header.OriginalName, "mydata.txt")
	}
	if !bytes.Equal(content, decrypted) {
		t.Fatal("decrypted content mismatch")
	}

	outPath := filepath.Join(decDir, header.OriginalName)
	err = os.MkdirAll(decDir, 0755)
	if err != nil {
		t.Fatalf("MkdirAll dec failed: %v", err)
	}
	err = os.WriteFile(outPath, decrypted, 0644)
	if err != nil {
		t.Fatalf("WriteFile dec failed: %v", err)
	}

	finalData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile dec failed: %v", err)
	}
	if !bytes.Equal(content, finalData) {
		t.Fatal("final decrypted content mismatch")
	}
}

func TestAgeEncryptDecryptRoundTrip(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("age.GenerateX25519Identity failed: %v", err)
	}

	recipientStr := identity.Recipient().String()
	identityStr := identity.String()

	plaintext := []byte("age encryption round-trip test data: X25519+ChaCha20-Poly1305")

	encOpts := &EncryptFileOptions{
		Algorithm:    AlgoAge,
		AgeRecipient: recipientStr,
	}

	encData, err := EncryptFileBytes(plaintext, encOpts)
	if err != nil {
		t.Fatalf("EncryptFileBytes age failed: %v", err)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "age-identity.txt")
	err = os.WriteFile(keyPath, []byte(identityStr), 0600)
	if err != nil {
		t.Fatalf("write identity file: %v", err)
	}

	decOpts := &DecryptFileOptions{
		KeyFile: keyPath,
	}

	decrypted, header, err := DecryptFileBytes(encData, decOpts)
	if err != nil {
		t.Fatalf("DecryptFileBytes age failed: %v", err)
	}

	if header.Algorithm != AlgoAge {
		t.Errorf("header algorithm = %d, want %d", header.Algorithm, AlgoAge)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted age content mismatch")
	}
}

func TestAgeEncryptDecryptFile(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("age.GenerateX25519Identity failed: %v", err)
	}

	recipientStr := identity.Recipient().String()
	identityStr := identity.String()

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "secret.txt")
	encPath := filepath.Join(dir, "secret.txt.enc")
	keyPath := filepath.Join(dir, "age-identity.txt")

	content := []byte("age file encryption test")
	err = os.WriteFile(srcPath, content, 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	err = os.WriteFile(keyPath, []byte(identityStr), 0600)
	if err != nil {
		t.Fatalf("write identity: %v", err)
	}

	encOpts := &EncryptFileOptions{
		Algorithm:    AlgoAge,
		AgeRecipient: recipientStr,
	}

	encData, err := EncryptFile(srcPath, encOpts)
	if err != nil {
		t.Fatalf("EncryptFile age failed: %v", err)
	}

	err = os.WriteFile(encPath, encData, 0644)
	if err != nil {
		t.Fatalf("write encrypted: %v", err)
	}

	decOpts := &DecryptFileOptions{
		KeyFile: keyPath,
	}

	plaintext, header, err := DecryptFile(encPath, decOpts)
	if err != nil {
		t.Fatalf("DecryptFile age failed: %v", err)
	}

	if header.Algorithm != AlgoAge {
		t.Errorf("header algorithm = %d, want %d", header.Algorithm, AlgoAge)
	}

	if !bytes.Equal(content, plaintext) {
		t.Fatal("decrypted age file content mismatch")
	}
}

func TestAgeEncryptNoRecipient(t *testing.T) {
	opts := &EncryptFileOptions{
		Algorithm: AlgoAge,
	}
	_, err := EncryptFileBytes([]byte("test"), opts)
	if err == nil {
		t.Fatal("expected error for missing age recipient")
	}
}

func TestAgeDecryptNoIdentity(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("age.GenerateX25519Identity failed: %v", err)
	}

	encOpts := &EncryptFileOptions{
		Algorithm:    AlgoAge,
		AgeRecipient: identity.Recipient().String(),
	}

	encData, err := EncryptFileBytes([]byte("test data"), encOpts)
	if err != nil {
		t.Fatalf("EncryptFileBytes failed: %v", err)
	}

	_, _, err = DecryptFileBytes(encData, &DecryptFileOptions{})
	if err == nil {
		t.Fatal("expected error for missing identity key file")
	}
}

func TestAgeDecryptWrongIdentity(t *testing.T) {
	identity1, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("age.GenerateX25519Identity failed: %v", err)
	}
	identity2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("age.GenerateX25519Identity failed: %v", err)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "wrong-identity.txt")
	err = os.WriteFile(keyPath, []byte(identity2.String()), 0600)
	if err != nil {
		t.Fatalf("write identity: %v", err)
	}

	encOpts := &EncryptFileOptions{
		Algorithm:    AlgoAge,
		AgeRecipient: identity1.Recipient().String(),
	}

	encData, err := EncryptFileBytes([]byte("secret"), encOpts)
	if err != nil {
		t.Fatalf("EncryptFileBytes failed: %v", err)
	}

	_, _, err = DecryptFileBytes(encData, &DecryptFileOptions{KeyFile: keyPath})
	if err == nil {
		t.Fatal("expected error for wrong identity key")
	}
}

func TestEncryptFileAgeWithEmbeddedMetadata(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("age.GenerateX25519Identity failed: %v", err)
	}

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "docs", "report.pdf")
	encPath := filepath.Join(dir, "output", "report.pdf.enc")
	keyPath := filepath.Join(dir, "identity.txt")

	err = os.MkdirAll(filepath.Dir(srcPath), 0755)
	if err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	content := []byte("age with embedded metadata")
	err = os.WriteFile(srcPath, content, 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	err = os.WriteFile(keyPath, []byte(identity.String()), 0600)
	if err != nil {
		t.Fatalf("write identity: %v", err)
	}

	opts := &EncryptFileOptions{
		Algorithm:     AlgoAge,
		AgeRecipient:  identity.Recipient().String(),
		EmbedMetadata: true,
	}

	encData, err := EncryptFile(srcPath, opts)
	if err != nil {
		t.Fatalf("EncryptFile age failed: %v", err)
	}

	err = os.MkdirAll(filepath.Dir(encPath), 0755)
	if err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	err = os.WriteFile(encPath, encData, 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	plaintext, header, err := DecryptFile(encPath, &DecryptFileOptions{KeyFile: keyPath})
	if err != nil {
		t.Fatalf("DecryptFile age failed: %v", err)
	}

	if header.OriginalName != "report.pdf" {
		t.Errorf("OriginalName = %q, want %q", header.OriginalName, "report.pdf")
	}
	if !bytes.Equal(content, plaintext) {
		t.Fatal("decrypted content mismatch")
	}
}

func TestEncryptFileAge(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "test.txt")
	err = os.WriteFile(srcPath, []byte("encrypt file age test"), 0644)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	opts := &EncryptFileOptions{
		AgeRecipient:  identity.Recipient().String(),
		EmbedMetadata: true,
	}

	encData, err := EncryptFileAge(srcPath, opts)
	if err != nil {
		t.Fatalf("EncryptFileAge: %v", err)
	}

	keyPath := filepath.Join(dir, "identity.txt")
	err = os.WriteFile(keyPath, []byte(identity.String()), 0600)
	if err != nil {
		t.Fatalf("write identity: %v", err)
	}

	decrypted, header, err := DecryptFileBytes(encData, &DecryptFileOptions{KeyFile: keyPath})
	if err != nil {
		t.Fatalf("DecryptFileBytes: %v", err)
	}

	if header.Algorithm != AlgoAge {
		t.Errorf("algorithm = %d, want %d", header.Algorithm, AlgoAge)
	}
	if string(decrypted) != "encrypt file age test" {
		t.Errorf("content mismatch: got %q", string(decrypted))
	}
	if header.OriginalName != "test.txt" {
		t.Errorf("OriginalName = %q, want %q", header.OriginalName, "test.txt")
	}
}

func TestEncryptFileAgeFileNotFound(t *testing.T) {
	_, err := EncryptFileAge("/nonexistent/file.txt", &EncryptFileOptions{
		AgeRecipient: "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsl3d9j",
	})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestHPKEEncryptDecrypt(t *testing.T) {
	kp, err := GenerateHPKEKeypair()
	if err != nil {
		t.Fatalf("GenerateHPKEKeypair: %v", err)
	}

	enc, _ := GetEncryptor(AlgoHPKE)
	plaintext := []byte("HPKE unit test")

	result, err := enc.Encrypt(plaintext, kp.PublicKey)
	if err != nil {
		t.Fatalf("HPKE Encrypt: %v", err)
	}

	decrypted, err := enc.Decrypt(result.Ciphertext, kp.PrivateSeed, result.Nonce)
	if err != nil {
		t.Fatalf("HPKE Decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("content mismatch: got %q", string(decrypted))
	}
}

func TestMLKEM768EncryptDecrypt(t *testing.T) {
	kp, err := GenerateMLKEMKeypair()
	if err != nil {
		t.Fatalf("GenerateMLKEMKeypair: %v", err)
	}

	enc, _ := GetEncryptor(AlgoMLKEM768)
	plaintext := []byte("ML-KEM-768 unit test")

	result, err := enc.Encrypt(plaintext, kp.PublicKey)
	if err != nil {
		t.Fatalf("MLKEM768 Encrypt: %v", err)
	}

	decrypted, err := enc.Decrypt(result.Ciphertext, kp.PrivateSeed, result.Nonce)
	if err != nil {
		t.Fatalf("MLKEM768 Decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("content mismatch: got %q", string(decrypted))
	}
}

func TestMLKEM1024EncryptDecrypt(t *testing.T) {
	kp, err := GenerateMLKEM1024Keypair()
	if err != nil {
		t.Fatalf("GenerateMLKEM1024Keypair: %v", err)
	}

	enc, _ := GetEncryptor(AlgoMLKEM1024)
	plaintext := []byte("ML-KEM-1024 unit test")

	result, err := enc.Encrypt(plaintext, kp.PublicKey)
	if err != nil {
		t.Fatalf("MLKEM1024 Encrypt: %v", err)
	}

	decrypted, err := enc.Decrypt(result.Ciphertext, kp.PrivateSeed, result.Nonce)
	if err != nil {
		t.Fatalf("MLKEM1024 Decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("content mismatch: got %q", string(decrypted))
	}
}

func TestHybridXWingEncryptDecrypt(t *testing.T) {
	kp, err := GenerateXWingKeypair()
	if err != nil {
		t.Fatalf("GenerateXWingKeypair: %v", err)
	}

	enc, _ := GetEncryptor(AlgoHybridXWing)
	plaintext := []byte("X-Wing unit test")

	result, err := enc.Encrypt(plaintext, kp.PublicKey)
	if err != nil {
		t.Fatalf("XWing Encrypt: %v", err)
	}

	decrypted, err := enc.Decrypt(result.Ciphertext, kp.PrivateSeed, result.Nonce)
	if err != nil {
		t.Fatalf("XWing Decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("content mismatch: got %q", string(decrypted))
	}
}

func TestPQCAlgorithmsWrongKeyFails(t *testing.T) {
	kp1, err := GenerateMLKEMKeypair()
	if err != nil {
		t.Fatalf("GenerateMLKEMKeypair: %v", err)
	}
	kp2, err := GenerateMLKEMKeypair()
	if err != nil {
		t.Fatalf("GenerateMLKEMKeypair: %v", err)
	}

	enc, _ := GetEncryptor(AlgoMLKEM768)
	plaintext := []byte("test data")

	result, err := enc.Encrypt(plaintext, kp1.PublicKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = enc.Decrypt(result.Ciphertext, kp2.PrivateSeed, result.Nonce)
	if err == nil {
		t.Error("expected error for wrong decryption key")
	}
}
