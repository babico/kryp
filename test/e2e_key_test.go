package test

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestE2E_RawKey(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")
	keyPath := filepath.Join(dir, "key.bin")

	err := os.MkdirAll(srcDir, 0755)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)
	err = os.WriteFile(keyPath, key, 0600)
	if err != nil {
		t.Fatalf("write key: %v", err)
	}

	err = os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("raw key encryption test"), 0644)
	if err != nil {
		t.Fatalf("write data: %v", err)
	}

	out, err := runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "xchacha20-poly1305",
		"--key-file", keyPath,
	)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--key-file", keyPath,
	)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, string(out))
	}

	data, err := os.ReadFile(filepath.Join(decDir, "data.txt"))
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if string(data) != "raw key encryption test" {
		t.Errorf("content mismatch: got %q", string(data))
	}
}

func TestE2E_KeyGenAndEncrypt(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")
	keyPath := filepath.Join(dir, "secretbox.key")

	err := os.MkdirAll(srcDir, 0755)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err = os.WriteFile(filepath.Join(srcDir, "data.bin"), []byte("generated key test"), 0644)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	out, err := runCLI("genkey", "secretbox", keyPath)
	if err != nil {
		t.Fatalf("genkey failed: %v\n%s", err, string(out))
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if len(keyData) != 32 {
		t.Fatalf("key length = %d, want 32", len(keyData))
	}

	out, err = runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "secretbox",
		"--key-file", keyPath,
	)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--key-file", keyPath,
	)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, string(out))
	}

	data, err := os.ReadFile(filepath.Join(decDir, "data.bin"))
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if string(data) != "generated key test" {
		t.Errorf("content mismatch: got %q", string(data))
	}
}

func TestE2E_RawKeyAgeEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")

	err := os.MkdirAll(srcDir, 0755)
	if err != nil {
		t.Fatalf("mkdir src: %v", err)
	}

	err = os.WriteFile(filepath.Join(srcDir, "keyfile.bin"), []byte("test data for keyfile encrypt"), 0644)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	keyPath := filepath.Join(dir, "raw.key")
	key := make([]byte, 32)
	rand.Read(key)
	err = os.WriteFile(keyPath, key, 0600)
	if err != nil {
		t.Fatalf("write key: %v", err)
	}

	out, err := runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "aes-256-gcm",
		"--key-file", keyPath,
	)
	if err != nil {
		t.Fatalf("encrypt raw key failed: %v\n%s", err, string(out))
	}

	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--key-file", keyPath,
	)
	if err != nil {
		t.Fatalf("decrypt raw key failed: %v\n%s", err, string(out))
	}

	data, err := os.ReadFile(filepath.Join(decDir, "keyfile.bin"))
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if string(data) != "test data for keyfile encrypt" {
		t.Errorf("content mismatch: got %q", string(data))
	}
}

func TestCLI_UniversalKey(t *testing.T) {
	tmpDir := t.TempDir()

	data := []byte("universal key test")
	src := filepath.Join(tmpDir, "src.txt")
	if err := os.WriteFile(src, data, 0644); err != nil {
		t.Fatal(err)
	}

	uniKey := filepath.Join(tmpDir, "uni.bin")
	if _, err := runCLI("genkey", uniKey); err != nil {
		t.Fatalf("genkey failed: %v", err)
	}

	keyData, err := os.ReadFile(uniKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(keyData) != 64 {
		t.Fatalf("universal key length = %d, want 64", len(keyData))
	}

	encDir := filepath.Join(tmpDir, "enc")
	out, err := runCLI("encrypt",
		"-s", src,
		"-o", encDir,
		"--algorithm", "aes-256-gcm",
		"--key-file", uniKey,
	)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	decDir := filepath.Join(tmpDir, "dec")
	out, err = runCLI("decrypt",
		"-s", filepath.Join(encDir, "src.txt.enc"),
		"-o", decDir,
		"--key-file", uniKey,
	)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, string(out))
	}

	decData, err := os.ReadFile(filepath.Join(decDir, "src.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(decData) != string(data) {
		t.Errorf("content mismatch: got %q, want %q", string(decData), string(data))
	}
}
