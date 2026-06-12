package test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestE2E_HPKEKeypair(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "hpke.priv")

	out, err := runCLI("genkey", "hpke", keyPath)
	if err != nil {
		t.Fatalf("genkey hpke failed: %v\n%s", err, string(out))
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("private key not created")
	}
	pubPath := keyPath + ".pub"
	if _, err := os.Stat(pubPath); os.IsNotExist(err) {
		t.Errorf("public key not created")
	}
}

func TestE2E_HPKEEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "hpke.priv")
	pubPath := keyPath + ".pub"

	_, err := runCLI("genkey", "hpke", keyPath)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")

	os.MkdirAll(srcDir, 0755)
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("HPKE E2E test"), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := runCLI("encrypt", "--algorithm", "hpke", "--key-file", pubPath, "--source", srcDir, "--output", encDir)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	out, err = runCLI("decrypt", "--key-file", keyPath, "--source", encDir, "--output", decDir)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, string(out))
	}

	data, err := os.ReadFile(filepath.Join(decDir, "data.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "HPKE E2E test" {
		t.Errorf("content mismatch: got %q", string(data))
	}
}

func TestE2E_MLKEM1024Keypair(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "mlkem1024.priv")

	out, err := runCLI("genkey", "ml-kem-1024", keyPath)
	if err != nil {
		t.Fatalf("genkey ml-kem-1024 failed: %v\n%s", err, string(out))
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("private key not created")
	}
	pubPath := keyPath + ".pub"
	if _, err := os.Stat(pubPath); os.IsNotExist(err) {
		t.Errorf("public key not created")
	}
}

func TestE2E_MLKEM1024EncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "mlkem1024.priv")
	pubPath := keyPath + ".pub"

	_, err := runCLI("genkey", "ml-kem-1024", keyPath)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")

	os.MkdirAll(srcDir, 0755)
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("ML-KEM-1024 E2E test"), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := runCLI("encrypt", "--algorithm", "ml-kem-1024", "--key-file", pubPath, "--source", srcDir, "--output", encDir)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	out, err = runCLI("decrypt", "--key-file", keyPath, "--source", encDir, "--output", decDir)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, string(out))
	}

	data, err := os.ReadFile(filepath.Join(decDir, "data.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ML-KEM-1024 E2E test" {
		t.Errorf("content mismatch: got %q", string(data))
	}
}

func TestE2E_XWingEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "xwing.priv")
	pubPath := keyPath + ".pub"

	_, err := runCLI("genkey", "x-wing", keyPath)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")

	os.MkdirAll(srcDir, 0755)
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("X-Wing E2E test"), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := runCLI("encrypt", "--algorithm", "x-wing", "--key-file", pubPath, "--source", srcDir, "--output", encDir)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	out, err = runCLI("decrypt", "--key-file", keyPath, "--source", encDir, "--output", decDir)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, string(out))
	}

	data, err := os.ReadFile(filepath.Join(decDir, "data.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "X-Wing E2E test" {
		t.Errorf("content mismatch: got %q", string(data))
	}
}

func TestE2E_XWingKeypair(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "xwing.priv")

	out, err := runCLI("genkey", "x-wing", keyPath)
	if err != nil {
		t.Fatalf("genkey x-wing failed: %v\n%s", err, string(out))
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("private key not created")
	}
	pubPath := keyPath + ".pub"
	if _, err := os.Stat(pubPath); os.IsNotExist(err) {
		t.Errorf("public key not created")
	}
}

func TestE2E_ASCONEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")

	os.MkdirAll(srcDir, 0755)
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("ASCON E2E test"), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := runCLI("encrypt", "--algorithm", "ascon", "--passphrase", "test", "--source", srcDir, "--output", encDir)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	out, err = runCLI("decrypt", "--passphrase", "test", "--source", encDir, "--output", decDir)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, string(out))
	}

	data, err := os.ReadFile(filepath.Join(decDir, "data.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ASCON E2E test" {
		t.Errorf("content mismatch: got %q", string(data))
	}
}

func TestE2E_ASCONRawKeyEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")

	os.MkdirAll(srcDir, 0755)
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("ASCON raw key E2E test"), 0644); err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(dir, "ascon.key")
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}

	out, err := runCLI("encrypt", "--algorithm", "ascon", "--key-file", keyPath, "--source", srcDir, "--output", encDir)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	out, err = runCLI("decrypt", "--key-file", keyPath, "--source", encDir, "--output", decDir)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, string(out))
	}

	data, err := os.ReadFile(filepath.Join(decDir, "data.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ASCON raw key E2E test" {
		t.Errorf("content mismatch: got %q", string(data))
	}
}
