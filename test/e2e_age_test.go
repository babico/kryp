package test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2E_AgeEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")
	keyDir := filepath.Join(dir, "keys")

	err := os.MkdirAll(srcDir, 0755)
	if err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	err = os.MkdirAll(keyDir, 0755)
	if err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}

	err = os.WriteFile(filepath.Join(srcDir, "secret.txt"), []byte("age e2e test secret data"), 0644)
	if err != nil {
		t.Fatalf("write secret: %v", err)
	}
	err = os.WriteFile(filepath.Join(srcDir, "config.yml"), []byte("api_key: secret-123"), 0644)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	identityPath := filepath.Join(keyDir, "age-identity.txt")

	out, err := runCLI("genkey", "age", identityPath)
	if err != nil {
		t.Fatalf("genkey age failed: %v\n%s", err, string(out))
	}

	recipientData, err := os.ReadFile(identityPath + ".recipient")
	if err != nil {
		t.Fatalf("read recipient file: %v", err)
	}
	recipient := strings.TrimSpace(string(recipientData))

	out, err = runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "age",
		"--age-recipient", recipient,
	)
	if err != nil {
		t.Fatalf("encrypt age failed: %v\n%s", err, string(out))
	}

	encEntries, err := os.ReadDir(encDir)
	if err != nil {
		t.Fatalf("read encrypted dir: %v", err)
	}
	if len(encEntries) == 0 {
		t.Fatal("no encrypted files created")
	}

	manifestPath := filepath.Join(encDir, "manifest.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Fatal("manifest.json not found")
	}
	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--key-file", identityPath,
	)
	if err != nil {
		t.Fatalf("decrypt age failed: %v\n%s", err, string(out))
	}

	for _, name := range []string{"secret.txt", "config.yml"} {
		origData, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			t.Fatalf("read original %s: %v", name, err)
		}
		decData, err := os.ReadFile(filepath.Join(decDir, name))
		if err != nil {
			t.Fatalf("read decrypted %s: %v", name, err)
		}
		if !bytes.Equal(origData, decData) {
			t.Errorf("decrypted %s content mismatch", name)
		}
	}
}

func TestE2E_AgeEncryptDecryptWithMetadata(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")

	err := os.MkdirAll(srcDir, 0755)
	if err != nil {
		t.Fatalf("mkdir src: %v", err)
	}

	err = os.WriteFile(filepath.Join(srcDir, "report.pdf"), []byte("age with metadata"), 0644)
	if err != nil {
		t.Fatalf("write report: %v", err)
	}

	identityPath := filepath.Join(dir, "age-id.txt")

	out, err := runCLI("genkey", "age", identityPath)
	if err != nil {
		t.Fatalf("genkey age failed: %v\n%s", err, string(out))
	}

	recipientData, _ := os.ReadFile(identityPath + ".recipient")
	recipient := strings.TrimSpace(string(recipientData))

	out, err = runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "age",
		"--age-recipient", recipient,
		"--embed-metadata",
	)
	if err != nil {
		t.Fatalf("encrypt age+metadata failed: %v\n%s", err, string(out))
	}

	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--key-file", identityPath,
	)
	if err != nil {
		t.Fatalf("decrypt age+metadata failed: %v\n%s", err, string(out))
	}

	data, err := os.ReadFile(filepath.Join(decDir, "report.pdf"))
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if string(data) != "age with metadata" {
		t.Errorf("content mismatch: got %q", string(data))
	}
}

func TestE2E_AgeKeyGenOutput(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "my-age-key.txt")

	out, err := runCLI("genkey", "age", identityPath)
	if err != nil {
		t.Fatalf("genkey age failed: %v\n%s", err, string(out))
	}

	output := string(out)

	if !strings.Contains(output, "Age identity written") {
		t.Error("output should mention identity file")
	}
	if !strings.Contains(output, "Age recipient written") {
		t.Error("output should mention recipient file")
	}
	if !strings.Contains(output, "kryp encrypt") {
		t.Error("output should show encrypt example")
	}

	if _, err := os.Stat(identityPath); os.IsNotExist(err) {
		t.Error("identity file not created")
	}
	identityData, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if !strings.HasPrefix(string(identityData), "AGE-SECRET-KEY-") {
		t.Errorf("identity should start with AGE-SECRET-KEY-, got %q", string(identityData[:20]))
	}

	recipientPath := identityPath + ".recipient"
	if _, err := os.Stat(recipientPath); os.IsNotExist(err) {
		t.Error("recipient file not created")
	}
	recipientData, err := os.ReadFile(recipientPath)
	if err != nil {
		t.Fatalf("read recipient: %v", err)
	}
	if !strings.HasPrefix(string(recipientData), "age1") {
		t.Errorf("recipient should start with age1, got %q", string(recipientData[:10]))
	}
}
