package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

var cliBinary string

func TestMain(m *testing.M) {
	cliBinary = filepath.Join(os.TempDir(), "kryp-test")
	if runtime.GOOS == "windows" {
		cliBinary += ".exe"
	}

	cmd := exec.Command("go", "build", "-o", cliBinary, "../cmd/cli")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build CLI: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	os.Remove(cliBinary)
	os.Exit(code)
}

type e2eTest struct {
	name        string
	algorithm   string
	kdf         string
	passphrase  string
	uuidRename  bool
	setupFiles  map[string]string
}

func (tt *e2eTest) run(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")

	err := os.MkdirAll(srcDir, 0755)
	if err != nil {
		t.Fatalf("mkdir src: %v", err)
	}

	for name, content := range tt.setupFiles {
		fullPath := filepath.Join(srcDir, name)
		os.MkdirAll(filepath.Dir(fullPath), 0755)
		err := os.WriteFile(fullPath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	var args []string
	args = append(args, "encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", tt.algorithm,
		"--kdf", tt.kdf,
		"--passphrase", tt.passphrase,
	)
	if tt.uuidRename {
		args = append(args, "--uuid-rename")
	}

	out, err := runCLI(args...)
	if err != nil {
		t.Fatalf("encrypt failed: %v\noutput: %s", err, string(out))
	}

	encEntries, err := os.ReadDir(encDir)
	if err != nil {
		t.Fatalf("read encrypted dir: %v", err)
	}
	if len(encEntries) == 0 {
		t.Fatal("no encrypted files created")
	}

	manifestPath := filepath.Join(encDir, "manifest.json.enc")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Fatal("manifest.json.enc not found")
	}

	args = []string{"decrypt",
		"--source", encDir,
		"--output", decDir,
		"--passphrase", tt.passphrase,
	}

	out, err = runCLI(args...)
	if err != nil {
		t.Fatalf("decrypt failed: %v\noutput: %s", err, string(out))
	}

	for name, content := range tt.setupFiles {
		decPath := filepath.Join(decDir, name)
		data, err := os.ReadFile(decPath)
		if err != nil {
			t.Fatalf("read decrypted %s: %v", name, err)
		}
		if string(data) != content {
			t.Errorf("decrypted %s content mismatch:\ngot:  %q\nwant: %q", name, string(data), content)
		}
	}
}

func runCLI(args ...string) ([]byte, error) {
	cmd := exec.Command(cliBinary, args...)
	cmd.Env = append(os.Environ(), "GOCOVERDIR=")
	return cmd.CombinedOutput()
}

func TestE2E_XChaCha20_Passphrase(t *testing.T) {
	tt := &e2eTest{
		name:       "XChaCha20-Poly1305 with Argon2id",
		algorithm:  "xchacha20-poly1305",
		kdf:        "argon2id",
		passphrase: "StrongPassphrase123!",
		setupFiles: map[string]string{
			"document.txt": "This is a confidential document with sensitive information.",
			"config.json":  `{"host":"server01","port":443,"key":"supersecret"}`,
			"notes.md":     "# Meeting Notes\n\nDate: 2026-06-11\n\nAttendees: Team\n\nDecisions:\n- Release v2.0\n- Migrate to new infrastructure",
		},
	}
	tt.run(t)
}

func TestE2E_AESGCM_Passphrase(t *testing.T) {
	tt := &e2eTest{
		name:       "AES-256-GCM with scrypt",
		algorithm:  "aes-256-gcm",
		kdf:        "scrypt",
		passphrase: "AnotherStrongPass!",
		setupFiles: map[string]string{
			"financial.csv":  "date,amount,description\n2026-01-01,1500.00,Revenue\n2026-01-02,-250.00,Expense",
			"backup.sql":     "INSERT INTO users VALUES (1, 'admin', 'admin@example.com');",
		},
	}
	tt.run(t)
}

func TestE2E_ChaCha20_PBKDF2(t *testing.T) {
	tt := &e2eTest{
		name:       "ChaCha20-Poly1305 with PBKDF2",
		algorithm:  "chacha20-poly1305",
		kdf:        "pbkdf2",
		passphrase: "PassWithPBKDF2!",
		setupFiles: map[string]string{
			"secret.txt": "This message is encrypted with ChaCha20-Poly1305 and PBKDF2 key derivation.",
		},
	}
	tt.run(t)
}

func TestE2E_SecretBox_Passphrase(t *testing.T) {
	tt := &e2eTest{
		name:       "NaCl SecretBox with Argon2id",
		algorithm:  "secretbox",
		kdf:        "argon2id",
		passphrase: "NaClSecretPass!",
		setupFiles: map[string]string{
			"key.bin":     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
			"data.msg":    "XSalsa20-Poly1305 authenticated encryption",
		},
	}
	tt.run(t)
}

func TestE2E_AESCTRHMAC_Passphrase(t *testing.T) {
	tt := &e2eTest{
		name:       "AES-256-CTR+HMAC with Argon2id",
		algorithm:  "aes-256-ctr-hmac",
		kdf:        "argon2id",
		passphrase: "CTRHMACPass!",
		setupFiles: map[string]string{
			"stream.dat":  "Large file encryption with encrypt-then-MAC approach for integrity verification.",
		},
	}
	tt.run(t)
}

func TestE2E_UUIDRenameMode(t *testing.T) {
	tt := &e2eTest{
		name:       "UUID rename mode",
		algorithm:  "xchacha20-poly1305",
		kdf:        "argon2id",
		passphrase: "UUIDTestPass!",
		uuidRename: true,
		setupFiles: map[string]string{
			"private.key": "BEGIN PRIVATE KEY\nMOCK-KEY-DATA\nEND PRIVATE KEY",
			"token.txt":   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.mock-token",
		},
	}
	tt.run(t)
}

func TestE2E_WrongPassphraseFails(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")

	err := os.MkdirAll(srcDir, 0755)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	err = os.WriteFile(filepath.Join(srcDir, "secret.txt"), []byte("top secret"), 0644)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	out, err := runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "xchacha20-poly1305",
		"--passphrase", "correct-passphrase",
	)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	_, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--passphrase", "wrong-passphrase",
	)
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}
