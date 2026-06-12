package test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var cliBinary string

func TestMain(m *testing.M) {
	// Build the CLI binary
	cliBinary = filepath.Join(os.TempDir(), "kryp-test")
	if os.Getenv("GOOS") == "windows" || true {
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

	// Verify encrypted files exist
	encEntries, err := os.ReadDir(encDir)
	if err != nil {
		t.Fatalf("read encrypted dir: %v", err)
	}
	if len(encEntries) == 0 {
		t.Fatal("no encrypted files created")
	}

	// Verify manifest.json.enc exists
	manifestPath := filepath.Join(encDir, "manifest.json.enc")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Fatal("manifest.json.enc not found")
	}

	// Decrypt
	args = []string{"decrypt",
		"--source", encDir,
		"--output", decDir,
		"--passphrase", tt.passphrase,
	}

	out, err = runCLI(args...)
	if err != nil {
		t.Fatalf("decrypt failed: %v\noutput: %s", err, string(out))
	}

	// Verify decrypted files match originals
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

	// Generate a key
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

	// Encrypt with raw key
	out, err := runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "xchacha20-poly1305",
		"--key-file", keyPath,
	)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	// Decrypt with raw key
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

	// Encrypt with passphrase
	out, err := runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "xchacha20-poly1305",
		"--passphrase", "correct-passphrase",
	)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	// Try decrypt with wrong passphrase
	_, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--passphrase", "wrong-passphrase",
	)
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestE2E_MultipleAlgorithmsSameData(t *testing.T) {
	baseContent := "Same data encrypted with different algorithms"
	algorithms := []struct {
		algo string
		kdf  string
	}{
		{"xchacha20-poly1305", "argon2id"},
		{"chacha20-poly1305", "scrypt"},
		{"aes-256-gcm", "pbkdf2"},
		{"secretbox", "argon2id"},
		{"aes-256-ctr-hmac", "argon2id"},
	}

	for _, a := range algorithms {
		t.Run(a.algo, func(t *testing.T) {
			dir := t.TempDir()
			srcDir := filepath.Join(dir, "original")
			encDir := filepath.Join(dir, "encrypted")
			decDir := filepath.Join(dir, "decrypted")

			err := os.MkdirAll(srcDir, 0755)
			if err != nil {
				t.Fatalf("mkdir: %v", err)
			}

			err = os.WriteFile(filepath.Join(srcDir, "shared.txt"), []byte(baseContent), 0644)
			if err != nil {
				t.Fatalf("write: %v", err)
			}

			pass := fmt.Sprintf("pass-%s", a.algo)

			out, err := runCLI("encrypt",
				"--source", srcDir,
				"--output", encDir,
				"--algorithm", a.algo,
				"--kdf", a.kdf,
				"--passphrase", pass,
			)
			if err != nil {
				t.Fatalf("encrypt failed: %v\n%s", err, string(out))
			}

			out, err = runCLI("decrypt",
				"--source", encDir,
				"--output", decDir,
				"--passphrase", pass,
			)
			if err != nil {
				t.Fatalf("decrypt failed: %v\n%s", err, string(out))
			}

			data, err := os.ReadFile(filepath.Join(decDir, "shared.txt"))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(data) != baseContent {
				t.Errorf("content mismatch: got %q", string(data))
			}
		})
	}
}

func TestE2E_AlgorithmsList(t *testing.T) {
	out, err := runCLI("algorithms")
	if err != nil {
		t.Fatalf("algorithms command failed: %v", err)
	}

	output := string(out)
	expectedAlgos := []string{
		"XChaCha20-Poly1305",
		"ChaCha20-Poly1305",
		"AES-256-GCM",
		"SecretBox",
		"AES-256-CTR+HMAC",
		"age",
	}

	for _, algo := range expectedAlgos {
		if !strings.Contains(output, algo) {
			t.Errorf("algorithms list missing: %s", algo)
		}
	}
}

func TestE2E_DetectAlgorithm(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")

	err := os.MkdirAll(srcDir, 0755)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	err = os.WriteFile(filepath.Join(srcDir, "test.txt"), []byte("detect me"), 0644)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	algorithms := []string{"xchacha20-poly1305", "aes-256-gcm", "chacha20-poly1305", "secretbox"}
	for i, algo := range algorithms {
		subDir := filepath.Join(encDir, fmt.Sprintf("test_%d", i))
		err := os.MkdirAll(subDir, 0755)
		if err != nil {
			t.Fatalf("mkdir: %v", err)
		}

		out, err := runCLI("encrypt",
			"--source", srcDir,
			"--output", subDir,
			"--algorithm", algo,
			"--passphrase", "test-pass",
		)
		if err != nil {
			t.Fatalf("encrypt %s failed: %v\n%s", algo, err, string(out))
		}
	}

	// Detect each encrypted file
	for i := range algorithms {
		subDir := filepath.Join(encDir, fmt.Sprintf("test_%d", i))
		entries, _ := os.ReadDir(subDir)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".enc") && e.Name() != "manifest.json.enc" {
				// Read header and verify algorithm
				data, err := os.ReadFile(filepath.Join(subDir, e.Name()))
				if err != nil {
					t.Fatalf("read %s: %v", e.Name(), err)
				}

				// Verify magic bytes
				if len(data) < 4 || string(data[:4]) != "ENCR" {
					t.Errorf("file %s missing magic bytes ENCR", e.Name())
					continue
				}
			}
		}
	}
}
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

func TestE2E_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	encDir := filepath.Join(dir, "encrypted")

	err := os.MkdirAll(filepath.Join(dir, "empty"), 0755)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	out, err := runCLI("encrypt",
		"--source", filepath.Join(dir, "empty"),
		"--output", encDir,
		"--algorithm", "xchacha20-poly1305",
		"--passphrase", "test",
	)
	if err != nil {
		t.Fatalf("encrypt empty dir failed: %v\n%s", err, string(out))
	}

	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", filepath.Join(dir, "decrypted"),
		"--passphrase", "test",
	)
	if err != nil {
		t.Fatalf("decrypt empty failed: %v\n%s", err, string(out))
	}
}

func TestE2E_LargeFile(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")

	err := os.MkdirAll(srcDir, 0755)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Create a 5MB file
	largeData := make([]byte, 5*1024*1024)
	rand.Read(largeData)
	err = os.WriteFile(filepath.Join(srcDir, "large.bin"), largeData, 0644)
	if err != nil {
		t.Fatalf("write large file: %v", err)
	}

	out, err := runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "xchacha20-poly1305",
		"--passphrase", "large-file-test",
	)
	if err != nil {
		t.Fatalf("encrypt large file failed: %v\n%s", err, string(out))
	}

	// Verify encrypted file was created
	encEntries, _ := os.ReadDir(encDir)
	encFileFound := false
	for _, e := range encEntries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".enc") && e.Name() != "manifest.json.enc" {
			encFileFound = true
			info, _ := e.Info()
			if info != nil && info.Size() <= 0 {
				t.Errorf("encrypted file %s has invalid size %d", e.Name(), info.Size())
			}
		}
	}
	if !encFileFound {
		t.Fatal("no encrypted file found for large data")
	}

	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--passphrase", "large-file-test",
	)
	if err != nil {
		t.Fatalf("decrypt large file failed: %v\n%s", err, string(out))
	}

	decData, err := os.ReadFile(filepath.Join(decDir, "large.bin"))
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}

	if !bytes.Equal(largeData, decData) {
		t.Fatal("decrypted large file content mismatch")
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

	// genkey command
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

	// Encrypt with generated key
	out, err = runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "secretbox",
		"--key-file", keyPath,
	)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	// Decrypt with generated key
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

func TestE2E_InitCommand(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI("init", dir)
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, string(out))
	}

	expectedFiles := []string{
		filepath.Join(dir, "config.yaml"),
		filepath.Join(dir, "test", "original"),
		filepath.Join(dir, "test", "encrypted"),
		filepath.Join(dir, "test", "decrypted"),
	}
	for _, path := range expectedFiles {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("init did not create: %s", path)
		}
	}
}

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

	// Generate age key pair
	out, err := runCLI("genkey", "age", identityPath)
	if err != nil {
		t.Fatalf("genkey age failed: %v\n%s", err, string(out))
	}

	// Read recipient from the .recipient file
	recipientData, err := os.ReadFile(identityPath + ".recipient")
	if err != nil {
		t.Fatalf("read recipient file: %v", err)
	}
	recipient := strings.TrimSpace(string(recipientData))

	// Encrypt with age
	out, err = runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "age",
		"--age-recipient", recipient,
	)
	if err != nil {
		t.Fatalf("encrypt age failed: %v\n%s", err, string(out))
	}

	// Verify encrypted files exist
	encEntries, err := os.ReadDir(encDir)
	if err != nil {
		t.Fatalf("read encrypted dir: %v", err)
	}
	if len(encEntries) == 0 {
		t.Fatal("no encrypted files created")
	}

	// Verify manifest exists (plain JSON for age)
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

	// Verify decrypted files match originals
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

	// Encrypt with age + embedded metadata
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

	// Decrypt with age identity
	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--key-file", identityPath,
	)
	if err != nil {
		t.Fatalf("decrypt age+metadata failed: %v\n%s", err, string(out))
	}

	// Verify decrypted content
	data, err := os.ReadFile(filepath.Join(decDir, "report.pdf"))
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if string(data) != "age with metadata" {
		t.Errorf("content mismatch: got %q", string(data))
	}
}

func TestE2E_EmbedMetadataKeepPath(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "source")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")

	err := os.MkdirAll(filepath.Join(srcDir, "subdir1", "nested"), 0755)
	if err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}

	err = os.WriteFile(filepath.Join(srcDir, "subdir1", "nested", "deep.txt"), []byte("deeply nested file"), 0644)
	if err != nil {
		t.Fatalf("write deep.txt: %v", err)
	}

	err = os.WriteFile(filepath.Join(srcDir, "root.txt"), []byte("root level file"), 0644)
	if err != nil {
		t.Fatalf("write root.txt: %v", err)
	}

	// Encrypt with embed-metadata
	out, err := runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "xchacha20-poly1305",
		"--passphrase", "keep-path-test",
		"--embed-metadata",
	)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	// Decrypt with --keep-path
	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--passphrase", "keep-path-test",
		"--keep-path",
	)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, string(out))
	}

	// Verify directory structure is recreated
	expected := map[string]string{
		filepath.Join("subdir1", "nested", "deep.txt"): "deeply nested file",
		"root.txt": "root level file",
	}
	for relPath, content := range expected {
		fullPath := filepath.Join(decDir, relPath)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("read %s: %v", relPath, err)
			continue
		}
		if string(data) != content {
			t.Errorf("%s content mismatch: got %q", relPath, string(data))
		}
	}
}

func TestE2E_SelectPartialDecrypt(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "original")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")

	err := os.MkdirAll(srcDir, 0755)
	if err != nil {
		t.Fatalf("mkdir src: %v", err)
	}

	files := map[string]string{
		"alpha.txt":   "alpha content",
		"beta.txt":    "beta content",
		"gamma.txt":   "gamma content",
	}
	for name, content := range files {
		err := os.WriteFile(filepath.Join(srcDir, name), []byte(content), 0644)
		if err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	out, err := runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "xchacha20-poly1305",
		"--passphrase", "select-test",
		"--uuid-rename",
	)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, string(out))
	}

	// Decrypt with --select filtering by filename
	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--passphrase", "select-test",
		"--select", "alpha.txt",
	)
	if err != nil {
		t.Fatalf("decrypt --select failed: %v\n%s", err, string(out))
	}

	// Verify only alpha.txt was decrypted
	if _, err := os.Stat(filepath.Join(decDir, "alpha.txt")); os.IsNotExist(err) {
		t.Error("alpha.txt was not decrypted")
	}
	if _, err := os.Stat(filepath.Join(decDir, "beta.txt")); !os.IsNotExist(err) {
		t.Error("beta.txt should NOT have been decrypted")
	}
	if _, err := os.Stat(filepath.Join(decDir, "gamma.txt")); !os.IsNotExist(err) {
		t.Error("gamma.txt should NOT have been decrypted")
	}

	data, err := os.ReadFile(filepath.Join(decDir, "alpha.txt"))
	if err != nil {
		t.Fatalf("read alpha.txt: %v", err)
	}
	if string(data) != "alpha content" {
		t.Errorf("alpha.txt content: got %q", string(data))
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

	// Verify output contains instructions
	if !strings.Contains(output, "Age identity written") {
		t.Error("output should mention identity file")
	}
	if !strings.Contains(output, "Age recipient written") {
		t.Error("output should mention recipient file")
	}
	if !strings.Contains(output, "kryp encrypt") {
		t.Error("output should show encrypt example")
	}

	// Verify identity file exists
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

	// Verify recipient file exists
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

func TestE2E_GenkeyAllAlgorithms(t *testing.T) {
	dir := t.TempDir()

	algorithms := []string{
		"xchacha20-poly1305",
		"chacha20-poly1305",
		"aes-256-gcm",
		"secretbox",
		"aes-256-ctr-hmac",
	}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			keyPath := filepath.Join(dir, algo+".key")
			out, err := runCLI("genkey", algo, keyPath)
			if err != nil {
				t.Fatalf("genkey %s failed: %v\n%s", algo, err, string(out))
			}
			if _, err := os.Stat(keyPath); os.IsNotExist(err) {
				t.Errorf("key file not created for %s", algo)
			}
		})
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

	// Encrypt with raw key
	out, err := runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "aes-256-gcm",
		"--key-file", keyPath,
	)
	if err != nil {
		t.Fatalf("encrypt raw key failed: %v\n%s", err, string(out))
	}

	// Decrypt with same raw key
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

func TestE2E_EncryptDecryptWithConfigFile(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "data")
	encDir := filepath.Join(dir, "encrypted")
	decDir := filepath.Join(dir, "decrypted")
	cfgPath := filepath.Join(dir, "config.yaml")

	err := os.MkdirAll(srcDir, 0755)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	err = os.WriteFile(filepath.Join(srcDir, "test.txt"), []byte("config test"), 0644)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Write config
	cfgContent := fmt.Sprintf(`encryption:
  algorithm: aes-256-gcm
  kdf_method: pbkdf2
  passphrase: config-pass
  uuid_rename: false
  embed_metadata: false
directories:
  source: %s
  output: %s
  decrypted: %s
`, strings.ReplaceAll(srcDir, "\\", "\\\\"),
		strings.ReplaceAll(encDir, "\\", "\\\\"),
		strings.ReplaceAll(decDir, "\\", "\\\\"))

	err = os.WriteFile(cfgPath, []byte(cfgContent), 0644)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Encrypt using config
	out, err := runCLI("encrypt", "--config", cfgPath)
	if err != nil {
		t.Fatalf("encrypt with config failed: %v\n%s", err, string(out))
	}

	// Decrypt using config with passphrase override
	out, err = runCLI("decrypt", "--config", cfgPath, "--passphrase", "config-pass")
	if err != nil {
		t.Fatalf("decrypt with config failed: %v\n%s", err, string(out))
	}

	data, err := os.ReadFile(filepath.Join(decDir, "test.txt"))
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if string(data) != "config test" {
		t.Errorf("content mismatch: got %q", string(data))
	}
}

func TestE2E_MultipleFilesSubdirectories(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	encDir := filepath.Join(dir, "enc")
	decDir := filepath.Join(dir, "dec")

	dirs := []string{"docs", "images", "config/backup"}
	for _, d := range dirs {
		err := os.MkdirAll(filepath.Join(srcDir, d), 0755)
		if err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	files := map[string]string{
		filepath.Join("docs", "readme.txt"):       "readme content",
		filepath.Join("images", "icon.png"):       "fake png data",
		filepath.Join("config", "backup", "cfg"): "backup config",
		"root.txt": "root file",
	}
	for relPath, content := range files {
		err := os.WriteFile(filepath.Join(srcDir, relPath), []byte(content), 0644)
		if err != nil {
			t.Fatalf("write %s: %v", relPath, err)
		}
	}

	// Encrypt recursively
	out, err := runCLI("encrypt",
		"--source", srcDir,
		"--output", encDir,
		"--algorithm", "chacha20-poly1305",
		"--passphrase", "subdir-test",
		"--embed-metadata",
	)
	if err != nil {
		t.Fatalf("encrypt subdirs failed: %v\n%s", err, string(out))
	}

	// Decrypt with keep-path
	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--passphrase", "subdir-test",
		"--keep-path",
	)
	if err != nil {
		t.Fatalf("decrypt subdirs failed: %v\n%s", err, string(out))
	}

	// Verify all files decrypted with correct structure
	for relPath, content := range files {
		data, err := os.ReadFile(filepath.Join(decDir, relPath))
		if err != nil {
			t.Errorf("read %s: %v", relPath, err)
			continue
		}
		if string(data) != content {
			t.Errorf("%s content mismatch: got %q", relPath, string(data))
		}
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


