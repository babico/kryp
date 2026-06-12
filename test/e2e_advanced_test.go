package test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

	for i := range algorithms {
		subDir := filepath.Join(encDir, fmt.Sprintf("test_%d", i))
		entries, _ := os.ReadDir(subDir)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".enc") && e.Name() != "manifest.json.enc" {
				data, err := os.ReadFile(filepath.Join(subDir, e.Name()))
				if err != nil {
					t.Fatalf("read %s: %v", e.Name(), err)
				}

				if len(data) < 4 || string(data[:4]) != "ENCR" {
					t.Errorf("file %s missing magic bytes ENCR", e.Name())
				}
			}
		}
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

	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--passphrase", "keep-path-test",
		"--keep-path",
	)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, string(out))
	}

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

	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--passphrase", "select-test",
		"--select", "alpha.txt",
	)
	if err != nil {
		t.Fatalf("decrypt --select failed: %v\n%s", err, string(out))
	}

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

	out, err := runCLI("encrypt", "--config", cfgPath)
	if err != nil {
		t.Fatalf("encrypt with config failed: %v\n%s", err, string(out))
	}

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
		filepath.Join("docs", "readme.txt"):                "readme content",
		filepath.Join("images", "icon.png"):                "fake png data",
		filepath.Join("config", "backup", "cfg"):            "backup config",
		"root.txt": "root file",
	}
	for relPath, content := range files {
		err := os.WriteFile(filepath.Join(srcDir, relPath), []byte(content), 0644)
		if err != nil {
			t.Fatalf("write %s: %v", relPath, err)
		}
	}

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

	out, err = runCLI("decrypt",
		"--source", encDir,
		"--output", decDir,
		"--passphrase", "subdir-test",
		"--keep-path",
	)
	if err != nil {
		t.Fatalf("decrypt subdirs failed: %v\n%s", err, string(out))
	}

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

func TestCLI_TrainEncryptDecrypt(t *testing.T) {
	tmpDir := t.TempDir()

	files := map[string]string{
		"alpha.txt": "content alpha",
		"beta.txt":  "content beta",
		"gamma.txt": "content gamma",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	keyFile := filepath.Join(tmpDir, "key.bin")
	if _, err := runCLI("genkey", keyFile); err != nil {
		t.Fatalf("genkey failed: %v", err)
	}

	encDir := filepath.Join(tmpDir, "enc")
	outEnc, err := runCLI("encrypt",
		"-s", filepath.Join(tmpDir, "alpha.txt"),
		"-s", filepath.Join(tmpDir, "beta.txt"),
		"-s", filepath.Join(tmpDir, "gamma.txt"),
		"-o", encDir,
		"--key-file", keyFile,
	)
	if err != nil {
		t.Fatalf("encrypt train failed: %v\n%s", err, string(outEnc))
	}
	if !strings.Contains(string(outEnc), "Encrypted:") {
		t.Error("output should contain 'Encrypted:'")
	}

	for name := range files {
		if _, err := os.Stat(filepath.Join(encDir, name+".enc")); err != nil {
			t.Errorf("missing encrypted file %s: %v", name+".enc", err)
		}
	}

	decDir := filepath.Join(tmpDir, "dec")
	outDec, err := runCLI("decrypt",
		"-s", filepath.Join(encDir, "alpha.txt.enc"),
		"-s", filepath.Join(encDir, "beta.txt.enc"),
		"-s", filepath.Join(encDir, "gamma.txt.enc"),
		"-o", decDir,
		"--key-file", keyFile,
	)
	if err != nil {
		t.Fatalf("decrypt train failed: %v\n%s", err, string(outDec))
	}
	if !strings.Contains(string(outDec), "Decrypted:") {
		t.Error("output should contain 'Decrypted:'")
	}

	for name, content := range files {
		data, err := os.ReadFile(filepath.Join(decDir, name))
		if err != nil {
			t.Errorf("read decrypted %s: %v", name, err)
			continue
		}
		if string(data) != content {
			t.Errorf("decrypted %s content mismatch: got %q, want %q", name, string(data), content)
		}
	}
}

func TestCLI_FilesFrom(t *testing.T) {
	tmpDir := t.TempDir()

	files := map[string]string{"x.txt": "x", "y.txt": "y"}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	listContent := strings.Join([]string{
		filepath.Join(tmpDir, "x.txt"),
		"# this is a comment",
		"",
		filepath.Join(tmpDir, "y.txt"),
	}, "\n")
	listPath := filepath.Join(tmpDir, "list.txt")
	if err := os.WriteFile(listPath, []byte(listContent), 0644); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(tmpDir, "key.bin")
	if _, err := runCLI("genkey", keyFile); err != nil {
		t.Fatalf("genkey failed: %v", err)
	}

	encDir := filepath.Join(tmpDir, "enc")
	out, err := runCLI("encrypt",
		"--files-from", listPath,
		"-o", encDir,
		"--key-file", keyFile,
	)
	if err != nil {
		t.Fatalf("encrypt files-from failed: %v\n%s", err, string(out))
	}

	for name := range files {
		if _, err := os.Stat(filepath.Join(encDir, name+".enc")); err != nil {
			t.Errorf("missing encrypted file %s: %v", name+".enc", err)
		}
	}
}

func TestCLI_CompatibleMode(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte("compatible mode test")
	src := filepath.Join(tmpDir, "compat.txt")
	if err := os.WriteFile(src, data, 0644); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(tmpDir, "key.bin")
	if _, err := runCLI("genkey", keyFile); err != nil {
		t.Fatalf("genkey failed: %v", err)
	}

	out, err := runCLI("encrypt",
		"-s", src,
		"-o", tmpDir,
		"--algorithm", "aes-256-gcm",
		"--key-file", keyFile,
		"--compatible",
	)
	if err != nil {
		t.Fatalf("encrypt compatible failed: %v\n%s", err, string(out))
	}

	outFile := filepath.Join(tmpDir, "compat.txt.enc")
	outData, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}

	if len(outData) >= 4 && string(outData[:4]) == "ENCR" {
		t.Error("compatible mode should not have ENCR header")
	}
}
