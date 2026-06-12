package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/babico/kryp/internal/crypto"
)

func TestEnsureExtension(t *testing.T) {
	tests := []struct {
		path, ext, want string
	}{
		{"file.txt", ".txt", "file.txt"},
		{"file", ".txt", "file.txt"},
		{"file.TXT", ".txt", "file.TXT"},
		{"file.txt", ".TXT", "file.txt"},
		{"file.hex", ".hex", "file.hex"},
		{"file", ".b64", "file.b64"},
		{"path/to/file", ".enc", "path/to/file.enc"},
		{"path/to/file.enc", ".enc", "path/to/file.enc"},
	}
	for _, tt := range tests {
		got := ensureExtension(tt.path, tt.ext)
		if got != tt.want {
			t.Errorf("ensureExtension(%q, %q) = %q, want %q", tt.path, tt.ext, got, tt.want)
		}
	}
}

func TestOutputPathForFile(t *testing.T) {
	dir := t.TempDir()

	subDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	existingFile := filepath.Join(dir, "existing.out")
	if err := os.WriteFile(existingFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name                    string
		sourceFile, outputBase, defaultName, want string
	}{
		{
			name:        "existing directory",
			sourceFile:  "/src/file.txt",
			outputBase:  subDir,
			defaultName: "out.enc",
			want:        filepath.Join(subDir, "out.enc"),
		},
		{
			name:        "existing file",
			sourceFile:  "/src/file.txt",
			outputBase:  existingFile,
			defaultName: "out.enc",
			want:        existingFile,
		},
		{
			name:        "non-existent path with extension",
			sourceFile:  "/src/file.txt",
			outputBase:  filepath.Join(dir, "custom.out"),
			defaultName: "out.enc",
			want:        filepath.Join(dir, "custom.out"),
		},
		{
			name:        "non-existent path without extension -> treated as directory",
			sourceFile:  "/src/file.txt",
			outputBase:  filepath.Join(dir, "newdir"),
			defaultName: "out.enc",
			want:        filepath.Join(dir, "newdir", "out.enc"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := outputPathForFile(tt.sourceFile, tt.outputBase, tt.defaultName)
			if got != tt.want {
				t.Errorf("outputPathForFile(%q, %q, %q) = %q, want %q",
					tt.sourceFile, tt.outputBase, tt.defaultName, got, tt.want)
			}
		})
	}
}

func TestDecryptOutputPath(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "dec")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(subDir, "file.dec")
	got := decryptOutputPath("/src/file.enc", subDir, "file.dec")
	if got != want {
		t.Errorf("decryptOutputPath = %q, want %q", got, want)
	}
}

func TestReadFilesFrom(t *testing.T) {
	dir := t.TempDir()

	t.Run("normal file", func(t *testing.T) {
		content := "file1.txt\nfile2.txt\n# this is a comment\n\nfile3.txt\n"
		f := filepath.Join(dir, "list.txt")
		if err := os.WriteFile(f, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		files, err := readFilesFrom(f)
		if err != nil {
			t.Fatalf("readFilesFrom error: %v", err)
		}
		want := []string{"file1.txt", "file2.txt", "file3.txt"}
		if len(files) != len(want) {
			t.Fatalf("got %d files, want %d: %v", len(files), len(want), files)
		}
		for i := range want {
			if files[i] != want[i] {
				t.Errorf("files[%d] = %q, want %q", i, files[i], want[i])
			}
		}
	})

	t.Run("empty file", func(t *testing.T) {
		f := filepath.Join(dir, "empty.txt")
		if err := os.WriteFile(f, []byte{}, 0644); err != nil {
			t.Fatal(err)
		}
		files, err := readFilesFrom(f)
		if err != nil {
			t.Fatalf("readFilesFrom error: %v", err)
		}
		if len(files) != 0 {
			t.Errorf("expected 0 files, got %d", len(files))
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := readFilesFrom(filepath.Join(dir, "nonexistent.txt"))
		if err == nil {
			t.Error("expected error for non-existent file")
		}
	})

	t.Run("only comments and blanks", func(t *testing.T) {
		f := filepath.Join(dir, "comments.txt")
		if err := os.WriteFile(f, []byte("# comment\n\n# another\n"), 0644); err != nil {
			t.Fatal(err)
		}
		files, err := readFilesFrom(f)
		if err != nil {
			t.Fatalf("readFilesFrom error: %v", err)
		}
		if len(files) != 0 {
			t.Errorf("expected 0 files, got %d", len(files))
		}
	})
}

func TestDetectMode(t *testing.T) {
	dir := t.TempDir()

	testFile := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	testDir := filepath.Join(dir, "subdir")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	oldFilesFrom := filesFrom
	defer func() { filesFrom = oldFilesFrom }()

	t.Run("filesFrom modeTrain", func(t *testing.T) {
		listFile := filepath.Join(dir, "list.txt")
		if err := os.WriteFile(listFile, []byte("a.txt\nb.txt\n"), 0644); err != nil {
			t.Fatal(err)
		}
		filesFrom = listFile

		mode, paths, err := detectMode([]string{})
		if err != nil {
			t.Fatalf("detectMode error: %v", err)
		}
		if mode != modeTrain {
			t.Errorf("mode = %d, want modeTrain(%d)", mode, modeTrain)
		}
		if len(paths) != 2 {
			t.Errorf("got %d paths, want 2", len(paths))
		}
	})

	t.Run("multiple files modeTrain", func(t *testing.T) {
		filesFrom = ""
		mode, paths, err := detectMode([]string{"a.txt", "b.txt"})
		if err != nil {
			t.Fatalf("detectMode error: %v", err)
		}
		if mode != modeTrain {
			t.Errorf("mode = %d, want modeTrain(%d)", mode, modeTrain)
		}
		if len(paths) != 2 {
			t.Errorf("got %d paths, want 2", len(paths))
		}
	})

	t.Run("directory modeDirectory", func(t *testing.T) {
		filesFrom = ""
		mode, paths, err := detectMode([]string{testDir})
		if err != nil {
			t.Fatalf("detectMode error: %v", err)
		}
		if mode != modeDirectory {
			t.Errorf("mode = %d, want modeDirectory(%d)", mode, modeDirectory)
		}
		if len(paths) != 1 || paths[0] != testDir {
			t.Errorf("paths = %v, want [%s]", paths, testDir)
		}
	})

	t.Run("single file modeSingleFile", func(t *testing.T) {
		filesFrom = ""
		mode, paths, err := detectMode([]string{testFile})
		if err != nil {
			t.Fatalf("detectMode error: %v", err)
		}
		if mode != modeSingleFile {
			t.Errorf("mode = %d, want modeSingleFile(%d)", mode, modeSingleFile)
		}
		if len(paths) != 1 || paths[0] != testFile {
			t.Errorf("paths = %v, want [%s]", paths, testFile)
		}
	})

	t.Run("no files error", func(t *testing.T) {
		filesFrom = ""
		_, _, err := detectMode([]string{})
		if err == nil {
			t.Error("expected error for no source files")
		}
		if err != nil && !strings.Contains(err.Error(), "no source") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

func TestPrintKEMKeypairOutput(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "mlkem.priv")

	kp := &crypto.KEMKeypair{
		PrivateSeed: []byte("seed1234567890123456789012345678901"),
		PublicKey:   []byte("publickeydata"),
		Algorithm:   7,
	}

	oldFormat := keyFormat
	defer func() { keyFormat = oldFormat }()
	keyFormat = "raw"

	printKEMKeypairOutput(outPath, kp, "ml-kem-768")

	if _, err := os.Stat(outPath); os.IsNotExist(err) {
		t.Error("private key file not created")
	}
	if _, err := os.Stat(outPath + ".pub"); os.IsNotExist(err) {
		t.Error("public key file (.pub) not created")
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(kp.PrivateSeed) {
		t.Errorf("private key content mismatch:\ngot:  %x\nwant: %x", data, kp.PrivateSeed)
	}

	pubData, err := os.ReadFile(outPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if string(pubData) != string(kp.PublicKey) {
		t.Errorf("public key content mismatch:\ngot:  %x\nwant: %x", pubData, kp.PublicKey)
	}
}

func TestPrintKEMKeypairOutputHexFormat(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "hexkey.priv")

	kp := &crypto.KEMKeypair{
		PrivateSeed: []byte("seed1234567890123456789012345678901"),
		PublicKey:   []byte("pubdata"),
		Algorithm:   10,
	}

	oldFormat := keyFormat
	defer func() { keyFormat = oldFormat }()
	keyFormat = "hex"

	printKEMKeypairOutput(outPath, kp, "hpke")

	if _, err := os.Stat(outPath + ".priv.hex"); os.IsNotExist(err) {
		t.Error("hex private key file not created")
	}
	if _, err := os.Stat(outPath + ".pub.hex"); os.IsNotExist(err) {
		t.Error("hex public key file not created")
	}
}

func TestPrintKEMKeypairOutputBase64Format(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "b64key.priv")

	kp := &crypto.KEMKeypair{
		PrivateSeed: []byte("seed1234567890123456789012345678901"),
		PublicKey:   []byte("pubdata"),
		Algorithm:   9,
	}

	oldFormat := keyFormat
	defer func() { keyFormat = oldFormat }()
	keyFormat = "base64"

	printKEMKeypairOutput(outPath, kp, "x-wing")

	if _, err := os.Stat(outPath + ".priv.b64"); os.IsNotExist(err) {
		t.Error("base64 private key file not created")
	}
	if _, err := os.Stat(outPath + ".pub.b64"); os.IsNotExist(err) {
		t.Error("base64 public key file not created")
	}
}

func TestGenerateAgeKey(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "age-key.txt")

	err := generateAgeKey(outPath)
	if err != nil {
		t.Fatalf("generateAgeKey failed: %v", err)
	}

	if _, err := os.Stat(outPath); os.IsNotExist(err) {
		t.Error("identity file not created")
	}
	identityData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(identityData), "AGE-SECRET-KEY-") {
		t.Errorf("identity should start with AGE-SECRET-KEY-, got: %s", string(identityData)[:20])
	}

	recipPath := outPath + ".recipient"
	if _, err := os.Stat(recipPath); os.IsNotExist(err) {
		t.Error("recipient file not created")
	}
	recipData, err := os.ReadFile(recipPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(recipData), "age1") {
		t.Errorf("recipient should start with age1, got: %s", string(recipData)[:10])
	}
}

func TestResolveConfig(t *testing.T) {
	dir := t.TempDir()
	oldCfg := cfgFile
	defer func() { cfgFile = oldCfg }()

	cfgFile = filepath.Join(dir, ".kryp.yaml")

	cfg := resolveConfig()
	if cfg == nil {
		t.Fatal("resolveConfig returned nil")
	}
	if cfg.Encryption.Algorithm == "" {
		t.Error("config should have default algorithm")
	}
}

func TestSourceModeConstants(t *testing.T) {
	if modeSingleFile != 0 {
		t.Errorf("modeSingleFile = %d, want 0", modeSingleFile)
	}
	if modeDirectory != 1 {
		t.Errorf("modeDirectory = %d, want 1", modeDirectory)
	}
	if modeTrain != 2 {
		t.Errorf("modeTrain = %d, want 2", modeTrain)
	}
}
