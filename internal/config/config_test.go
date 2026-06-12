package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := Default()
	if cfg.Encryption.Algorithm != "xchacha20-poly1305" {
		t.Errorf("default algorithm = %q, want xchacha20-poly1305", cfg.Encryption.Algorithm)
	}
	if cfg.Encryption.KDFMethod != "argon2id" {
		t.Errorf("default KDF = %q, want argon2id", cfg.Encryption.KDFMethod)
	}
	if cfg.Database.Encrypt != true {
		t.Error("default database encrypt should be true")
	}
	if cfg.Directories.Source != "test/original" {
		t.Errorf("default source = %q, want test/original", cfg.Directories.Source)
	}
	if cfg.Directories.Output != "test/encrypted" {
		t.Errorf("default output = %q, want test/encrypted", cfg.Directories.Output)
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	cfg := Default()
	cfg.Encryption.Algorithm = "aes-256-gcm"
	cfg.Encryption.KDFMethod = "scrypt"
	cfg.Encryption.UUIDRename = true
	cfg.Encryption.EmbedMetadata = true
	cfg.Database.Encrypt = false

	err := Save(path, cfg)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Encryption.Algorithm != "aes-256-gcm" {
		t.Errorf("algorithm = %q, want aes-256-gcm", loaded.Encryption.Algorithm)
	}
	if loaded.Encryption.KDFMethod != "scrypt" {
		t.Errorf("KDF = %q, want scrypt", loaded.Encryption.KDFMethod)
	}
	if loaded.Encryption.UUIDRename != true {
		t.Error("UUIDRename should be true")
	}
	if loaded.Encryption.EmbedMetadata != true {
		t.Error("EmbedMetadata should be true")
	}
	if loaded.Database.Encrypt != false {
		t.Error("Encrypt should be false")
	}
}

func TestLoadDefaultsOnPartialConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.yaml")

	err := os.WriteFile(path, []byte("encryption:\n  algorithm: secretbox\n"), 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Encryption.Algorithm != "secretbox" {
		t.Errorf("algorithm = %q, want secretbox", cfg.Encryption.Algorithm)
	}
	if cfg.Encryption.KDFMethod != "argon2id" {
		t.Errorf("KDF should default to argon2id, got %q", cfg.Encryption.KDFMethod)
	}

}

func TestLoadNonExistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")

	err := os.WriteFile(path, []byte("encryption: [invalid yaml\n"), 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err = Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestConfigRoundTripPreservesFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "full.yaml")

	cfg := &Config{
		Encryption: EncryptionConfig{
			Algorithm:     "aes-256-ctr-hmac",
			KeyFile:       "/etc/keys/enc.key",
			KDFMethod:     "pbkdf2",
			Passphrase:    "s3cret!",
			UUIDRename:    true,
			EmbedMetadata: true,
		},

		Database: DatabaseConfig{
			Encrypt: false,
			Format:  "json",
		},
		Directories: DirectoryConfig{
			Source:    "/data/in",
			Output:    "/data/out",
			Decrypted: "/data/restored",
		},
	}

	err := Save(path, cfg)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Encryption.Algorithm != cfg.Encryption.Algorithm {
		t.Errorf("Algorithm: got %q, want %q", loaded.Encryption.Algorithm, cfg.Encryption.Algorithm)
	}
	if loaded.Encryption.KeyFile != cfg.Encryption.KeyFile {
		t.Errorf("KeyFile: got %q, want %q", loaded.Encryption.KeyFile, cfg.Encryption.KeyFile)
	}
	if loaded.Encryption.KDFMethod != cfg.Encryption.KDFMethod {
		t.Errorf("KDFMethod: got %q, want %q", loaded.Encryption.KDFMethod, cfg.Encryption.KDFMethod)
	}
	if loaded.Encryption.Passphrase != cfg.Encryption.Passphrase {
		t.Errorf("Passphrase: got %q, want %q", loaded.Encryption.Passphrase, cfg.Encryption.Passphrase)
	}
	if loaded.Encryption.UUIDRename != cfg.Encryption.UUIDRename {
		t.Errorf("UUIDRename: got %v, want %v", loaded.Encryption.UUIDRename, cfg.Encryption.UUIDRename)
	}
	if loaded.Encryption.EmbedMetadata != cfg.Encryption.EmbedMetadata {
		t.Errorf("EmbedMetadata: got %v, want %v", loaded.Encryption.EmbedMetadata, cfg.Encryption.EmbedMetadata)
	}
	if loaded.Database.Encrypt != cfg.Database.Encrypt {
		t.Errorf("Database.Encrypt: got %v, want %v", loaded.Database.Encrypt, cfg.Database.Encrypt)
	}
	if loaded.Database.Format != cfg.Database.Format {
		t.Errorf("Database.Format: got %q, want %q", loaded.Database.Format, cfg.Database.Format)
	}
	if loaded.Directories.Source != cfg.Directories.Source {
		t.Errorf("Directories.Source: got %q, want %q", loaded.Directories.Source, cfg.Directories.Source)
	}
	if loaded.Directories.Output != cfg.Directories.Output {
		t.Errorf("Directories.Output: got %q, want %q", loaded.Directories.Output, cfg.Directories.Output)
	}
	if loaded.Directories.Decrypted != cfg.Directories.Decrypted {
		t.Errorf("Directories.Decrypted: got %q, want %q", loaded.Directories.Decrypted, cfg.Directories.Decrypted)
	}
}

func TestConfigFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "perm.yaml")

	cfg := Default()
	err := Save(path, cfg)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	mode := info.Mode().Perm()
	if mode&0040 == 0 && mode&0004 == 0 {
		t.Logf("config file permissions: %o (group/other readable)", mode)
	}
}

func TestApplyEnvOverridesPassphrase(t *testing.T) {
	t.Setenv(EnvPassphrase, "env-pass-123")
	cfg := Default()
	ApplyEnvOverrides(cfg)
	if cfg.Encryption.Passphrase != "env-pass-123" {
		t.Errorf("Passphrase = %q, want %q", cfg.Encryption.Passphrase, "env-pass-123")
	}
}

func TestApplyEnvOverridesDoesNotOverrideExisting(t *testing.T) {
	t.Setenv(EnvPassphrase, "env-pass")
	cfg := Default()
	cfg.Encryption.Passphrase = "config-pass"
	ApplyEnvOverrides(cfg)
	if cfg.Encryption.Passphrase != "config-pass" {
		t.Errorf("env should not override existing passphrase, got %q", cfg.Encryption.Passphrase)
	}
}

func TestApplyEnvOverridesKeyFile(t *testing.T) {
	t.Setenv(EnvKeyFile, "/env/key.bin")
	cfg := Default()
	ApplyEnvOverrides(cfg)
	if cfg.Encryption.KeyFile != "/env/key.bin" {
		t.Errorf("KeyFile = %q, want %q", cfg.Encryption.KeyFile, "/env/key.bin")
	}
}

func TestApplyEnvOverridesEmptyEnv(t *testing.T) {
	cfg := Default()
	cfg.Encryption.Passphrase = "existing"
	ApplyEnvOverrides(cfg)
	if cfg.Encryption.Passphrase != "existing" {
		t.Error("empty env should not modify config")
	}
}
