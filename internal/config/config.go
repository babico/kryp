package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	EnvPassphrase = "ENCRYPT_CLI_PASSPHRASE"
	EnvKeyFile    = "ENCRYPT_CLI_KEY_FILE"
)

type Config struct {
	Encryption EncryptionConfig `yaml:"encryption"`
	Database   DatabaseConfig   `yaml:"database"`
	Directories DirectoryConfig `yaml:"directories"`
}

type EncryptionConfig struct {
	Algorithm     string `yaml:"algorithm"`
	KeyFile       string `yaml:"key_file"`
	KDFMethod     string `yaml:"kdf_method"`
	Passphrase    string `yaml:"passphrase"`
	UUIDRename    bool   `yaml:"uuid_rename"`
	EmbedMetadata bool   `yaml:"embed_metadata"`
	Argon2Time    uint32 `yaml:"argon2_time,omitempty"`
	Argon2Memory  uint32 `yaml:"argon2_memory,omitempty"`
	Argon2Threads uint8  `yaml:"argon2_threads,omitempty"`
	ScryptN       uint32 `yaml:"scrypt_n,omitempty"`
	ScryptR       uint32 `yaml:"scrypt_r,omitempty"`
	ScryptP       uint32 `yaml:"scrypt_p,omitempty"`
	PBKDF2Iter    uint32 `yaml:"pbkdf2_iter,omitempty"`
}

type DatabaseConfig struct {
	Encrypt bool   `yaml:"encrypt"`
	Format  string `yaml:"format"`
}

type DirectoryConfig struct {
	Source    string `yaml:"source"`
	Output    string `yaml:"output"`
	Decrypted string `yaml:"decrypted"`
}

func Default() *Config {
	return &Config{
		Encryption: EncryptionConfig{
			Algorithm:   "xchacha20-poly1305",
			KDFMethod:   "argon2id",
			UUIDRename:  false,
		},
		Database: DatabaseConfig{
			Encrypt: true,
			Format:  "json",
		},
		Directories: DirectoryConfig{
			Source:    "test/original",
			Output:    "test/encrypted",
			Decrypted: "test/decrypted",
		},
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg := Default()
	err = yaml.Unmarshal(data, cfg)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return cfg, nil
}

func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func ApplyEnvOverrides(cfg *Config) {
	if pass := os.Getenv(EnvPassphrase); pass != "" && cfg.Encryption.Passphrase == "" {
		cfg.Encryption.Passphrase = pass
	}
	if key := os.Getenv(EnvKeyFile); key != "" && cfg.Encryption.KeyFile == "" {
		cfg.Encryption.KeyFile = key
	}
}
