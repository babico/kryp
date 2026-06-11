package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Encryption EncryptionConfig `yaml:"encryption"`
	Storage    StorageConfig    `yaml:"storage"`
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
}

type StorageConfig struct {
	Type    string          `yaml:"type"`
	Rclone  RcloneConfig    `yaml:"rclone"`
}

type RcloneConfig struct {
	RemotePath  string `yaml:"remote_path"`
	Binary      string `yaml:"binary"`
	Incremental bool   `yaml:"incremental"`
	Args        string `yaml:"args"`
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
		Storage: StorageConfig{
			Type: "local",
			Rclone: RcloneConfig{
				RemotePath:  "",
				Binary:      "rclone",
				Incremental: true,
				Args:        "-v --progress",
			},
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
