package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/babico/kryp/internal/config"
	"github.com/babico/kryp/internal/crypto"
)

func encryptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt files",
		Long:  `Encrypt files from source directory to output directory.`,
		RunE:  runEncrypt,
	}

	cmd.Flags().StringVarP(&algorithm, "algorithm", "a", "xchacha20-poly1305", "Encryption algorithm")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "p", "", "Encryption passphrase")
	cmd.Flags().StringVarP(&keyFile, "key-file", "k", "", "Path to key file")
	cmd.Flags().StringVarP(&kdfMethod, "kdf", "", "argon2id", "Key derivation method (argon2id, scrypt, pbkdf2)")
	cmd.Flags().BoolVarP(&uuidRename, "uuid-rename", "u", false, "Rename files to UUID and store mapping")
	cmd.Flags().StringSliceVarP(&sourceFiles, "source", "s", []string{}, "Source file(s) or directory")
	cmd.Flags().StringVarP(&filesFrom, "files-from", "", "", "Read file list from file")
	cmd.Flags().BoolVarP(&compatible, "compatible", "", false, "Compatible mode: no kryp header (interop with OpenSSL etc.)")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory")
	cmd.Flags().BoolVarP(&embedMetadata, "embed-metadata", "m", false, "Embed original filename/path in header")
	cmd.Flags().StringVarP(&ageRecipient, "age-recipient", "", "", "Age recipient (public key) for age encryption")
	cmd.Flags().Uint32VarP(&argon2Time, "argon2-time", "", 0, "Argon2id time cost (default 3)")
	cmd.Flags().Uint32VarP(&argon2Memory, "argon2-memory", "", 0, "Argon2id memory cost in KiB (default 65536)")
	cmd.Flags().Uint8VarP(&argon2Threads, "argon2-threads", "", 0, "Argon2id parallelism threads (default 4)")
	cmd.Flags().Uint32VarP(&scryptN, "scrypt-n", "", 0, "Scrypt CPU/memory cost parameter N (default 32768)")
	cmd.Flags().Uint32VarP(&scryptR, "scrypt-r", "", 0, "Scrypt block size parameter r (default 8)")
	cmd.Flags().Uint32VarP(&scryptP, "scrypt-p", "", 0, "Scrypt parallelization parameter p (default 1)")
	cmd.Flags().Uint32VarP(&pbkdf2Iter, "pbkdf2-iter", "", 0, "PBKDF2 iteration count (default 600000)")
	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "Config file")

	return cmd
}

func decryptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt files",
		Long:  `Decrypt files from encrypted directory to output directory. Auto-detects algorithm.`,
		RunE:  runDecrypt,
	}

	cmd.Flags().StringVarP(&passphrase, "passphrase", "p", "", "Decryption passphrase")
	cmd.Flags().StringVarP(&keyFile, "key-file", "k", "", "Path to key file")
	cmd.Flags().StringSliceVarP(&sourceFiles, "source", "s", []string{}, "Source file(s) or encrypted directory")
	cmd.Flags().StringVarP(&filesFrom, "files-from", "", "", "Read file list from file")
	cmd.Flags().StringVarP(&decryptDir, "output", "o", "", "Decrypted output directory")
	cmd.Flags().StringSliceVarP(&selectedFiles, "select", "", []string{}, "UUIDs or filenames to decrypt (comma-separated)")
	cmd.Flags().BoolVarP(&keepPath, "keep-path", "", false, "Recreate original directory structure from header metadata")
	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "Config file")

	return cmd
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list [encrypted-directory]",
		Short: "List encrypted files from manifest",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runList,
	}
}

func algorithmsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "algorithms",
		Short: "List supported encryption algorithms",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Supported encryption algorithms:")
			for _, id := range crypto.ListAlgorithms() {
				e, _ := crypto.GetEncryptor(id)
				fmt.Printf("  %d: %s (key size: %d bytes)\n", id, id.String(), e.KeySize())
			}
			return nil
		},
	}
}

func genkeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "genkey [algorithm] <output>",
		Short: "Generate a random key for a given algorithm",
		Long: `Generate a random key file or keypair for a given algorithm.

Modes:
  1. kryp genkey <output>                    → generate a 64-byte universal key
  2. kryp genkey <algorithm> <output>         → generate key for specific algorithm
  3. kryp genkey <algorithm> <output> --seed-file <path>  → deterministic PQC keygen
  4. kryp genkey --extract-public <key-path>  → extract public key from private key

Algorithms: xchacha20-poly1305, chacha20-poly1305, aes-256-gcm, secretbox, aes-256-ctr-hmac, age, ml-kem-768, ml-kem-1024, x-wing, hpke, ascon, aegis-128l, aegis-256, aes-256-gcm-siv, hqc-128, xoodyak, deoxys-ii, aes-256-siv, frodokem-640-shake
For age and PQC algorithms (ml-kem-768, ml-kem-1024, x-wing, hpke, hqc-128, frodokem-640-shake), generates a keypair.

Examples:
  kryp genkey keys/universal.key
  kryp genkey aes-256-gcm keys/aes.key
  kryp genkey age keys/identity.txt
  kryp genkey --format hex xchacha20-poly1305 keys/key.hex
  kryp genkey --extract-public keys/private.key`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if extractPublic {
				if len(args) != 1 {
					return errors.New("usage: kryp genkey --extract-public <private-key-path>")
				}
				kp, err := crypto.ExtractPublicKey(args[0])
				if err != nil {
					return err
				}
				pubPath := args[0] + ".pub"
				if err := os.WriteFile(pubPath, kp.PublicKey, 0644); err != nil {
					return err
				}
				fmt.Printf("[+] Public key extracted: %s (%s)\n", pubPath, kp.Algorithm)
				return nil
			}

			if len(args) == 1 {
				key := make([]byte, 64)
				_, err := rand.Read(key)
				if err != nil {
					return err
				}
				if err := os.WriteFile(args[0], key, 0600); err != nil {
					return err
				}
				fmt.Printf("[+] Universal key (64B): %s\n", args[0])
				return nil
			}

			if len(args) < 2 {
				return errors.New("usage: kryp genkey [algorithm] <output> [--seed-file <path>]")
			}

			algoName := args[0]
			outPath := args[1]

			if seedFile != "" {
				seedData, err := os.ReadFile(seedFile)
				if err != nil {
					return err
				}
				algoID, err := crypto.ParseAlgorithm(algoName)
				if err != nil {
					return err
				}
				kp, err := crypto.GenerateKeyPairFromSeed(algoID, seedData)
				if err != nil {
					return err
				}
				printKEMKeypairOutput(outPath, kp, algoName)
				return nil
			}

			algoID, err := crypto.ParseAlgorithm(algoName)
			if err != nil {
				return err
			}

			switch algoID {
			case crypto.AlgoAge:
				return generateAgeKey(outPath)
			case crypto.AlgoMLKEM768, crypto.AlgoMLKEM1024, crypto.AlgoHybridXWing, crypto.AlgoHPKE, crypto.AlgoHQC128, crypto.AlgoFrodo640SHAKE:
				kp, err := crypto.GenerateKEMKeypair(algoID)
				if err != nil {
					return err
				}
				printKEMKeypairOutput(outPath, kp, algoName)
				return nil
			}

			e, err := crypto.GetEncryptor(algoID)
			if err != nil {
				return err
			}

			key, err := crypto.GenerateKey(algoID)
			if err != nil {
				return err
			}

			if keyFormat == "raw" || keyFormat == "" {
				if err := os.WriteFile(outPath, key, 0600); err != nil {
					return err
				}
			} else if keyFormat == "hex" {
				outPath = ensureExtension(outPath, ".hex")
				if err := os.WriteFile(outPath, []byte(hex.EncodeToString(key)+"\n"), 0600); err != nil {
					return err
				}
			} else if keyFormat == "base64" {
				outPath = ensureExtension(outPath, ".b64")
				if err := os.WriteFile(outPath, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0600); err != nil {
					return err
				}
			}

			fmt.Printf("Key generated: %s\n", outPath)
			fmt.Printf("  Algorithm: %s (ID: %d)\n", algoID.String(), algoID)
			fmt.Printf("  Key size:  %d bytes\n", e.KeySize())

			return nil
		},
	}
	cmd.Flags().StringVarP(&keyFormat, "format", "f", "raw", "Output format: raw, hex, base64")
	cmd.Flags().StringVarP(&seedFile, "seed-file", "", "", "Seed file for deterministic key generation")
	cmd.Flags().BoolVarP(&extractPublic, "extract-public", "", false, "Extract public key from private key")
	return cmd
}

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init [path]",
		Short: "Initialize default config and test directories",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			basePath := "."
			if len(args) > 0 {
				basePath = args[0]
			}

			cfg := config.Default()
			cfgPath := filepath.Join(basePath, "config.yaml")
			if err := config.Save(cfgPath, cfg); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}
			fmt.Printf("Config saved: %s\n", cfgPath)

			for _, dir := range []string{"test/original", "test/encrypted", "test/decrypted"} {
				d := filepath.Join(basePath, dir)
				if err := os.MkdirAll(d, 0755); err != nil {
					return fmt.Errorf("creating directory %s: %w", dir, err)
				}
				fmt.Printf("Directory created: %s\n", d)
			}

			readme := filepath.Join(basePath, "test", "original", "README.txt")
			if _, err := os.Stat(readme); os.IsNotExist(err) {
				content := "This is a test file.\nIt will be encrypted, then decrypted.\n\nYou can put any files in test/original/ and run:\n  kryp encrypt\n"
				if err := os.WriteFile(readme, []byte(content), 0644); err != nil {
					return fmt.Errorf("writing test file: %w", err)
				}
				fmt.Printf("Test file created: %s\n", readme)
			}

			fmt.Println("\nProject initialized! Run 'kryp encrypt' to encrypt test/original/")
			return nil
		},
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Kryp version %s\n", Version)
			fmt.Printf("Module: %s\n", "github.com/babico/kryp")
			return nil
		},
	}
}

func inspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <encrypted-file>",
		Short: "Inspect encrypted file header",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}
			h, err := crypto.DecodeHeader(data)
			if err != nil {
				return fmt.Errorf("decoding header: %w", err)
			}
			fmt.Printf("File: %s\n", args[0])
			fmt.Printf("  Version:     %d\n", h.Version)
			fmt.Printf("  Algorithm:   %s (ID: %d)\n", h.Algorithm.String(), h.Algorithm)
			fmt.Printf("  KDF Method:  %s\n", h.KDFMethod.String())
			fmt.Printf("  Nonce size:  %d bytes\n", len(h.Nonce))
			fmt.Printf("  Salt:        %x\n", h.KDFSalt)
			if h.OriginalName != "" {
				fmt.Printf("  Orig Name:   %s\n", h.OriginalName)
			}
			if h.OriginalPath != "" {
				fmt.Printf("  Orig Path:   %s\n", h.OriginalPath)
			}
			fmt.Printf("  Body size:   %d bytes (encrypted)\n", len(data))
			return nil
		},
	}
}

func hashCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hash <file>",
		Short: "Compute file hash (SHA256 by default)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}
			switch hashAlgorithm {
			case "sha256":
				h := sha256.Sum256(data)
				fmt.Printf("SHA256 (%s) = %x\n", args[0], h[:])
			case "sha512":
				h := sha512.Sum512(data)
				fmt.Printf("SHA512 (%s) = %x\n", args[0], h[:])
			default:
				return fmt.Errorf("unsupported hash: %s", hashAlgorithm)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&hashAlgorithm, "algorithm", "a", "sha256", "Hash algorithm (sha256, sha512)")
	return cmd
}

func infoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show system and crypto information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Kryp — System Information")
			fmt.Println(strings.Repeat("=", 40))
			fmt.Printf("Version:   %s\n", Version)
			fmt.Printf("Go:        %s\n", runtime.Version())
			fmt.Println()
			fmt.Println("Supported Algorithms:")
			for _, id := range crypto.ListAlgorithms() {
				e, err := crypto.GetEncryptor(id)
				if err != nil {
					continue
				}
				fmt.Printf("  %s (key: %d bytes, nonce: %d bytes)\n", id.String(), e.KeySize(), e.NonceSize())
			}
			fmt.Println()
			fmt.Println("KDF Methods:")
			for _, k := range []string{"argon2id", "scrypt", "pbkdf2", "none"} {
				m, err := crypto.ParseKDF(k)
				if err != nil {
					continue
				}
				fmt.Printf("  %s\n", m.String())
			}
			return nil
		},
	}
}
