package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/babico/data-encrypter-decrypter/internal/config"
	"github.com/babico/data-encrypter-decrypter/internal/crypto"
	"github.com/babico/data-encrypter-decrypter/internal/db"
	"github.com/babico/data-encrypter-decrypter/internal/store"
)

var (
	cfgFile       string
	algorithm     string
	passphrase    string
	keyFile       string
	kdfMethod     string
	uuidRename    bool
	embedMetadata bool
	keepPath      bool
	ageRecipient  string
	sourceDir     string
	outputDir     string
	decryptDir    string
	upload         bool
	rcloneTarget  string
	selectedFiles  []string
	keyFormat     string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "encrypt-cli",
		Short: "Encrypt/decrypt data for secure cloud storage",
		Long:  `A powerful encryption tool for cloud storage with multiple algorithms, UUID renaming, and rclone integration.`,
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path")

	rootCmd.AddCommand(encryptCmd())
	rootCmd.AddCommand(decryptCmd())
	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(algorithmsCmd())
	rootCmd.AddCommand(genkeyCmd())
	rootCmd.AddCommand(initCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

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
	cmd.Flags().StringVarP(&sourceDir, "source", "s", "", "Source directory")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory")
	cmd.Flags().BoolVarP(&upload, "upload", "", false, "Upload to cloud after encryption")
	cmd.Flags().StringVarP(&rcloneTarget, "rclone-target", "r", "", "Rclone remote:path target")
	cmd.Flags().BoolVarP(&embedMetadata, "embed-metadata", "m", false, "Embed original filename/path in header")
	cmd.Flags().StringVarP(&ageRecipient, "age-recipient", "", "", "Age recipient (public key) for age encryption")
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
	cmd.Flags().StringVarP(&sourceDir, "source", "s", "", "Source (encrypted) directory")
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
		Use:   "genkey [algorithm] [output-file]",
		Short: "Generate a random key for a given algorithm",
		Long: `Generate a random key file or keypair for a given algorithm.

Algorithms: xchacha20-poly1305, chacha20-poly1305, aes-256-gcm, secretbox, aes-256-ctr-hmac, age, ml-kem-768, ml-kem-1024, x-wing, hpke, ascon
For age and PQC algorithms (ml-kem-768, ml-kem-1024, x-wing, hpke), generates a keypair.

Examples:
  encrypt-cli genkey aes-256-gcm keys/aes.key
  encrypt-cli genkey age keys/identity.txt
  encrypt-cli genkey --format hex xchacha20-poly1305 keys/key.hex`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			algoName := args[0]
			outPath := args[1]

			algoID, err := crypto.ParseAlgorithm(algoName)
			if err != nil {
				return err
			}

			switch algoID {
			case crypto.AlgoAge:
				return generateAgeKey(outPath)
			case crypto.AlgoMLKEM768:
				kp, err := crypto.GenerateMLKEMKeypair()
				if err != nil {
					return err
				}
				printKEMKeypairOutput(outPath, kp, "ml-kem-768")
				return nil
			case crypto.AlgoMLKEM1024:
				kp, err := crypto.GenerateMLKEM1024Keypair()
				if err != nil {
					return err
				}
				printKEMKeypairOutput(outPath, kp, "ml-kem-1024")
				return nil
			case crypto.AlgoHybridXWing:
				kp, err := crypto.GenerateXWingKeypair()
				if err != nil {
					return err
				}
				printKEMKeypairOutput(outPath, kp, "x-wing")
				return nil
			case crypto.AlgoHPKE:
				kp, err := crypto.GenerateHPKEKeypair()
				if err != nil {
					return err
				}
				printKEMKeypairOutput(outPath, kp, "hpke")
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
	return cmd
}

func ensureExtension(path, ext string) string {
	if strings.HasSuffix(strings.ToLower(path), strings.ToLower(ext)) {
		return path
	}
	return path + ext
}

func printKEMKeypairOutput(outPath string, kp *crypto.KEMKeypair, algoName string) {
	pubPath := outPath + ".pub"
	if err := os.WriteFile(outPath, kp.PrivateSeed, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing private key: %v\n", err)
		return
	}
	if err := os.WriteFile(pubPath, kp.PublicKey, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing public key: %v\n", err)
		return
	}

	if keyFormat == "hex" {
		hexPriv := outPath + ".priv.hex"
		hexPub := pubPath + ".hex"
		os.WriteFile(hexPriv, []byte(fmt.Sprintf("%x", kp.PrivateSeed)+"\n"), 0600)
		os.WriteFile(hexPub, []byte(fmt.Sprintf("%x", kp.PublicKey)+"\n"), 0644)
	} else if keyFormat == "base64" {
		b64Priv := outPath + ".priv.b64"
		b64Pub := pubPath + ".b64"
		os.WriteFile(b64Priv, []byte(base64.StdEncoding.EncodeToString(kp.PrivateSeed)+"\n"), 0600)
		os.WriteFile(b64Pub, []byte(base64.StdEncoding.EncodeToString(kp.PublicKey)+"\n"), 0644)
	}

	algoUpper := strings.ToUpper(algoName[:1]) + algoName[1:]
	fmt.Printf("%s keypair generated:\n", algoUpper)
	fmt.Printf("  Private key (seed): %s  (%d bytes)\n", outPath, len(kp.PrivateSeed))
	fmt.Printf("  Public key:          %s  (%d bytes)\n", pubPath, len(kp.PublicKey))
	fmt.Printf("\nEncrypt:\n")
	fmt.Printf("  encrypt-cli encrypt --algorithm %s --key-file %s ...\n", algoName, pubPath)
	fmt.Printf("Decrypt:\n")
	fmt.Printf("  encrypt-cli decrypt --key-file %s ...\n", outPath)
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
				content := "This is a test file.\nIt will be encrypted, then decrypted.\n\nYou can put any files in test/original/ and run:\n  encrypt-cli encrypt\n"
				if err := os.WriteFile(readme, []byte(content), 0644); err != nil {
					return fmt.Errorf("writing test file: %w", err)
				}
				fmt.Printf("Test file created: %s\n", readme)
			}

			fmt.Println("\nProject initialized! Run 'encrypt-cli encrypt' to encrypt test/original/")
			return nil
		},
	}
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	cfg := resolveConfig()

	if sourceDir == "" {
		sourceDir = cfg.Directories.Source
	}
	if outputDir == "" {
		outputDir = cfg.Directories.Output
	}
	if v, _ := cmd.Flags().GetString("algorithm"); v == "xchacha20-poly1305" && cfg.Encryption.Algorithm != "" {
		algorithm = cfg.Encryption.Algorithm
	}
	if passphrase == "" && cfg.Encryption.Passphrase != "" {
		passphrase = cfg.Encryption.Passphrase
	}
	if keyFile == "" && cfg.Encryption.KeyFile != "" {
		keyFile = cfg.Encryption.KeyFile
	}
	if !uuidRename && cfg.Encryption.UUIDRename {
		uuidRename = cfg.Encryption.UUIDRename
	}
	if !embedMetadata && cfg.Encryption.EmbedMetadata {
		embedMetadata = cfg.Encryption.EmbedMetadata
	}
	if v, _ := cmd.Flags().GetString("kdf"); v == "argon2id" && cfg.Encryption.KDFMethod != "" {
		kdfMethod = cfg.Encryption.KDFMethod
	}
	if rcloneTarget == "" && cfg.Storage.Rclone.RemotePath != "" {
		rcloneTarget = cfg.Storage.Rclone.RemotePath
	}

	algoID, err := crypto.ParseAlgorithm(algorithm)
	if err != nil {
		return err
	}

	kdf, err := crypto.ParseKDF(kdfMethod)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	manifest := db.NewManifest()
	encryptedCount := 0

	err = filepath.WalkDir(sourceDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(sourceDir, path)
		fmt.Printf("[+] Encrypting: %s\n", relPath)

		encOpts := &crypto.EncryptFileOptions{
			Algorithm:      algoID,
			Passphrase:     []byte(passphrase),
			KeyFile:        keyFile,
			KDFMethod:      kdf,
			UUIDRename:     uuidRename,
			EmbedMetadata:  embedMetadata,
			AgeRecipient:   ageRecipient,
			OriginalPathHint: relPath,
		}

		encData, err := crypto.EncryptFile(path, encOpts)
		if err != nil {
			return fmt.Errorf("encrypting %s: %w", relPath, err)
		}

		info, _ := d.Info()
		var size int64
		if info != nil {
			size = info.Size()
		}

		fe := manifest.AddFile(
			relPath,
			d.Name(),
			size,
			int64(len(encData)),
			algoID.String(),
		)

		var outName string
		if uuidRename {
			outName = fe.UUID + ".enc"
		} else {
			outName = relPath + ".enc"
		}

		outPath := filepath.Join(outputDir, outName)
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return fmt.Errorf("creating output dir: %w", err)
		}
		if err := os.WriteFile(outPath, encData, 0644); err != nil {
			return fmt.Errorf("writing encrypted file: %w", err)
		}

		encryptedCount++
		return nil
	})
	if err != nil {
		return err
	}

	fmt.Printf("\nEncrypted %d files to %s\n", encryptedCount, outputDir)

	// Save manifest
	manifestPath := filepath.Join(outputDir, "manifest.json")
	encryptManifest := cfg.Database.Encrypt && algoID != crypto.AlgoAge
	if encryptManifest {
		manifestPath = filepath.Join(outputDir, "manifest.json.enc")
		manifestData, err := manifest.Serialize()
		if err != nil {
			return fmt.Errorf("serializing manifest: %w", err)
		}
		encOpts := &crypto.EncryptFileOptions{
			Algorithm:  algoID,
			Passphrase: []byte(passphrase),
			KeyFile:    keyFile,
			KDFMethod:  kdf,
		}
		encManifest, err := crypto.EncryptFileBytes(manifestData, encOpts)
		if err != nil {
			return fmt.Errorf("encrypting manifest: %w", err)
		}
		if err := os.WriteFile(manifestPath, encManifest, 0644); err != nil {
			return fmt.Errorf("writing encrypted manifest: %w", err)
		}
		fmt.Printf("Encrypted manifest saved: %s\n", manifestPath)
	} else {
		if err := db.SaveManifest(manifestPath, manifest); err != nil {
			return fmt.Errorf("saving manifest: %w", err)
		}
		fmt.Printf("Manifest saved: %s\n", manifestPath)
	}

	if rcloneTarget != "" || upload {
		target := rcloneTarget
		if target == "" && cfg.Storage.Rclone.RemotePath != "" {
			target = cfg.Storage.Rclone.RemotePath
		}
		if target != "" {
			rcloneBin := cfg.Storage.Rclone.Binary
			uploader := store.NewRcloneUploader(rcloneBin, target, cfg.Storage.Rclone.Incremental, cfg.Storage.Rclone.Args)
			if err := uploader.Upload(outputDir); err != nil {
				return fmt.Errorf("rclone upload failed: %w", err)
			}
			fmt.Printf("Uploaded to %s\n", target)
		}
	}

	return nil
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	cfg := resolveConfig()

	var decryptErr error

	if sourceDir == "" {
		sourceDir = cfg.Directories.Output
	}
	if decryptDir == "" {
		decryptDir = cfg.Directories.Decrypted
	}

	if err := os.MkdirAll(decryptDir, 0755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	// Check for manifest
	manifestPath := filepath.Join(sourceDir, "manifest.json.enc")
	plainManifestPath := filepath.Join(sourceDir, "manifest.json")

	var manifest *db.Manifest

	if _, err := os.Stat(manifestPath); err == nil {
		// Encrypted manifest
		manifestData, err := os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("reading manifest: %w", err)
		}

		// Need to figure out algorithm from first file or from manifest header
		// Try decrypting with given passphrase/key
		decResult, _, err := crypto.DecryptFileBytes(manifestData, &crypto.DecryptFileOptions{
			Passphrase: []byte(passphrase),
			KeyFile:    keyFile,
		})
		if err != nil {
			return fmt.Errorf("decrypting manifest (wrong passphrase/key?): %w", err)
		}

		manifest, err = db.DeserializeManifest(decResult)
		if err != nil {
			return fmt.Errorf("parsing manifest: %w", err)
		}
		fmt.Printf("Loaded encrypted manifest with %d files\n", manifest.Count())
	} else if _, err := os.Stat(plainManifestPath); err == nil {
		manifest, err = db.LoadManifest(plainManifestPath)
		if err != nil {
			return fmt.Errorf("loading manifest: %w", err)
		}
		fmt.Printf("Loaded manifest with %d files\n", manifest.Count())
	} else {
		fmt.Println("No manifest found. Attempting to decrypt all .enc files by filename pattern.")
	}

	var filesToDecrypt []*db.FileEntry

	if manifest != nil {
		allFiles := manifest.ListFiles()
		if len(selectedFiles) > 0 && selectedFiles[0] != "" {
			selectSet := make(map[string]bool)
			for _, s := range selectedFiles {
				selectSet[strings.TrimSpace(s)] = true
			}
			for _, f := range allFiles {
				if selectSet[f.UUID] || selectSet[f.OriginalName] || selectSet[f.OriginalPath] {
					filesToDecrypt = append(filesToDecrypt, f)
				}
			}
			if len(filesToDecrypt) == 0 {
				fmt.Println("No matching files found. Available files:")
				for _, f := range allFiles {
					fmt.Printf("  %s → %s\n", f.UUID[:8], f.OriginalName)
				}
				return nil
			}
		} else {
			filesToDecrypt = allFiles
		}
		fmt.Printf("Selected %d files to decrypt\n", len(filesToDecrypt))
	} else {
		// No manifest, walk recursively to find .enc files
		decryptErr = filepath.WalkDir(sourceDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".enc") {
				return nil
			}
			relPath, _ := filepath.Rel(sourceDir, path)
			filesToDecrypt = append(filesToDecrypt, &db.FileEntry{
				UUID:         relPath,
				OriginalName: strings.TrimSuffix(d.Name(), ".enc"),
			})
			return nil
		})
		if decryptErr != nil {
			return fmt.Errorf("walking source dir: %w", decryptErr)
		}
	}

	resolveOutPath := func(outDir, origName, origPath string) string {
		name := origName
		if name == "" {
			name = origPath
		}
		if name == "" {
			name = "decrypted"
		}
		if keepPath && origPath != "" {
			rel := origPath
			clean := filepath.Clean(rel)
			if clean != "." {
				return filepath.Join(outDir, clean)
			}
		}
		return filepath.Join(outDir, name)
	}

	decryptedCount := 0

	if manifest != nil {
		for _, f := range filesToDecrypt {
			encName := f.UUID + ".enc"
			encPath := filepath.Join(sourceDir, encName)

			if _, err := os.Stat(encPath); os.IsNotExist(err) {
				encPath = filepath.Join(sourceDir, f.OriginalName+".enc")
				if _, err := os.Stat(encPath); os.IsNotExist(err) {
					encPath = filepath.Join(sourceDir, f.OriginalPath+".enc")
					if _, err := os.Stat(encPath); os.IsNotExist(err) {
						fmt.Printf("[-] Skipping %s: encrypted file not found\n", f.OriginalName)
						continue
					}
				}
			}

			fmt.Printf("[+] Decrypting: %s\n", f.OriginalName)

			plaintext, header, err := crypto.DecryptFile(encPath, &crypto.DecryptFileOptions{
				Passphrase: []byte(passphrase),
				KeyFile:    keyFile,
			})
			if err != nil {
				return fmt.Errorf("decrypting %s: %w", f.OriginalName, err)
			}

			outName := f.OriginalName
			if header.OriginalName != "" {
				outName = header.OriginalName
			}
			origPath := header.OriginalPath
			outPath := resolveOutPath(decryptDir, outName, origPath)

			outDir := filepath.Dir(outPath)
			if err := os.MkdirAll(outDir, 0755); err != nil {
				return fmt.Errorf("creating output dir %s: %w", outDir, err)
			}
			if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
				return fmt.Errorf("writing decrypted file: %w", err)
			}
			hash := sha256.Sum256(plaintext)
			fmt.Printf("  SHA256: %x\n", hash[:])
			decryptedCount++
		}
	} else {
		for _, f := range filesToDecrypt {
			encPath := filepath.Join(sourceDir, f.UUID)
			fmt.Printf("[+] Decrypting: %s\n", f.UUID)

			plaintext, header, err := crypto.DecryptFile(encPath, &crypto.DecryptFileOptions{
				Passphrase: []byte(passphrase),
				KeyFile:    keyFile,
			})
			if err != nil {
				return fmt.Errorf("decrypting %s: %w", f.UUID, err)
			}

			outName := f.OriginalName
			if header.OriginalName != "" {
				outName = header.OriginalName
			}
			origPath := header.OriginalPath
			outPath := resolveOutPath(decryptDir, outName, origPath)

			outDir := filepath.Dir(outPath)
			if err := os.MkdirAll(outDir, 0755); err != nil {
				return fmt.Errorf("creating output dir %s: %w", outDir, err)
			}
			if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
				return fmt.Errorf("writing decrypted file: %w", err)
			}
			hash := sha256.Sum256(plaintext)
			fmt.Printf("  SHA256: %x\n", hash[:])
			decryptedCount++
		}
	}

	fmt.Printf("\nDecrypted %d files to %s\n", decryptedCount, decryptDir)
	return nil
}

func runList(cmd *cobra.Command, args []string) error {
	dir := "test/encrypted"
	if len(args) > 0 {
		dir = args[0]
	}

	manifestPath := filepath.Join(dir, "manifest.json.enc")
	plainPath := filepath.Join(dir, "manifest.json")

	var manifest *db.Manifest

	if _, err := os.Stat(manifestPath); err == nil {
		fmt.Println("Encrypted manifest found. Decrypt it first or use unencrypted manifest.")
		fmt.Printf("  %s\n", manifestPath)
		return nil
	}

	if _, err := os.Stat(plainPath); err == nil {
		manifest, err = db.LoadManifest(plainPath)
		if err != nil {
			return err
		}
	} else {
		fmt.Printf("No manifest found. Encrypted files in %s:\n", dir)
		filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".enc") {
				return nil
			}
			relPath, _ := filepath.Rel(dir, path)
			algo, _ := crypto.DetectAlgorithm(path)
			fmt.Printf("  %s (algorithm: %s)\n", relPath, algo.String())
			return nil
		})
		return nil
	}

	fmt.Printf("Manifest: %d files\n", manifest.Count())
	fmt.Printf("%-36s %-30s %-10s %s\n", "UUID", "Original Name", "Size", "Algorithm")
	fmt.Println(strings.Repeat("-", 100))
	for _, f := range manifest.ListFiles() {
		fmt.Printf("%-36s %-30s %-10d %s\n", f.UUID[:8], f.OriginalName, f.Size, f.Algorithm)
	}
	return nil
}

func generateAgeKey(outPath string) error {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generating age identity: %w", err)
	}
	identityData := []byte(identity.String())
	if err := os.WriteFile(outPath, identityData, 0600); err != nil {
		return fmt.Errorf("writing identity file: %w", err)
	}
	recipientPath := outPath + ".recipient"
	recipientData := []byte(identity.Recipient().String())
	if err := os.WriteFile(recipientPath, recipientData, 0644); err != nil {
		return fmt.Errorf("writing recipient file: %w", err)
	}
	fmt.Printf("Age identity written to:  %s\n", outPath)
	fmt.Printf("Age recipient written to: %s\n", recipientPath)
	fmt.Println()
	fmt.Println("Encrypt:")
	fmt.Printf("  encrypt-cli encrypt --algorithm age --age-recipient \"%s\" ...\n", identity.Recipient().String())
	fmt.Println("Decrypt:")
	fmt.Printf("  encrypt-cli decrypt --key-file %s ...\n", outPath)
	return nil
}

func resolveConfig() *config.Config {
	var cfg *config.Config
	if cfgFile != "" {
		c, err := config.Load(cfgFile)
		if err == nil {
			cfg = c
		} else {
			fmt.Fprintf(os.Stderr, "Warning: could not load config %s: %v\n", cfgFile, err)
		}
	}
	if cfg == nil {
		for _, path := range []string{"config.yaml", "config.yml", filepath.Join("~", ".encrypt-cli.yaml")} {
			expanded := os.ExpandEnv(path)
			c, err := config.Load(expanded)
			if err == nil {
				cfg = c
				break
			}
		}
	}
	if cfg == nil {
		cfg = config.Default()
	}
	config.ApplyEnvOverrides(cfg)
	return cfg
}
