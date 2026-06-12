package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/babico/kryp/internal/config"
	"github.com/babico/kryp/internal/crypto"
)

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

	switch keyFormat {
	case "hex":
		hexPriv := outPath + ".priv.hex"
		hexPub := pubPath + ".hex"
		if err := os.WriteFile(hexPriv, []byte(fmt.Sprintf("%x", kp.PrivateSeed)+"\n"), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing hex private key: %v\n", err)
		}
		if err := os.WriteFile(hexPub, []byte(fmt.Sprintf("%x", kp.PublicKey)+"\n"), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing hex public key: %v\n", err)
		}
	case "base64":
		b64Priv := outPath + ".priv.b64"
		b64Pub := pubPath + ".b64"
		if err := os.WriteFile(b64Priv, []byte(base64.StdEncoding.EncodeToString(kp.PrivateSeed)+"\n"), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing base64 private key: %v\n", err)
		}
		if err := os.WriteFile(b64Pub, []byte(base64.StdEncoding.EncodeToString(kp.PublicKey)+"\n"), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing base64 public key: %v\n", err)
		}
	}

	algoUpper := strings.ToUpper(algoName[:1]) + algoName[1:]
	fmt.Printf("%s keypair generated:\n", algoUpper)
	fmt.Printf("  Private key (seed): %s  (%d bytes)\n", outPath, len(kp.PrivateSeed))
	fmt.Printf("  Public key:          %s  (%d bytes)\n", pubPath, len(kp.PublicKey))
	fmt.Printf("\nEncrypt:\n")
	fmt.Printf("  kryp encrypt --algorithm %s --key-file %s ...\n", algoName, pubPath)
	fmt.Printf("Decrypt:\n")
	fmt.Printf("  kryp decrypt --key-file %s ...\n", outPath)
}

func readFilesFrom(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		files = append(files, line)
	}
	return files, nil
}

type sourceMode int

const (
	modeSingleFile sourceMode = iota
	modeDirectory
	modeTrain
)

func detectMode(files []string) (sourceMode, []string, error) {
	if filesFrom != "" {
		paths, err := readFilesFrom(filesFrom)
		if err != nil {
			return 0, nil, err
		}
		return modeTrain, paths, nil
	}
	if len(files) > 1 {
		return modeTrain, files, nil
	}
	if len(files) == 0 {
		return 0, nil, fmt.Errorf("no source specified (use -s or --files-from)")
	}
	info, err := os.Stat(files[0])
	if err != nil {
		return 0, nil, err
	}
	if info.IsDir() {
		return modeDirectory, files, nil
	}
	return modeSingleFile, files, nil
}

func encryptTrain(paths []string, outputDir string, opts *crypto.EncryptFileOptions) error {
	if outputDir == "" {
		outputDir = "encrypted"
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}
	var errs []error
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			errs = append(errs, fmt.Errorf("skipping %s: %v", path, err))
			continue
		}
		encData, err := crypto.EncryptFile(path, opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("encrypting %s: %v", path, err))
			continue
		}
		outPath := filepath.Join(outputDir, filepath.Base(path)+".enc")
		if err := os.WriteFile(outPath, encData, 0644); err != nil {
			errs = append(errs, fmt.Errorf("writing %s: %v", outPath, err))
			continue
		}
		fmt.Printf("[+] Encrypted: %s -> %s\n", path, outPath)
	}
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "[-] %v\n", e)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d of %d files failed", len(errs), len(paths))
	}
	return nil
}

func decryptTrain(paths []string, outputDir string, opts *crypto.DecryptFileOptions) error {
	if outputDir == "" {
		outputDir = "decrypted"
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}
	var errs []error
	for _, path := range paths {
		plaintext, header, err := crypto.DecryptFile(path, opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("decrypting %s: %v", path, err))
			continue
		}
		outName := strings.TrimSuffix(filepath.Base(path), ".enc")
		if header.OriginalName != "" {
			outName = header.OriginalName
		}
		outPath := filepath.Join(outputDir, outName)
		if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
			errs = append(errs, fmt.Errorf("writing %s: %v", outPath, err))
			continue
		}
		hash := sha256.Sum256(plaintext)
		fmt.Printf("[+] Decrypted: %s -> %s\n", path, outPath)
		fmt.Printf("  SHA256: %x\n", hash[:])
	}
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "[-] %v\n", e)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d of %d files failed", len(errs), len(paths))
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
	fmt.Printf("  kryp encrypt --algorithm age --age-recipient \"%s\" ...\n", identity.Recipient().String())
	fmt.Println("Decrypt:")
	fmt.Printf("  kryp decrypt --key-file %s ...\n", outPath)
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
		home, _ := os.UserHomeDir()
		homeCfg := ""
		if home != "" {
			homeCfg = filepath.Join(home, ".kryp.yaml")
		}
		for _, path := range []string{"config.yaml", "config.yml", homeCfg} {
			if path == "" {
				continue
			}
			c, err := config.Load(path)
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

func outputPathForFile(outputBase, defaultName string) string {
	info, err := os.Stat(outputBase)
	if err == nil && info.IsDir() {
		return filepath.Join(outputBase, defaultName)
	}
	if err == nil {
		return outputBase
	}
	ext := filepath.Ext(outputBase)
	if ext != "" && len(outputBase) > len(ext) {
		return outputBase
	}
	return filepath.Join(outputBase, defaultName)
}

func decryptOutputPath(outputBase, defaultName string) string {
	return outputPathForFile(outputBase, defaultName)
}
