package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/babico/kryp/internal/crypto"
	"github.com/babico/kryp/internal/db"
)

func runEncrypt(cmd *cobra.Command, args []string) error {
	cfg := resolveConfig()

	if len(sourceFiles) == 0 {
		if cfg.Directories.Source != "" {
			sourceFiles = []string{cfg.Directories.Source}
		}
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
	if argon2Time == 0 && cfg.Encryption.Argon2Time != 0 {
		argon2Time = cfg.Encryption.Argon2Time
	}
	if argon2Memory == 0 && cfg.Encryption.Argon2Memory != 0 {
		argon2Memory = cfg.Encryption.Argon2Memory
	}
	if argon2Threads == 0 && cfg.Encryption.Argon2Threads != 0 {
		argon2Threads = cfg.Encryption.Argon2Threads
	}
	if scryptN == 0 && cfg.Encryption.ScryptN != 0 {
		scryptN = cfg.Encryption.ScryptN
	}
	if scryptR == 0 && cfg.Encryption.ScryptR != 0 {
		scryptR = cfg.Encryption.ScryptR
	}
	if scryptP == 0 && cfg.Encryption.ScryptP != 0 {
		scryptP = cfg.Encryption.ScryptP
	}
	if pbkdf2Iter == 0 && cfg.Encryption.PBKDF2Iter != 0 {
		pbkdf2Iter = cfg.Encryption.PBKDF2Iter
	}

	mode, paths, err := detectMode(sourceFiles)
	if err != nil {
		return err
	}

	algoID, err := crypto.ParseAlgorithm(algorithm)
	if err != nil {
		return err
	}

	kdf, err := crypto.ParseKDF(kdfMethod)
	if err != nil {
		return err
	}

	encOptsBase := &crypto.EncryptFileOptions{
		Algorithm:     algoID,
		Passphrase:    []byte(passphrase),
		KeyFile:       keyFile,
		KDFMethod:     kdf,
		UUIDRename:    uuidRename,
		EmbedMetadata: embedMetadata,
		Compatible:    compatible,
		AgeRecipient:  ageRecipient,
		Argon2Time:    argon2Time,
		Argon2Memory:  argon2Memory,
		Argon2Threads: argon2Threads,
		ScryptN:       scryptN,
		ScryptR:       scryptR,
		ScryptP:       scryptP,
		PBKDF2Iter:    pbkdf2Iter,
	}

	if mode == modeTrain {
		return encryptTrain(paths, outputDir, encOptsBase)
	}

	manifest := db.NewManifest()
	encryptedCount := 0

	srcPath := paths[0]
	srcInfo, srcErr := os.Stat(srcPath)
	if srcErr != nil {
		return fmt.Errorf("accessing source: %w", srcErr)
	}

	manifestDir := outputDir

	if srcInfo.IsDir() {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("creating output dir: %w", err)
		}
	}

	encryptFile := func(path string, info os.FileInfo, relPath string) (string, error) {
		fmt.Printf("[+] Encrypting: %s\n", relPath)

		encOpts := *encOptsBase
		encOpts.OriginalPathHint = relPath

		encData, err := crypto.EncryptFile(path, &encOpts)
		if err != nil {
			return "", fmt.Errorf("encrypting %s: %w", relPath, err)
		}

		fe := manifest.AddFile(
			relPath,
			filepath.Base(path),
			info.Size(),
			int64(len(encData)),
			algoID.String(),
		)

		var outName string
		if uuidRename {
			outName = fe.UUID + ".enc"
		} else {
			outName = relPath + ".enc"
		}

		outPath := outputPathForFile(path, outputDir, outName)
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return "", fmt.Errorf("creating output dir: %w", err)
		}
		if err := os.WriteFile(outPath, encData, 0644); err != nil {
			return "", fmt.Errorf("writing encrypted file: %w", err)
		}

		encryptedCount++
		return outPath, nil
	}

	if srcInfo.IsDir() {
		err := filepath.WalkDir(srcPath, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			relPath, _ := filepath.Rel(srcPath, path)
			info, _ := d.Info()
			if info == nil {
				return nil
			}
			_, err = encryptFile(path, info, relPath)
			return err
		})
		if err != nil {
			return err
		}
	} else {
		info, err := os.Stat(srcPath)
		if err != nil {
			return fmt.Errorf("accessing file: %w", err)
		}
		outPath, err := encryptFile(srcPath, info, filepath.Base(srcPath))
		if err != nil {
			return err
		}
		manifestDir = filepath.Dir(outPath)
	}

	fmt.Printf("\nEncrypted %d files\n", encryptedCount)

	manifestPath := filepath.Join(manifestDir, "manifest.json")
	encryptManifest := cfg.Database.Encrypt && algoID != crypto.AlgoAge
	if encryptManifest {
		manifestPath = filepath.Join(manifestDir, "manifest.json.enc")
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

	return nil
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	cfg := resolveConfig()

	var decryptErr error

	if len(sourceFiles) == 0 {
		if cfg.Directories.Output != "" {
			sourceFiles = []string{cfg.Directories.Output}
		}
	}
	if decryptDir == "" {
		decryptDir = cfg.Directories.Decrypted
	}

	mode, paths, err := detectMode(sourceFiles)
	if err != nil {
		return err
	}

	if mode == modeTrain {
		opts := &crypto.DecryptFileOptions{
			Passphrase: []byte(passphrase),
			KeyFile:    keyFile,
		}
		return decryptTrain(paths, decryptDir, opts)
	}

	srcPath := paths[0]
	srcInfo, srcErr := os.Stat(srcPath)
	if srcErr != nil {
		return fmt.Errorf("accessing source: %w", srcErr)
	}

	if !srcInfo.IsDir() {
		if !strings.HasSuffix(srcPath, ".enc") {
			return fmt.Errorf("source file must have .enc extension: %s", srcPath)
		}
		plaintext, header, err := crypto.DecryptFile(srcPath, &crypto.DecryptFileOptions{
			Passphrase: []byte(passphrase),
			KeyFile:    keyFile,
		})
		if err != nil {
			return fmt.Errorf("decrypting %s: %w", srcPath, err)
		}

		outName := strings.TrimSuffix(filepath.Base(srcPath), ".enc")
		if header.OriginalName != "" {
			outName = header.OriginalName
		}
		outPath := decryptOutputPath(srcPath, decryptDir, outName)

		outDir := filepath.Dir(outPath)
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return fmt.Errorf("creating output dir %s: %w", outDir, err)
		}
		if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
			return fmt.Errorf("writing decrypted file: %w", err)
		}
		hash := sha256.Sum256(plaintext)
		fmt.Printf("[+] Decrypted: %s\n", outPath)
		fmt.Printf("  SHA256: %x\n", hash[:])
		return nil
	}

	if err := os.MkdirAll(decryptDir, 0755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	manifestPath := filepath.Join(srcPath, "manifest.json.enc")
	plainManifestPath := filepath.Join(srcPath, "manifest.json")

	var manifest *db.Manifest

	if _, err := os.Stat(manifestPath); err == nil {
		manifestData, err := os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("reading manifest: %w", err)
		}

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
		decryptErr = filepath.WalkDir(srcPath, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".enc") {
				return nil
			}
			relPath, _ := filepath.Rel(srcPath, path)
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
			encPath := filepath.Join(srcPath, encName)

			if _, err := os.Stat(encPath); os.IsNotExist(err) {
				encPath = filepath.Join(srcPath, f.OriginalName+".enc")
				if _, err := os.Stat(encPath); os.IsNotExist(err) {
					encPath = filepath.Join(srcPath, f.OriginalPath+".enc")
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
			encPath := filepath.Join(srcPath, f.UUID)
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
