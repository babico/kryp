package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"

	"github.com/babico/kryp/internal/crypto"
	"github.com/babico/kryp/internal/db"
)

func (g *guiApp) runEncrypt() {
	g.setEncryptRunning(true)
	fyne.Do(func() {
		g.encryptProgress.Start()
		g.encryptProgress.Show()
	})

	defer func() {
		fyne.Do(func() {
			g.encryptProgress.Stop()
			g.encryptProgress.Hide()
		})
		g.setEncryptRunning(false)
	}()

	fyne.Do(func() { g.logEncrypt("Encryption Started") })

	algoID, err := crypto.ParseAlgorithm(g.algoSelect.Selected)
	if err != nil {
		fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR: %v", err)) })
		return
	}

	kdf, err := crypto.ParseKDF(g.kdfSelect.Selected)
	if err != nil {
		fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR: %v", err)) })
		return
	}

	output := g.encryptOutputEntry.Text
	pass := g.encryptPassphraseEntry.Text
	keyFile := g.encryptKeyFileEntry.Text

	if algoID == crypto.AlgoAge && g.ageEntry.Text == "" {
		fyne.Do(func() { g.logEncrypt("ERROR: age algorithm requires an age recipient (public key)") })
		return
	}
	if algoID >= crypto.AlgoMLKEM768 && keyFile == "" && pass == "" {
		fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR: %s requires a key file", algoID.String())) })
		return
	}

	manifest := db.NewManifest()
	encryptedCount := 0

	var argon2Time, argon2Memory, scryptN, scryptR, scryptP, pbkdf2Iter uint32
	var argon2Threads uint8

	fmt.Sscanf(g.argon2TimeEntry.Text, "%d", &argon2Time)
	fmt.Sscanf(g.argon2MemoryEntry.Text, "%d", &argon2Memory)
	fmt.Sscanf(g.argon2ThreadsEntry.Text, "%d", &argon2Threads)
	fmt.Sscanf(g.scryptNEntry.Text, "%d", &scryptN)
	fmt.Sscanf(g.scryptREntry.Text, "%d", &scryptR)
	fmt.Sscanf(g.scryptPEntry.Text, "%d", &scryptP)
	fmt.Sscanf(g.pbkdf2IterEntry.Text, "%d", &pbkdf2Iter)

	encryptFile := func(path string, info os.FileInfo, relPath string) {
		relPath = filepath.ToSlash(relPath)
		fyne.Do(func() { g.logEncrypt(fmt.Sprintf("Encrypting: %s", relPath)) })

		encOpts := &crypto.EncryptFileOptions{
			Algorithm:        algoID,
			Passphrase:       []byte(pass),
			KeyFile:          keyFile,
			KDFMethod:        kdf,
			EmbedMetadata:    g.embedCheck.Checked,
			Compatible:       g.compatCheck.Checked,
			AgeRecipient:     g.ageEntry.Text,
			OriginalPathHint: relPath,
			Argon2Time:       argon2Time,
			Argon2Memory:     argon2Memory,
			Argon2Threads:    argon2Threads,
			ScryptN:          scryptN,
			ScryptR:          scryptR,
			ScryptP:          scryptP,
			PBKDF2Iter:       pbkdf2Iter,
		}

		encData, encErr := crypto.EncryptFile(path, encOpts)
		if encErr != nil {
			fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR encrypting %s: %v", relPath, encErr)) })
			return
		}

		fe := manifest.AddFile(relPath, filepath.Base(path), info.Size(), int64(len(encData)), algoID.String())

		var outName string
		if g.uuidCheck.Checked && !g.compatCheck.Checked {
			outName = fe.UUID + ".enc"
		} else {
			outName = relPath + ".enc"
		}

		outPath := filepath.Join(output, outName)
		os.MkdirAll(filepath.Dir(outPath), 0755)
		if err := os.WriteFile(outPath, encData, 0644); err != nil {
			fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR writing %s: %v", outName, err)) })
			return
		}
		encryptedCount++
	}

	if len(g.encryptFiles) > 0 {
		if err := os.MkdirAll(output, 0755); err != nil {
			fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR: creating output dir: %v", err)) })
			return
		}
		for _, filePath := range g.encryptFiles {
			info, err := os.Stat(filePath)
			if err != nil {
				fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR: %v", err)) })
				continue
			}
			encryptFile(filePath, info, filepath.Base(filePath))
		}
	} else {
		source := g.encryptSourceEntry.Text
		srcInfo, err := os.Stat(source)
		if os.IsNotExist(err) {
			fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR: source not found: %s", source)) })
			return
		}

		if srcInfo.IsDir() {
			if err := os.MkdirAll(output, 0755); err != nil {
				fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR: creating output dir: %v", err)) })
				return
			}
			walkErr := filepath.WalkDir(source, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				relPath, _ := filepath.Rel(source, path)
				info, _ := d.Info()
				if info == nil {
					return nil
				}
				encryptFile(path, info, relPath)
				return nil
			})
			if walkErr != nil {
				fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR: walking source dir: %v", walkErr)) })
				return
			}
		} else {
			if err := os.MkdirAll(output, 0755); err != nil {
				fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR: creating output dir: %v", err)) })
				return
			}
			encryptFile(source, srcInfo, filepath.Base(source))
		}
	}

	fyne.Do(func() { g.logEncrypt(fmt.Sprintf("Encrypted %d files", encryptedCount)) })

	encryptManifest := algoID != crypto.AlgoAge
	manifestPath := filepath.Join(output, "manifest.json")
	if encryptManifest {
		manifestPath = filepath.Join(output, "manifest.json.enc")
		manifestData, err := manifest.Serialize()
		if err != nil {
			fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR serializing manifest: %v", err)) })
			return
		}
		encOpts := &crypto.EncryptFileOptions{
			Algorithm:  algoID,
			Passphrase: []byte(pass),
			KeyFile:    keyFile,
			KDFMethod:  kdf,
		}
		encManifest, err := crypto.EncryptFileBytes(manifestData, encOpts)
		if err != nil {
			fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR encrypting manifest: %v", err)) })
			return
		}
		if err := os.WriteFile(manifestPath, encManifest, 0644); err != nil {
			fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR saving manifest: %v", err)) })
			return
		}
		fyne.Do(func() { g.logEncrypt(fmt.Sprintf("Encrypted manifest saved: %s", manifestPath)) })
	} else {
		manifestData, err := manifest.Serialize()
		if err != nil {
			fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR serializing manifest: %v", err)) })
			return
		}
		if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
			fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR saving manifest: %v", err)) })
			return
		}
		fyne.Do(func() { g.logEncrypt(fmt.Sprintf("Manifest saved: %s", manifestPath)) })
	}

	fyne.Do(func() { g.logEncrypt("Encryption Complete") })
}

func (g *guiApp) runDecrypt() {
	g.setDecryptRunning(true)
	fyne.Do(func() {
		g.decryptProgress.Start()
		g.decryptProgress.Show()
	})

	defer func() {
		fyne.Do(func() {
			g.decryptProgress.Stop()
			g.decryptProgress.Hide()
		})
		g.setDecryptRunning(false)
	}()

	fyne.Do(func() { g.logDecrypt("Decryption Started") })

	output := g.decryptOutputEntry.Text
	pass := g.decryptPassphraseEntry.Text
	keyFile := g.decryptKeyFileEntry.Text

	if len(g.decryptFiles) > 0 {
		if err := os.MkdirAll(output, 0755); err != nil {
			fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR: creating output dir: %v", err)) })
			return
		}
		decryptedCount := 0
		for _, encPath := range g.decryptFiles {
			fileName := filepath.Base(encPath)
			fyne.Do(func() { g.logDecrypt(fmt.Sprintf("Decrypting: %s", fileName)) })
			plaintext, header, decErr := crypto.DecryptFile(encPath, &crypto.DecryptFileOptions{
				Passphrase: []byte(pass),
				KeyFile:    keyFile,
			})
			if decErr != nil {
				fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR decrypting %s: %v", fileName, decErr)) })
				continue
			}
			outName := strings.TrimSuffix(fileName, ".enc")
			if header.OriginalName != "" {
				outName = header.OriginalName
			}
			outPath := filepath.Join(output, outName)
			os.MkdirAll(filepath.Dir(outPath), 0755)
			if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
				fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR writing %s: %v", outName, err)) })
				continue
			}
			fyne.Do(func() { g.logDecrypt(fmt.Sprintf("Decrypted: %s", outPath)) })
			decryptedCount++
		}
		fyne.Do(func() { g.logDecrypt(fmt.Sprintf("Decrypted %d files", decryptedCount)) })
		fyne.Do(func() { g.logDecrypt("Decryption Complete") })
		return
	}

	source := g.decryptSourceEntry.Text
	srcInfo, err := os.Stat(source)
	if os.IsNotExist(err) {
		fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR: source not found: %s", source)) })
		return
	}

	if !srcInfo.IsDir() {
		if !strings.HasSuffix(source, ".enc") {
			fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR: source file must have .enc extension: %s", source)) })
			return
		}
		plaintext, header, decErr := crypto.DecryptFile(source, &crypto.DecryptFileOptions{
			Passphrase: []byte(pass),
			KeyFile:    keyFile,
		})
		if decErr != nil {
			fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR decrypting: %v", decErr)) })
			return
		}
		outName := strings.TrimSuffix(filepath.Base(source), ".enc")
		if header.OriginalName != "" {
			outName = header.OriginalName
		}
		outPath := filepath.Join(output, outName)
		os.MkdirAll(filepath.Dir(outPath), 0755)
		if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
			fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR writing: %v", err)) })
			return
		}
		fyne.Do(func() { g.logDecrypt(fmt.Sprintf("Decrypted: %s", outPath)) })
		fyne.Do(func() { g.logDecrypt("Decryption Complete") })
		return
	}

	if err := os.MkdirAll(output, 0755); err != nil {
		fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR: creating output dir: %v", err)) })
		return
	}

	manifestPath := filepath.Join(source, "manifest.json.enc")
	var manifest *db.Manifest

	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		fyne.Do(func() { g.logDecrypt("No encrypted manifest found, trying plain files") })
		g.runDecryptFiles(source, output, pass, keyFile, nil)
		return
	}

	decResult, _, err := crypto.DecryptFileBytes(manifestData, &crypto.DecryptFileOptions{
		Passphrase: []byte(pass),
		KeyFile:    keyFile,
	})
	if err != nil {
		fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR decrypting manifest: %v", err)) })
		return
	}

	manifest, err = db.DeserializeManifest(decResult)
	if err != nil {
		fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR parsing manifest: %v", err)) })
		return
	}

	fyne.Do(func() { g.logDecrypt(fmt.Sprintf("Loaded manifest: %d files", manifest.Count())) })
	g.runDecryptFiles(source, output, pass, keyFile, manifest)
}

func (g *guiApp) runDecryptFiles(source, output, pass, keyFile string, manifest *db.Manifest) {
	keepPath := g.keepPathCheck.Checked

	resolveOutPath := func(outDir, origName, origPath string) string {
		name := origName
		if name == "" {
			name = origPath
		}
		if name == "" {
			name = "decrypted"
		}
		if keepPath && origPath != "" {
			clean := filepath.Clean(origPath)
			if clean != "." {
				return filepath.Join(outDir, clean)
			}
		}
		return filepath.Join(outDir, name)
	}

	if manifest != nil {
		decryptedCount := 0
		for _, f := range manifest.ListFiles() {
			encName := f.UUID + ".enc"
			encPath := filepath.Join(source, encName)

			if _, err := os.Stat(encPath); os.IsNotExist(err) {
				encPath = filepath.Join(source, f.OriginalName+".enc")
				if _, err := os.Stat(encPath); os.IsNotExist(err) {
					encPath = filepath.Join(source, f.OriginalPath+".enc")
					if _, err := os.Stat(encPath); os.IsNotExist(err) {
						fyne.Do(func() { g.logDecrypt(fmt.Sprintf("Skipping %s: file not found", f.OriginalName)) })
						continue
					}
				}
			}

			fyne.Do(func() { g.logDecrypt(fmt.Sprintf("Decrypting: %s", f.OriginalName)) })
			plaintext, header, err := crypto.DecryptFile(encPath, &crypto.DecryptFileOptions{
				Passphrase: []byte(pass),
				KeyFile:    keyFile,
			})
			if err != nil {
				fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR decrypting %s: %v", f.OriginalName, err)) })
				continue
			}

			outName := f.OriginalName
			if header.OriginalName != "" {
				outName = header.OriginalName
			}
			outPath := resolveOutPath(output, outName, header.OriginalPath)
			outDir := filepath.Dir(outPath)
			os.MkdirAll(outDir, 0755)
			if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
				fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR writing %s: %v", outName, err)) })
				continue
			}
			decryptedCount++
		}
		fyne.Do(func() { g.logDecrypt(fmt.Sprintf("Decrypted %d files", decryptedCount)) })
	} else {
		err := filepath.WalkDir(source, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".enc") {
				return nil
			}
			fyne.Do(func() { g.logDecrypt(fmt.Sprintf("Decrypting: %s", d.Name())) })
			plaintext, header, err := crypto.DecryptFile(path, &crypto.DecryptFileOptions{
				Passphrase: []byte(pass),
				KeyFile:    keyFile,
			})
			if err != nil {
				fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR decrypting %s: %v", d.Name(), err)) })
				return nil
			}
			outName := strings.TrimSuffix(d.Name(), ".enc")
			if header.OriginalName != "" {
				outName = header.OriginalName
			}
			outPath := resolveOutPath(output, outName, header.OriginalPath)
			outDir := filepath.Dir(outPath)
			os.MkdirAll(outDir, 0755)
			if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
				fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR writing %s: %v", outName, err)) })
			}
			return nil
		})
		if err != nil {
			fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR walking source: %v", err)) })
		}
	}
	fyne.Do(func() { g.logDecrypt("Decryption Complete") })
}

func generateKEMKeypair(algoID crypto.AlgorithmID, outPath string) *crypto.KEMKeypair {
	kp, err := crypto.GenerateKEMKeypair(algoID)
	if err != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return nil
	}
	pubPath := outPath + ".pub"
	if err := os.WriteFile(outPath, kp.PrivateSeed, 0600); err != nil {
		return nil
	}
	if err := os.WriteFile(pubPath, kp.PublicKey, 0644); err != nil {
		return nil
	}
	return kp
}
