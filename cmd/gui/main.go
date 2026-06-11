package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"gopkg.in/yaml.v3"

	"github.com/babico/data-encrypter-decrypter/internal/config"
	"github.com/babico/data-encrypter-decrypter/internal/crypto"
	"github.com/babico/data-encrypter-decrypter/internal/db"
	"github.com/babico/data-encrypter-decrypter/internal/store"
)

type guiApp struct {
	window fyne.Window

	encryptSourceEntry     *widget.Entry
	encryptOutputEntry     *widget.Entry
	algoSelect      *widget.Select
	kdfSelect       *widget.Select
	encryptPassphraseEntry *widget.Entry
	encryptKeyFileEntry    *widget.Entry
	uuidCheck       *widget.Check
	embedCheck      *widget.Check
	ageEntry        *widget.Entry
	rcloneEntry     *widget.Entry
	rcloneIncCheck  *widget.Check
	uploadCheck     *widget.Check
	encryptLog      *widget.Entry

	decryptSourceEntry     *widget.Entry
	decryptOutputEntry     *widget.Entry
	decryptPassphraseEntry *widget.Entry
	decryptKeyFileEntry    *widget.Entry
	keepPathCheck   *widget.Check
	decryptLog      *widget.Entry

	progress *widget.ProgressBarInfinite
}

func main() {
	a := app.NewWithID("com.babico.encrypt-cli")
	w := a.NewWindow("Encrypt CLI - Secure Data Encryption")

	g := &guiApp{window: w}

	tabs := container.NewAppTabs(
		container.NewTabItem("Encrypt", g.makeEncryptTab()),
		container.NewTabItem("Decrypt", g.makeDecryptTab()),
		container.NewTabItem("Settings", g.makeSettingsTab()),
	)

	w.SetContent(tabs)
	w.Resize(fyne.NewSize(800, 600))
	w.ShowAndRun()
}

func (g *guiApp) makeEncryptTab() fyne.CanvasObject {
	g.encryptSourceEntry = widget.NewEntry()
	g.encryptSourceEntry.SetText("test/original")
	sourceBtn := widget.NewButton("Browse...", func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err == nil && uri != nil {
				g.encryptSourceEntry.SetText(uri.Path())
			}
		}, g.window)
	})

	g.encryptOutputEntry = widget.NewEntry()
	g.encryptOutputEntry.SetText("test/encrypted")
	outputBtn := widget.NewButton("Browse...", func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err == nil && uri != nil {
				g.encryptOutputEntry.SetText(uri.Path())
			}
		}, g.window)
	})

	algos := []string{"xchacha20-poly1305", "chacha20-poly1305", "aes-256-gcm", "secretbox", "aes-256-ctr-hmac", "age", "ml-kem-768", "ml-kem-1024", "x-wing", "hpke", "ascon"}
	g.algoSelect = widget.NewSelect(algos, nil)
	g.algoSelect.SetSelected("xchacha20-poly1305")

	kdfs := []string{"argon2id", "scrypt", "pbkdf2"}
	g.kdfSelect = widget.NewSelect(kdfs, nil)
	g.kdfSelect.SetSelected("argon2id")

	g.encryptPassphraseEntry = widget.NewPasswordEntry()
	g.encryptPassphraseEntry.SetPlaceHolder("Passphrase (or leave empty for key file)")

	g.encryptKeyFileEntry = widget.NewEntry()
	g.encryptKeyFileEntry.SetPlaceHolder("Key file path (optional)")

	encryptKeyGenBtn := widget.NewButton("Generate", func() {
		g.showGenerateKeyDialog(g.encryptKeyFileEntry)
	})

	g.uuidCheck = widget.NewCheck("UUID rename (encrypt files as UUIDs)", nil)

	g.embedCheck = widget.NewCheck("Embed metadata (filename, path in header)", nil)

	g.ageEntry = widget.NewEntry()
	g.ageEntry.SetPlaceHolder("Age recipient (public key)")

	g.rcloneEntry = widget.NewEntry()
	g.rcloneEntry.SetPlaceHolder("rclone remote:path (e.g. mydropbox:backup/)")

	g.rcloneIncCheck = widget.NewCheck("Incremental sync (rclone sync)", nil)
	g.rcloneIncCheck.SetChecked(true)

	g.uploadCheck = widget.NewCheck("Upload after encryption", nil)

	g.encryptLog = widget.NewMultiLineEntry()
	g.encryptLog.Disable()

	g.progress = widget.NewProgressBarInfinite()
	g.progress.Hide()

	encryptBtn := widget.NewButtonWithIcon("Encrypt", theme.ConfirmIcon(), func() {
		go g.runEncrypt()
	})

	form := container.NewVBox(
		widget.NewLabelWithStyle("Source Directory", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, sourceBtn, g.encryptSourceEntry),
		widget.NewLabelWithStyle("Output Directory", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, outputBtn, g.encryptOutputEntry),
		widget.NewLabelWithStyle("Algorithm", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		g.algoSelect,
		widget.NewLabelWithStyle("Key Derivation", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		g.kdfSelect,
		widget.NewLabelWithStyle("Passphrase", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		g.encryptPassphraseEntry,
		widget.NewLabelWithStyle("Key File (optional)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, encryptKeyGenBtn, g.encryptKeyFileEntry),
		g.uuidCheck,
		g.embedCheck,
		widget.NewLabelWithStyle("Age Recipient (for age algorithm)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		g.ageEntry,
		g.rcloneIncCheck,
		g.rcloneEntry,
		g.uploadCheck,
		encryptBtn,
		g.progress,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Log", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		g.encryptLog,
	)

	return container.NewScroll(form)
}

func (g *guiApp) makeDecryptTab() fyne.CanvasObject {
	g.decryptSourceEntry = widget.NewEntry()
	g.decryptSourceEntry.SetText("test/encrypted")
	sourceBtn := widget.NewButton("Browse...", func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err == nil && uri != nil {
				g.decryptSourceEntry.SetText(uri.Path())
			}
		}, g.window)
	})

	g.decryptOutputEntry = widget.NewEntry()
	g.decryptOutputEntry.SetText("test/decrypted")
	outputBtn := widget.NewButton("Browse...", func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err == nil && uri != nil {
				g.decryptOutputEntry.SetText(uri.Path())
			}
		}, g.window)
	})

	g.decryptPassphraseEntry = widget.NewPasswordEntry()
	g.decryptPassphraseEntry.SetPlaceHolder("Passphrase")

	g.decryptKeyFileEntry = widget.NewEntry()
	g.decryptKeyFileEntry.SetPlaceHolder("Key file path")

	decryptKeyGenBtn := widget.NewButton("Generate", func() {
		g.showGenerateKeyDialog(g.decryptKeyFileEntry)
	})

	g.keepPathCheck = widget.NewCheck("Recreate original directory structure from header metadata", nil)

	g.decryptLog = widget.NewMultiLineEntry()
	g.decryptLog.Disable()

	decryptBtn := widget.NewButtonWithIcon("Decrypt", theme.ConfirmIcon(), func() {
		go g.runDecrypt()
	})

	form := container.NewVBox(
		widget.NewLabelWithStyle("Source (Encrypted) Directory", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, sourceBtn, g.decryptSourceEntry),
		widget.NewLabelWithStyle("Output Directory", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, outputBtn, g.decryptOutputEntry),
		widget.NewLabelWithStyle("Passphrase", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		g.decryptPassphraseEntry,
		widget.NewLabelWithStyle("Key File (optional)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, decryptKeyGenBtn, g.decryptKeyFileEntry),
		g.keepPathCheck,
		decryptBtn,
		g.progress,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Log", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		g.decryptLog,
	)

	return container.NewScroll(form)
}

func (g *guiApp) makeSettingsTab() fyne.CanvasObject {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		cfg = config.Default()
	}

	cfgEditor := widget.NewMultiLineEntry()
	cfgData, _ := yaml.Marshal(cfg)
	cfgEditor.SetText(string(cfgData))

	saveBtn := widget.NewButton("Save Config", func() {
		if err := os.WriteFile("config.yaml", []byte(cfgEditor.Text), 0644); err != nil {
			g.logEncrypt(fmt.Sprintf("Error saving config: %v", err))
			return
		}
		g.logEncrypt("Config saved to config.yaml")
	})

	algoList := widget.NewLabel("")
	var sb strings.Builder
	sb.WriteString("Supported Algorithms:\n")
	for _, id := range crypto.ListAlgorithms() {
		e, _ := crypto.GetEncryptor(id)
		sb.WriteString(fmt.Sprintf("  • %s (key: %d bytes)\n", id.String(), e.KeySize()))
	}
	algoList.SetText(sb.String())

	return container.NewScroll(container.NewVBox(
		widget.NewLabelWithStyle("Configuration", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		cfgEditor,
		saveBtn,
		widget.NewSeparator(),
		algoList,
	))
}

func (g *guiApp) showGenerateKeyDialog(targetEntry *widget.Entry) {
	algoSelect := widget.NewSelect([]string{"xchacha20-poly1305", "chacha20-poly1305", "aes-256-gcm", "secretbox", "aes-256-ctr-hmac", "age", "ml-kem-768", "ml-kem-1024", "x-wing", "hpke", "ascon"}, nil)
	algoSelect.SetSelected("xchacha20-poly1305")

	pathEntry := widget.NewEntry()
	pathEntry.SetPlaceHolder("Output file path (e.g. keys/mykey.bin)")

	browseBtn := widget.NewButton("Browse...", func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err == nil && uri != nil {
				pathEntry.SetText(filepath.Join(uri.Path(), "key.bin"))
			}
		}, g.window)
	})

	log := widget.NewMultiLineEntry()
	log.Disable()

	var d *dialog.CustomDialog

	genBtn := widget.NewButtonWithIcon("Generate", theme.ConfirmIcon(), func() {
		algoName := algoSelect.Selected
		outPath := pathEntry.Text
		if outPath == "" {
			log.SetText("ERROR: specify an output path")
			return
		}

		if strings.ToLower(algoName) == "age" {
			identity, err := age.GenerateX25519Identity()
			if err != nil {
				log.SetText(fmt.Sprintf("ERROR: %v", err))
				return
			}
			if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
				log.SetText(fmt.Sprintf("ERROR: %v", err))
				return
			}
			if err := os.WriteFile(outPath, []byte(identity.String()), 0600); err != nil {
				log.SetText(fmt.Sprintf("ERROR: %v", err))
				return
			}
			recipPath := outPath + ".recipient"
			recipData := []byte(identity.Recipient().String())
			os.WriteFile(recipPath, recipData, 0644)

			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Identity: %s\n", outPath))
			sb.WriteString(fmt.Sprintf("Recipient: %s\n", recipPath))
			sb.WriteString(fmt.Sprintf("\nRecipient key: %s\n", identity.Recipient().String()))
			log.SetText(sb.String())

			if targetEntry != nil {
				targetEntry.SetText(outPath)
			}
			return
		}

		algoID, err := crypto.ParseAlgorithm(algoName)
		if err != nil {
			log.SetText(fmt.Sprintf("ERROR: %v", err))
			return
		}
		algoNorm := strings.ToLower(algoName)
		if kp := generateKEMKeypair(algoNorm, log, outPath, targetEntry); kp != nil {
			return
		}

		key, err := crypto.GenerateKey(algoID)
		if err != nil {
			log.SetText(fmt.Sprintf("ERROR: %v", err))
			return
		}
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			log.SetText(fmt.Sprintf("ERROR: %v", err))
			return
		}
		if err := os.WriteFile(outPath, key, 0600); err != nil {
			log.SetText(fmt.Sprintf("ERROR: %v", err))
			return
		}
		log.SetText(fmt.Sprintf("Key saved: %s\nAlgorithm: %s\nKey size: %d bytes", outPath, algoName, len(key)))

		if targetEntry != nil {
			targetEntry.SetText(outPath)
		}
	})

	closeBtn := widget.NewButton("Close", func() {
		if d != nil {
			d.Hide()
		}
	})

	content := container.NewVBox(
		widget.NewLabelWithStyle("Algorithm", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		algoSelect,
		widget.NewLabelWithStyle("Output Path", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, browseBtn, pathEntry),
		genBtn,
		widget.NewSeparator(),
		log,
		closeBtn,
	)

	d = dialog.NewCustomWithoutButtons("Generate Key File", container.NewPadded(container.NewScroll(content)), g.window)
	d.Show()
}

func (g *guiApp) logEncrypt(msg string) {
	appendLog(g.encryptLog, msg)
}

func (g *guiApp) logDecrypt(msg string) {
	appendLog(g.decryptLog, msg)
}

func appendLog(e *widget.Entry, msg string) {
	if e == nil {
		return
	}
	current := e.Text
	if current != "" {
		e.SetText(current + "\n" + msg)
	} else {
		e.SetText(msg)
	}
}

func (g *guiApp) runEncrypt() {
	g.progress.Start()
	g.progress.Show()
	defer g.progress.Stop()
	defer g.progress.Hide()

	g.logEncrypt("=== Encryption Started ===")

	algoID, err := crypto.ParseAlgorithm(g.algoSelect.Selected)
	if err != nil {
		g.logEncrypt(fmt.Sprintf("ERROR: %v", err))
		return
	}

	kdf, err := crypto.ParseKDF(g.kdfSelect.Selected)
	if err != nil {
		g.logEncrypt(fmt.Sprintf("ERROR: %v", err))
		return
	}

	source := g.encryptSourceEntry.Text
	output := g.encryptOutputEntry.Text
	pass := g.encryptPassphraseEntry.Text
	keyFile := g.encryptKeyFileEntry.Text

	if err := os.MkdirAll(output, 0755); err != nil {
		g.logEncrypt(fmt.Sprintf("ERROR: creating output dir: %v", err))
		return
	}

	manifest := db.NewManifest()
	encryptedCount := 0

	walkErr := filepath.WalkDir(source, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(source, path)
		g.logEncrypt(fmt.Sprintf("Encrypting: %s", relPath))

		encOpts := &crypto.EncryptFileOptions{
			Algorithm:       algoID,
			Passphrase:      []byte(pass),
			KeyFile:         keyFile,
			KDFMethod:       kdf,
			EmbedMetadata:   g.embedCheck.Checked,
			AgeRecipient:    g.ageEntry.Text,
			OriginalPathHint: relPath,
		}

		encData, err := crypto.EncryptFile(path, encOpts)
		if err != nil {
			g.logEncrypt(fmt.Sprintf("ERROR encrypting %s: %v", relPath, err))
			return nil
		}

		info, _ := d.Info()
		var size int64
		if info != nil {
			size = info.Size()
		}

		fe := manifest.AddFile(relPath, d.Name(), size, int64(len(encData)), algoID.String())

		var outName string
		if g.uuidCheck.Checked {
			outName = fe.UUID + ".enc"
		} else {
			outName = relPath + ".enc"
		}

		outPath := filepath.Join(output, outName)
		os.MkdirAll(filepath.Dir(outPath), 0755)
		if err := os.WriteFile(outPath, encData, 0644); err != nil {
			g.logEncrypt(fmt.Sprintf("ERROR writing %s: %v", outName, err))
			return nil
		}
		encryptedCount++
		return nil
	})
	if walkErr != nil {
		g.logEncrypt(fmt.Sprintf("ERROR: walking source dir: %v", walkErr))
		return
	}

	g.logEncrypt(fmt.Sprintf("Encrypted %d files", encryptedCount))

	// Save manifest
	manifestPath := filepath.Join(output, "manifest.json")
	encryptManifest := algoID != crypto.AlgoAge
	if cfg, err := config.Load("config.yaml"); err == nil {
		encryptManifest = cfg.Database.Encrypt && algoID != crypto.AlgoAge
	}
	if encryptManifest {
		manifestPath = filepath.Join(output, "manifest.json.enc")
		manifestData, err := manifest.Serialize()
		if err != nil {
			g.logEncrypt(fmt.Sprintf("ERROR serializing manifest: %v", err))
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
			g.logEncrypt(fmt.Sprintf("ERROR encrypting manifest: %v", err))
			return
		}
		if err := os.WriteFile(manifestPath, encManifest, 0644); err != nil {
			g.logEncrypt(fmt.Sprintf("ERROR saving manifest: %v", err))
			return
		}
		g.logEncrypt(fmt.Sprintf("Encrypted manifest saved: %s", manifestPath))
	} else {
		manifestData, err := manifest.Serialize()
		if err != nil {
			g.logEncrypt(fmt.Sprintf("ERROR serializing manifest: %v", err))
			return
		}
		if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
			g.logEncrypt(fmt.Sprintf("ERROR saving manifest: %v", err))
			return
		}
		g.logEncrypt(fmt.Sprintf("Manifest saved: %s", manifestPath))
	}

	// Upload if enabled
	if g.uploadCheck.Checked && g.rcloneEntry.Text != "" {
		uploader := store.NewRcloneUploader("rclone", g.rcloneEntry.Text, g.rcloneIncCheck.Checked, "-v")
		if err := uploader.Upload(output); err != nil {
			g.logEncrypt(fmt.Sprintf("ERROR uploading: %v", err))
			return
		}
		g.logEncrypt("Upload complete!")
	}

	g.logEncrypt("=== Encryption Complete ===")
}

func (g *guiApp) runDecrypt() {
	g.progress.Start()
	g.progress.Show()
	defer g.progress.Stop()
	defer g.progress.Hide()

	g.logDecrypt("=== Decryption Started ===")

	source := g.decryptSourceEntry.Text
	output := g.decryptOutputEntry.Text
	pass := g.decryptPassphraseEntry.Text
	keyFile := g.decryptKeyFileEntry.Text

	if err := os.MkdirAll(output, 0755); err != nil {
		g.logDecrypt(fmt.Sprintf("ERROR: creating output dir: %v", err))
		return
	}

	// Load manifest
	manifestPath := filepath.Join(source, "manifest.json.enc")
	var manifest *db.Manifest

	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		g.logDecrypt("No encrypted manifest found, trying plain files")
		g.runDecryptFiles(source, output, pass, keyFile, nil)
		return
	}

	decResult, _, err := crypto.DecryptFileBytes(manifestData, &crypto.DecryptFileOptions{
		Passphrase: []byte(pass),
		KeyFile:    keyFile,
	})
	if err != nil {
		g.logDecrypt(fmt.Sprintf("ERROR decrypting manifest: %v", err))
		return
	}

	manifest, err = db.DeserializeManifest(decResult)
	if err != nil {
		g.logDecrypt(fmt.Sprintf("ERROR parsing manifest: %v", err))
		return
	}

	g.logDecrypt(fmt.Sprintf("Loaded manifest: %d files", manifest.Count()))
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
						g.logDecrypt(fmt.Sprintf("Skipping %s: file not found", f.OriginalName))
						continue
					}
				}
			}

			g.logDecrypt(fmt.Sprintf("Decrypting: %s", f.OriginalName))
			plaintext, header, err := crypto.DecryptFile(encPath, &crypto.DecryptFileOptions{
				Passphrase: []byte(pass),
				KeyFile:    keyFile,
			})
			if err != nil {
				g.logDecrypt(fmt.Sprintf("ERROR decrypting %s: %v", f.OriginalName, err))
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
				g.logDecrypt(fmt.Sprintf("ERROR writing %s: %v", outName, err))
				continue
			}
			decryptedCount++
		}
		g.logDecrypt(fmt.Sprintf("Decrypted %d files", decryptedCount))
	} else {
		err := filepath.WalkDir(source, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".enc") {
				return nil
			}
			g.logDecrypt(fmt.Sprintf("Decrypting: %s", d.Name()))
			plaintext, header, err := crypto.DecryptFile(path, &crypto.DecryptFileOptions{
				Passphrase: []byte(pass),
				KeyFile:    keyFile,
			})
			if err != nil {
				g.logDecrypt(fmt.Sprintf("ERROR decrypting %s: %v", d.Name(), err))
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
				g.logDecrypt(fmt.Sprintf("ERROR writing %s: %v", outName, err))
			}
			return nil
		})
		if err != nil {
			g.logDecrypt(fmt.Sprintf("ERROR walking source: %v", err))
		}
	}
	g.logDecrypt("=== Decryption Complete ===")
}

func generateKEMKeypair(algoNorm string, log *widget.Entry, outPath string, targetEntry *widget.Entry) *crypto.KEMKeypair {
	var kp *crypto.KEMKeypair
	var err error
	algoFlag := ""
	switch {
	case algoNorm == "ml-kem-768" || algoNorm == "mlkem768" || algoNorm == "kyber" || algoNorm == "post-quantum" || algoNorm == "7":
		kp, err = crypto.GenerateMLKEMKeypair()
		algoFlag = "ml-kem-768"
	case algoNorm == "ml-kem-1024" || algoNorm == "mlkem1024" || algoNorm == "kyber1024" || algoNorm == "8":
		kp, err = crypto.GenerateMLKEM1024Keypair()
		algoFlag = "ml-kem-1024"
	case algoNorm == "x-wing" || algoNorm == "xwing" || algoNorm == "hybrid" || algoNorm == "hybrid-xwing" || algoNorm == "9":
		kp, err = crypto.GenerateXWingKeypair()
		algoFlag = "x-wing"
	case algoNorm == "hpke" || algoNorm == "hpke-x25519" || algoNorm == "circl-hpke" || algoNorm == "10":
		kp, err = crypto.GenerateHPKEKeypair()
		algoFlag = "hpke"
	default:
		return nil
	}
	if err != nil {
		log.SetText(fmt.Sprintf("ERROR: %v", err))
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		log.SetText(fmt.Sprintf("ERROR: %v", err))
		return nil
	}
	pubPath := outPath + ".pub"
	if err := os.WriteFile(outPath, kp.PrivateSeed, 0600); err != nil {
		log.SetText(fmt.Sprintf("ERROR: %v", err))
		return nil
	}
	if err := os.WriteFile(pubPath, kp.PublicKey, 0644); err != nil {
		log.SetText(fmt.Sprintf("ERROR: %v", err))
		return nil
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Private key: %s  (%d bytes)\n", outPath, len(kp.PrivateSeed)))
	sb.WriteString(fmt.Sprintf("Public key:  %s  (%d bytes)\n", pubPath, len(kp.PublicKey)))
	sb.WriteString(fmt.Sprintf("\nEncrypt with: --algorithm %s --key-file %s", algoFlag, pubPath))
	log.SetText(sb.String())
	if targetEntry != nil {
		targetEntry.SetText(outPath)
	}
	return kp
}


