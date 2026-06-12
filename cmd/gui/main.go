package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"gopkg.in/yaml.v3"

	"github.com/babico/kryp/internal/config"
	"github.com/babico/kryp/internal/crypto"
	"github.com/babico/kryp/internal/db"
)

type logList struct {
	lines      []string
	scroll     *container.Scroll
	list       *widget.List
}

func newLogList() *logList {
	ll := &logList{
		lines: make([]string, 0),
	}
	ll.list = widget.NewList(
		func() int { return len(ll.lines) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, item fyne.CanvasObject) {
			item.(*widget.Label).SetText(ll.lines[id])
		},
	)
	ll.scroll = container.NewScroll(ll.list)
	return ll
}

func (ll *logList) Append(msg string) {
	ts := time.Now().Format("15:04:05")
	ll.lines = append(ll.lines, "["+ts+"] "+msg)
	ll.list.Refresh()
}

func (ll *logList) CanvasObject() fyne.CanvasObject {
	return ll.scroll
}

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
	encryptLog      *logList

	decryptSourceEntry     *widget.Entry
	decryptOutputEntry     *widget.Entry
	decryptPassphraseEntry *widget.Entry
	decryptKeyFileEntry    *widget.Entry
	keepPathCheck   *widget.Check
	decryptLog      *logList

	progress        *widget.ProgressBarInfinite
	encryptRunning   bool
	decryptRunning   bool
}

func main() {
	a := app.NewWithID("com.babico.kryp")
	w := a.NewWindow("Kryp - File Encryption")

	g := &guiApp{window: w}

	tabs := container.NewAppTabs(
		container.NewTabItem("Encrypt", g.makeEncryptTab()),
		container.NewTabItem("Decrypt", g.makeDecryptTab()),
		container.NewTabItem("Settings", g.makeSettingsTab()),
	)

	w.SetContent(tabs)
	w.Resize(fyne.NewSize(1200, 800))
	w.ShowAndRun()
}

func browseFolder(w fyne.Window, target *widget.Entry) {
	d := dialog.NewFolderOpen(func(uri fyne.ListableURI, err error) {
		if err == nil && uri != nil {
			target.SetText(uri.Path())
		}
	}, w)
	d.Resize(fyne.NewSize(800, 600))
	d.Show()
}

func buildRightColumn(algoSelect *widget.Select, ageEntry *widget.Entry, uuidCheck, embedCheck *widget.Check) (fyne.CanvasObject, *widget.Card) {
	ageCard := makeSection("Age Recipient", ageEntry)
	ageCard.Hide()

	right := container.NewVBox(
		makeSection("Options", container.NewVBox(
			uuidCheck,
			embedCheck,
		)),
		ageCard,
	)

	algoSelect.OnChanged = func(a string) {
		if a == "age" {
			ageCard.Show()
			right.Refresh()
		} else if ageCard.Visible() {
			ageCard.Hide()
			right.Refresh()
		}
	}

	return right, ageCard
}

func (g *guiApp) makeEncryptTab() fyne.CanvasObject {
	g.encryptSourceEntry = widget.NewEntry()
	g.encryptSourceEntry.SetText("test/original")
	sourceBtn := widget.NewButton("Browse...", func() {
		browseFolder(g.window, g.encryptSourceEntry)
	})

	g.encryptOutputEntry = widget.NewEntry()
	g.encryptOutputEntry.SetText("test/encrypted")
	outputBtn := widget.NewButton("Browse...", func() {
		browseFolder(g.window, g.encryptOutputEntry)
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
	g.encryptKeyFileEntry.SetPlaceHolder("Key file path")

	encryptKeyGenBtn := widget.NewButton("Generate", func() {
		g.showGenerateKeyDialog(g.encryptKeyFileEntry)
	})

	g.uuidCheck = widget.NewCheck("UUID rename", nil)

	g.embedCheck = widget.NewCheck("Embed metadata", nil)

	g.ageEntry = widget.NewEntry()
	g.ageEntry.SetPlaceHolder("Age recipient key (age1...)")

	g.encryptLog = newLogList()

	g.progress = widget.NewProgressBarInfinite()
	g.progress.Hide()

	encryptBtn := widget.NewButtonWithIcon("Encrypt", theme.ConfirmIcon(), func() {
		if g.encryptRunning {
			return
		}
		go g.runEncrypt()
	})

	left := container.NewVBox(
		makeSection("Directories", container.NewVBox(
			widget.NewLabelWithStyle("Source", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			container.NewBorder(nil, nil, nil, sourceBtn, g.encryptSourceEntry),
			widget.NewLabelWithStyle("Output", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			container.NewBorder(nil, nil, nil, outputBtn, g.encryptOutputEntry),
		)),
		makeSection("Encryption Settings", container.NewVBox(
			widget.NewLabelWithStyle("Algorithm", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			g.algoSelect,
			widget.NewLabelWithStyle("Key Derivation", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			g.kdfSelect,
			widget.NewLabelWithStyle("Passphrase", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			g.encryptPassphraseEntry,
			widget.NewLabelWithStyle("Key File", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			container.NewBorder(nil, nil, nil, encryptKeyGenBtn, g.encryptKeyFileEntry),
		)),
		encryptBtn,
		g.progress,
	)

	right, _ := buildRightColumn(g.algoSelect, g.ageEntry, g.uuidCheck, g.embedCheck)

	logArea := container.NewBorder(
		widget.NewLabelWithStyle("Log", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nil, nil, nil,
		g.encryptLog.CanvasObject(),
	)

	top := container.NewHSplit(
		container.NewScroll(left),
		container.NewScroll(right),
	)
	top.SetOffset(0.55)

	split := container.NewVSplit(top, logArea)
	split.SetOffset(0.75)

	return split
}

func (g *guiApp) makeDecryptTab() fyne.CanvasObject {
	g.decryptSourceEntry = widget.NewEntry()
	g.decryptSourceEntry.SetText("test/encrypted")
	sourceBtn := widget.NewButton("Browse...", func() {
		browseFolder(g.window, g.decryptSourceEntry)
	})

	g.decryptOutputEntry = widget.NewEntry()
	g.decryptOutputEntry.SetText("test/decrypted")
	outputBtn := widget.NewButton("Browse...", func() {
		browseFolder(g.window, g.decryptOutputEntry)
	})

	g.decryptPassphraseEntry = widget.NewPasswordEntry()
	g.decryptPassphraseEntry.SetPlaceHolder("Passphrase")

	g.decryptKeyFileEntry = widget.NewEntry()
	g.decryptKeyFileEntry.SetPlaceHolder("Key file path")

	decryptKeyGenBtn := widget.NewButton("Generate", func() {
		g.showGenerateKeyDialog(g.decryptKeyFileEntry)
	})

	g.keepPathCheck = widget.NewCheck("Restore original directory structure", nil)

	g.decryptLog = newLogList()

	g.progress = widget.NewProgressBarInfinite()
	g.progress.Hide()

	decryptBtn := widget.NewButtonWithIcon("Decrypt", theme.ConfirmIcon(), func() {
		if g.decryptRunning {
			return
		}
		go g.runDecrypt()
	})

	left := container.NewVBox(
		makeSection("Directories", container.NewVBox(
			widget.NewLabelWithStyle("Source (Encrypted)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			container.NewBorder(nil, nil, nil, sourceBtn, g.decryptSourceEntry),
			widget.NewLabelWithStyle("Output", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			container.NewBorder(nil, nil, nil, outputBtn, g.decryptOutputEntry),
		)),
		makeSection("Decryption Settings", container.NewVBox(
			widget.NewLabelWithStyle("Passphrase", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			g.decryptPassphraseEntry,
			widget.NewLabelWithStyle("Key File", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			container.NewBorder(nil, nil, nil, decryptKeyGenBtn, g.decryptKeyFileEntry),
		)),
		decryptBtn,
		g.progress,
	)

	right := container.NewVBox(
		makeSection("Options", container.NewVBox(
			g.keepPathCheck,
		)),
	)

	logArea := container.NewBorder(
		widget.NewLabelWithStyle("Log", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nil, nil, nil,
		g.decryptLog.CanvasObject(),
	)

	top := container.NewHSplit(
		container.NewScroll(left),
		container.NewScroll(right),
	)
	top.SetOffset(0.55)

	split := container.NewVSplit(top, logArea)
	split.SetOffset(0.75)

	return split
}

func makeSection(title string, content fyne.CanvasObject) *widget.Card {
	return widget.NewCard(title, "", content)
}

func (g *guiApp) makeSettingsTab() fyne.CanvasObject {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		cfg = config.Default()
	}

	cfgEditor := widget.NewMultiLineEntry()
	cfgData, _ := yaml.Marshal(cfg)
	cfgEditor.SetText(string(cfgData))
	cfgEditor.SetMinRowsVisible(12)

	saveBtn := widget.NewButton("Save Config", func() {
		if err := os.WriteFile("config.yaml", []byte(cfgEditor.Text), 0600); err != nil {
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
		sb.WriteString(fmt.Sprintf("  \u2022 %s (key: %d bytes)\n", id.String(), e.KeySize()))
	}
	algoList.SetText(sb.String())

	return container.NewScroll(container.NewVBox(
		makeSection("Configuration", container.NewVBox(
			cfgEditor,
			saveBtn,
		)),
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
		dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err == nil && writer != nil {
				pathEntry.SetText(writer.URI().Path())
				writer.Close()
			}
		}, g.window)
	})

	log := widget.NewMultiLineEntry()
	log.Disable()
	log.SetMinRowsVisible(6)

	var d *dialog.CustomDialog

	genBtn := widget.NewButtonWithIcon("Generate", theme.ConfirmIcon(), func() {
		algoName := algoSelect.Selected
		outPath := pathEntry.Text
		if outPath == "" {
			log.SetText("ERROR: specify an output path")
			return
		}

		algoID, err := crypto.ParseAlgorithm(algoName)
		if err != nil {
			log.SetText(fmt.Sprintf("ERROR: %v", err))
			return
		}

		switch algoID {
		case crypto.AlgoAge:
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

			log.SetText(fmt.Sprintf(
				"Age Identity: %s\nAge Recipient: %s\n\nRecipient key: %s\n\nEncrypt:  kryp encrypt --algorithm age --age-recipient \"%s\"\nDecrypt:  kryp decrypt --key-file %s",
				outPath, recipPath, identity.Recipient().String(), identity.Recipient().String(), outPath))

			if targetEntry != nil {
				targetEntry.SetText(outPath)
			}
			return

		case crypto.AlgoMLKEM768, crypto.AlgoMLKEM1024, crypto.AlgoHybridXWing, crypto.AlgoHPKE:
			if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
				log.SetText(fmt.Sprintf("ERROR: %v", err))
				return
			}
			kp := generateKEMKeypair(algoID, outPath)
			if kp == nil {
				return
			}
			pubPath := outPath + ".pub"
			log.SetText(fmt.Sprintf(
				"Private key: %s (%d bytes)\nPublic key:  %s (%d bytes)\n\nEncrypt:  kryp encrypt --algorithm %s --key-file %s\nDecrypt:  kryp decrypt --key-file %s",
				outPath, len(kp.PrivateSeed), pubPath, len(kp.PublicKey), algoID.String(), pubPath, outPath))
			if targetEntry != nil {
				targetEntry.SetText(outPath)
			}
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

		hexStr := fmt.Sprintf("%x", key)
		log.SetText(fmt.Sprintf(
			"Key saved: %s (%d bytes)\nAlgorithm: %s\n\nRaw (hex):  %s\n\nCLI:  kryp encrypt --algorithm %s --key-file %s",
			outPath, len(key), algoName, hexStr, algoName, outPath))

		if targetEntry != nil {
			targetEntry.SetText(outPath)
		}
	})

	content := container.NewVBox(
		widget.NewCard("Algorithm", "", algoSelect),
		widget.NewCard("Output Path", "", container.NewBorder(nil, nil, nil, browseBtn, pathEntry)),
		genBtn,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Result", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		log,
	)

	d = dialog.NewCustom("Generate Key", "Close", container.NewPadded(content), g.window)
	d.Resize(fyne.NewSize(500, 500))
	d.Show()
}

func (g *guiApp) logEncrypt(msg string) {
	if g.encryptLog != nil {
		g.encryptLog.Append(msg)
	}
}

func (g *guiApp) logDecrypt(msg string) {
	if g.decryptLog != nil {
		g.decryptLog.Append(msg)
	}
}

func (g *guiApp) setEncryptRunning(running bool) {
	g.encryptRunning = running
}

func (g *guiApp) setDecryptRunning(running bool) {
	g.decryptRunning = running
}

func (g *guiApp) runEncrypt() {
	g.setEncryptRunning(true)
	fyne.Do(func() {
		g.progress.Start()
		g.progress.Show()
	})

	defer func() {
		fyne.Do(func() {
			g.progress.Stop()
			g.progress.Hide()
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

	source := g.encryptSourceEntry.Text
	output := g.encryptOutputEntry.Text
	pass := g.encryptPassphraseEntry.Text
	keyFile := g.encryptKeyFileEntry.Text

	if _, err := os.Stat(source); os.IsNotExist(err) {
		fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR: source directory not found: %s", source)) })
		return
	}

	if algoID == crypto.AlgoAge && g.ageEntry.Text == "" {
		fyne.Do(func() { g.logEncrypt("ERROR: age algorithm requires an age recipient (public key)") })
		return
	}
	if algoID >= crypto.AlgoMLKEM768 && keyFile == "" && pass == "" {
		fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR: %s requires a key file", algoID.String())) })
		return
	}

	if err := os.MkdirAll(output, 0755); err != nil {
		fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR: creating output dir: %v", err)) })
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
		relPath = filepath.ToSlash(relPath)

		fyne.Do(func() { g.logEncrypt(fmt.Sprintf("Encrypting: %s", relPath)) })

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
			fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR encrypting %s: %v", relPath, err)) })
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
			fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR writing %s: %v", outName, err)) })
			return nil
		}
		encryptedCount++
		return nil
	})
	if walkErr != nil {
		fyne.Do(func() { g.logEncrypt(fmt.Sprintf("ERROR: walking source dir: %v", walkErr)) })
		return
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
		g.progress.Start()
		g.progress.Show()
	})

	defer func() {
		fyne.Do(func() {
			g.progress.Stop()
			g.progress.Hide()
		})
		g.setDecryptRunning(false)
	}()

	fyne.Do(func() { g.logDecrypt("Decryption Started") })

	source := g.decryptSourceEntry.Text
	output := g.decryptOutputEntry.Text
	pass := g.decryptPassphraseEntry.Text
	keyFile := g.decryptKeyFileEntry.Text

	if _, err := os.Stat(source); os.IsNotExist(err) {
		fyne.Do(func() { g.logDecrypt(fmt.Sprintf("ERROR: source directory not found: %s", source)) })
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
	var kp *crypto.KEMKeypair
	var err error

	switch algoID {
	case crypto.AlgoMLKEM768:
		kp, err = crypto.GenerateMLKEMKeypair()
	case crypto.AlgoMLKEM1024:
		kp, err = crypto.GenerateMLKEM1024Keypair()
	case crypto.AlgoHybridXWing:
		kp, err = crypto.GenerateXWingKeypair()
	case crypto.AlgoHPKE:
		kp, err = crypto.GenerateHPKEKeypair()
	default:
		return nil
	}
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
