package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"gopkg.in/yaml.v3"

	"github.com/babico/kryp/internal/config"
	"github.com/babico/kryp/internal/crypto"
)

func makeSection(title string, content fyne.CanvasObject) *widget.Card {
	return widget.NewCard(title, "", content)
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

func browseFile(w fyne.Window, target *widget.Entry) {
	d := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err == nil && reader != nil {
			target.SetText(reader.URI().Path())
			reader.Close()
		}
	}, w)
	d.Resize(fyne.NewSize(800, 600))
	d.Show()
}

func buildRightColumn(algoSelect *widget.Select, ageEntry *widget.Entry, uuidCheck, embedCheck, compatCheck *widget.Check) (fyne.CanvasObject, *widget.Card) {
	ageCard := makeSection("Age Recipient", ageEntry)
	ageCard.Hide()

	right := container.NewVBox(
		makeSection("Options", container.NewVBox(
			uuidCheck,
			embedCheck,
			compatCheck,
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
	g.encryptFiles = make([]string, 0)

	g.encryptFileList = widget.NewList(
		func() int { return len(g.encryptFiles) },
		func() fyne.CanvasObject {
			removeBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), nil)
			removeBtn.Resize(fyne.NewSize(32, 32))
			return container.NewBorder(nil, nil, nil, removeBtn, widget.NewLabel(""))
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			border := obj.(*fyne.Container)
			label := border.Objects[1].(*widget.Label)
			label.SetText(filepath.Base(g.encryptFiles[id]))
			btn := border.Objects[0].(*widget.Button)
			idx := id
			btn.OnTapped = func() {
				g.encryptFiles = append(g.encryptFiles[:idx], g.encryptFiles[idx+1:]...)
				g.encryptFileList.Refresh()
			}
		},
	)
	fileListScroll := container.NewScroll(g.encryptFileList)
	fileListScroll.SetMinSize(fyne.NewSize(0, 150))

	addFileBtn := widget.NewButton("Add File", func() {
		dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err == nil && reader != nil {
				g.encryptFiles = append(g.encryptFiles, reader.URI().Path())
				reader.Close()
				g.encryptFileList.Refresh()
			}
		}, g.window).Show()
	})

	clearBtn := widget.NewButton("Clear All", func() {
		g.encryptFiles = nil
		g.encryptFileList.Refresh()
	})

	dirBrowseBtn := widget.NewButton("Browse Directory...", func() {
		browseFolder(g.window, g.encryptSourceEntry)
	})

	g.encryptOutputEntry = widget.NewEntry()
	g.encryptOutputEntry.SetText("test/encrypted")
	outputBtn := widget.NewButton("Browse...", func() {
		browseFolder(g.window, g.encryptOutputEntry)
	})

	algos := []string{"xchacha20-poly1305", "chacha20-poly1305", "aes-256-gcm", "secretbox", "aes-256-ctr-hmac", "age", "ml-kem-768", "ml-kem-1024", "x-wing", "hpke", "ascon", "aegis-128l", "aegis-256", "aes-256-gcm-siv", "hqc-128", "xoodyak", "deoxys-ii", "aes-256-siv", "frodokem-640-shake"}
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

	g.argon2TimeEntry = widget.NewEntry()
	g.argon2TimeEntry.SetPlaceHolder("3")
	g.argon2MemoryEntry = widget.NewEntry()
	g.argon2MemoryEntry.SetPlaceHolder("65536")
	g.argon2ThreadsEntry = widget.NewEntry()
	g.argon2ThreadsEntry.SetPlaceHolder("4")
	g.scryptNEntry = widget.NewEntry()
	g.scryptNEntry.SetPlaceHolder("32768")
	g.scryptREntry = widget.NewEntry()
	g.scryptREntry.SetPlaceHolder("8")
	g.scryptPEntry = widget.NewEntry()
	g.scryptPEntry.SetPlaceHolder("1")
	g.pbkdf2IterEntry = widget.NewEntry()
	g.pbkdf2IterEntry.SetPlaceHolder("600000")

	advancedKDF := makeSection("Advanced KDF Settings", container.NewVBox(
		widget.NewLabelWithStyle("Argon2id", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewGridWithColumns(3,
			container.NewBorder(nil, nil, widget.NewLabel("Time"), nil, g.argon2TimeEntry),
			container.NewBorder(nil, nil, widget.NewLabel("Memory"), nil, g.argon2MemoryEntry),
			container.NewBorder(nil, nil, widget.NewLabel("Threads"), nil, g.argon2ThreadsEntry),
		),
		widget.NewLabelWithStyle("Scrypt", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewGridWithColumns(3,
			container.NewBorder(nil, nil, widget.NewLabel("N"), nil, g.scryptNEntry),
			container.NewBorder(nil, nil, widget.NewLabel("r"), nil, g.scryptREntry),
			container.NewBorder(nil, nil, widget.NewLabel("p"), nil, g.scryptPEntry),
		),
		widget.NewLabelWithStyle("PBKDF2", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewGridWithColumns(1,
			container.NewBorder(nil, nil, widget.NewLabel("Iterations"), nil, g.pbkdf2IterEntry),
		),
	))

	g.uuidCheck = widget.NewCheck("UUID rename", nil)

	g.embedCheck = widget.NewCheck("Embed metadata", nil)

	g.compatCheck = widget.NewCheck("Compatible mode (no header)", func(checked bool) {
		if checked {
			g.uuidCheck.Disable()
			g.embedCheck.Disable()
			g.uuidCheck.SetChecked(false)
			g.embedCheck.SetChecked(false)
		} else {
			g.uuidCheck.Enable()
			g.embedCheck.Enable()
		}
	})

	g.ageEntry = widget.NewEntry()
	g.ageEntry.SetPlaceHolder("Age recipient key (age1...)")

	g.encryptLog = newLogList()

	g.encryptProgress = widget.NewProgressBarInfinite()
	g.encryptProgress.Hide()

	encryptBtn := widget.NewButtonWithIcon("Encrypt", theme.ConfirmIcon(), func() {
		if g.encryptRunning.Get() {
			return
		}
		go g.runEncrypt()
	})

	left := container.NewVBox(
		makeSection("Files", container.NewVBox(
			container.NewGridWithColumns(3, addFileBtn, clearBtn, dirBrowseBtn),
			fileListScroll,
		)),
		makeSection("Output", container.NewVBox(
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
		advancedKDF,
		encryptBtn,
		g.encryptProgress,
	)

	right, _ := buildRightColumn(g.algoSelect, g.ageEntry, g.uuidCheck, g.embedCheck, g.compatCheck)

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
	g.decryptFiles = make([]string, 0)

	g.decryptFileList = widget.NewList(
		func() int { return len(g.decryptFiles) },
		func() fyne.CanvasObject {
			removeBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), nil)
			removeBtn.Resize(fyne.NewSize(32, 32))
			return container.NewBorder(nil, nil, nil, removeBtn, widget.NewLabel(""))
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			border := obj.(*fyne.Container)
			label := border.Objects[1].(*widget.Label)
			label.SetText(filepath.Base(g.decryptFiles[id]))
			btn := border.Objects[0].(*widget.Button)
			idx := id
			btn.OnTapped = func() {
				g.decryptFiles = append(g.decryptFiles[:idx], g.decryptFiles[idx+1:]...)
				g.decryptFileList.Refresh()
			}
		},
	)
	decryptFileListScroll := container.NewScroll(g.decryptFileList)
	decryptFileListScroll.SetMinSize(fyne.NewSize(0, 150))

	addDecryptFileBtn := widget.NewButton("Add Encrypted File", func() {
		dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err == nil && reader != nil {
				g.decryptFiles = append(g.decryptFiles, reader.URI().Path())
				reader.Close()
				g.decryptFileList.Refresh()
			}
		}, g.window).Show()
	})

	clearDecryptBtn := widget.NewButton("Clear All", func() {
		g.decryptFiles = nil
		g.decryptFileList.Refresh()
	})

	dirBrowseDecryptBtn := widget.NewButton("Browse Directory...", func() {
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

	g.decryptProgress = widget.NewProgressBarInfinite()
	g.decryptProgress.Hide()

	decryptBtn := widget.NewButtonWithIcon("Decrypt", theme.ConfirmIcon(), func() {
		if g.decryptRunning.Get() {
			return
		}
		go g.runDecrypt()
	})

	left := container.NewVBox(
		makeSection("Encrypted Files", container.NewVBox(
			container.NewGridWithColumns(3, addDecryptFileBtn, clearDecryptBtn, dirBrowseDecryptBtn),
			decryptFileListScroll,
		)),
		makeSection("Output", container.NewVBox(
			container.NewBorder(nil, nil, nil, outputBtn, g.decryptOutputEntry),
		)),
		makeSection("Decryption Settings", container.NewVBox(
			widget.NewLabelWithStyle("Passphrase", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			g.decryptPassphraseEntry,
			widget.NewLabelWithStyle("Key File", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			container.NewBorder(nil, nil, nil, decryptKeyGenBtn, g.decryptKeyFileEntry),
		)),
		decryptBtn,
		g.decryptProgress,
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
