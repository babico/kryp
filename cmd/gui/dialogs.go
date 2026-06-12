package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/babico/kryp/internal/crypto"
)

func (g *guiApp) showGenerateKeyDialog(targetEntry *widget.Entry) {
	algoOptions := []string{"", "xchacha20-poly1305", "chacha20-poly1305", "aes-256-gcm", "secretbox", "aes-256-ctr-hmac", "age", "ml-kem-768", "ml-kem-1024", "x-wing", "hpke", "ascon", "aegis-128l", "aegis-256", "aes-256-gcm-siv", "hqc-128", "xoodyak", "deoxys-ii", "aes-256-siv", "frodokem-640-shake"}
	algoSelect := widget.NewSelect(algoOptions, nil)
	algoSelect.PlaceHolder = "Algorithm (empty = universal 64B key)"

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

	seedEntry := widget.NewEntry()
	seedEntry.SetPlaceHolder("Seed file path (optional, for PQC deterministic keygen)")

	browseSeedBtn := widget.NewButton("Browse Seed...", func() {
		dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err == nil && reader != nil {
				seedEntry.SetText(reader.URI().Path())
				reader.Close()
			}
		}, g.window).Show()
	})

	log := widget.NewMultiLineEntry()
	log.Disable()
	log.SetMinRowsVisible(6)

	var d *dialog.CustomDialog

	genBtn := widget.NewButtonWithIcon("Generate", theme.ConfirmIcon(), func() {
		algoName := algoSelect.Selected
		outPath := pathEntry.Text
		seedPath := seedEntry.Text
		if outPath == "" {
			log.SetText("ERROR: specify an output path")
			return
		}

		if algoName == "" {
			key := make([]byte, 64)
			_, err := rand.Read(key)
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
				"Universal key saved: %s (%d bytes)\nRaw (hex):  %s",
				outPath, len(key), hexStr))
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

		if seedPath != "" {
			isKEM := algoID == crypto.AlgoMLKEM768 || algoID == crypto.AlgoMLKEM1024 || algoID == crypto.AlgoHybridXWing || algoID == crypto.AlgoHPKE || algoID == crypto.AlgoHQC128 || algoID == crypto.AlgoFrodo640SHAKE
			if !isKEM {
				log.SetText("ERROR: seed-based keygen only supported for PQC/KEM algorithms")
				return
			}
			seedData, err := os.ReadFile(seedPath)
			if err != nil {
				log.SetText(fmt.Sprintf("ERROR reading seed file: %v", err))
				return
			}
			kp, err := crypto.GenerateKeyPairFromSeed(algoID, seedData)
			if err != nil {
				log.SetText(fmt.Sprintf("ERROR: %v", err))
				return
			}
			if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
				log.SetText(fmt.Sprintf("ERROR: %v", err))
				return
			}
			if err := os.WriteFile(outPath, kp.PrivateSeed, 0600); err != nil {
				log.SetText(fmt.Sprintf("ERROR: %v", err))
				return
			}
			pubPath := outPath + ".pub"
			if err := os.WriteFile(pubPath, kp.PublicKey, 0644); err != nil {
				log.SetText(fmt.Sprintf("ERROR: %v", err))
				return
			}
			log.SetText(fmt.Sprintf(
				"Private key: %s (%d bytes) [seed-based]\nPublic key:  %s (%d bytes)\n\nEncrypt:  kryp encrypt --algorithm %s --key-file %s\nDecrypt:  kryp decrypt --key-file %s",
				outPath, len(kp.PrivateSeed), pubPath, len(kp.PublicKey), algoID.String(), pubPath, outPath))
			if targetEntry != nil {
				targetEntry.SetText(outPath)
			}
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
			if err := os.WriteFile(recipPath, recipData, 0644); err != nil {
				log.SetText(fmt.Sprintf("ERROR: %v", err))
				return
			}

			log.SetText(fmt.Sprintf(
				"Age Identity: %s\nAge Recipient: %s\n\nRecipient key: %s\n\nEncrypt:  kryp encrypt --algorithm age --age-recipient \"%s\"\nDecrypt:  kryp decrypt --key-file %s",
				outPath, recipPath, identity.Recipient().String(), identity.Recipient().String(), outPath))

			if targetEntry != nil {
				targetEntry.SetText(outPath)
			}
			return

		case crypto.AlgoMLKEM768, crypto.AlgoMLKEM1024, crypto.AlgoHybridXWing, crypto.AlgoHPKE, crypto.AlgoHQC128, crypto.AlgoFrodo640SHAKE:
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

	extractBtn := widget.NewButton("Extract Public Key from Private Key", func() {
		dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			privPath := reader.URI().Path()
			reader.Close()
			go func() {
				kp, err := crypto.ExtractPublicKey(privPath)
				if err != nil {
					fyne.Do(func() {
						log.SetText(fmt.Sprintf("ERROR: %v", err))
					})
					return
				}
				pubPath := privPath + ".pub"
				err = os.WriteFile(pubPath, kp.PublicKey, 0644)
				if err != nil {
					fyne.Do(func() {
						log.SetText(fmt.Sprintf("ERROR: %v", err))
					})
					return
				}
				fyne.Do(func() {
					log.SetText(fmt.Sprintf("Public key extracted: %s\nAlgorithm: %s\nSize: %d bytes", pubPath, kp.Algorithm.String(), len(kp.PublicKey)))
				})
			}()
		}, g.window).Show()
	})

	content := container.NewVBox(
		widget.NewCard("Algorithm", "", algoSelect),
		widget.NewCard("Output Path", "", container.NewBorder(nil, nil, nil, browseBtn, pathEntry)),
		widget.NewCard("Seed File (optional)", "", container.NewBorder(nil, nil, nil, browseSeedBtn, seedEntry)),
		genBtn,
		extractBtn,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Result", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		log,
	)

	d = dialog.NewCustom("Generate Key", "Close", container.NewPadded(content), g.window)
	d.Resize(fyne.NewSize(500, 500))
	d.Show()
}
