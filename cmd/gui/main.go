package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

var Version = "1.1.1"

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

	argon2TimeEntry     *widget.Entry
	argon2MemoryEntry   *widget.Entry
	argon2ThreadsEntry  *widget.Entry
	scryptNEntry        *widget.Entry
	scryptREntry        *widget.Entry
	scryptPEntry        *widget.Entry
	pbkdf2IterEntry     *widget.Entry

	decryptSourceEntry     *widget.Entry
	decryptOutputEntry     *widget.Entry
	decryptPassphraseEntry *widget.Entry
	decryptKeyFileEntry    *widget.Entry
	keepPathCheck   *widget.Check
	decryptLog      *logList

	encryptFiles      []string
	encryptFileList   *widget.List
	compatCheck       *widget.Check
	decryptFiles      []string
	decryptFileList   *widget.List

	encryptProgress  *widget.ProgressBarInfinite
	decryptProgress  *widget.ProgressBarInfinite
	encryptRunning   *atomicBool
	decryptRunning   *atomicBool
}

func main() {
	a := app.NewWithID("com.babico.kryp")
	w := a.NewWindow("Kryp - File Encryption")

	g := &guiApp{window: w, encryptRunning: &atomicBool{}, decryptRunning: &atomicBool{}}

	tabs := container.NewAppTabs(
		container.NewTabItem("Encrypt", g.makeEncryptTab()),
		container.NewTabItem("Decrypt", g.makeDecryptTab()),
		container.NewTabItem("Settings", g.makeSettingsTab()),
	)

	w.SetContent(tabs)
	w.Resize(fyne.NewSize(1200, 800))
	w.ShowAndRun()
}
