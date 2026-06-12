package main

import (
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) Set(v bool) {
	b.mu.Lock()
	b.v = v
	b.mu.Unlock()
}

func (b *atomicBool) Get() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.v
}

type logList struct {
	lines      []string
	scroll     *container.Scroll
	list       *widget.List
	mu         sync.Mutex
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
	ll.mu.Lock()
	ll.lines = append(ll.lines, "["+ts+"] "+msg)
	ll.mu.Unlock()
	ll.list.Refresh()
}

func (ll *logList) CanvasObject() fyne.CanvasObject {
	return ll.scroll
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
	g.encryptRunning.Set(running)
}

func (g *guiApp) setDecryptRunning(running bool) {
	g.decryptRunning.Set(running)
}


