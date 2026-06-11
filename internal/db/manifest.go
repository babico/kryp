package db

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

type FileEntry struct {
	UUID         string `json:"uuid"`
	OriginalPath string `json:"original_path"`
	OriginalName string `json:"original_name"`
	Size         int64  `json:"size"`
	ModTime      int64  `json:"mod_time"`
	EncryptedSize int64 `json:"encrypted_size"`
	Algorithm    string `json:"algorithm"`
}

type Manifest struct {
	mu           sync.RWMutex
	Version      string       `json:"version"`
	CreatedAt    string       `json:"created_at"`
	Files        []*FileEntry `json:"files"`
	fileIndex    map[string]*FileEntry
	uuidIndex    map[string]*FileEntry
}

func NewManifest() *Manifest {
	return &Manifest{
		Version:   "1",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Files:     make([]*FileEntry, 0),
		fileIndex: make(map[string]*FileEntry),
		uuidIndex: make(map[string]*FileEntry),
	}
}

func (m *Manifest) AddFile(originalPath, originalName string, size, encryptedSize int64, algorithm string) *FileEntry {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := uuid.New().String()
	entry := &FileEntry{
		UUID:          id,
		OriginalPath:  originalPath,
		OriginalName:  originalName,
		Size:          size,
		ModTime:       time.Now().Unix(),
		EncryptedSize: encryptedSize,
		Algorithm:     algorithm,
	}

	m.Files = append(m.Files, entry)
	m.fileIndex[originalPath] = entry
	m.uuidIndex[id] = entry
	return entry
}

func (m *Manifest) GetByUUID(uuid string) *FileEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.uuidIndex[uuid]
}

func (m *Manifest) GetByOriginalPath(path string) *FileEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.fileIndex[path]
}

func (m *Manifest) ListFiles() []*FileEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*FileEntry, len(m.Files))
	copy(result, m.Files)
	return result
}

func (m *Manifest) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.Files)
}

func (m *Manifest) Serialize() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return json.MarshalIndent(m, "", "  ")
}

func DeserializeManifest(data []byte) (*Manifest, error) {
	m := &Manifest{
		fileIndex: make(map[string]*FileEntry),
		uuidIndex: make(map[string]*FileEntry),
	}

	err := json.Unmarshal(data, m)
	if err != nil {
		return nil, err
	}

	for _, entry := range m.Files {
		m.fileIndex[entry.OriginalPath] = entry
		m.uuidIndex[entry.UUID] = entry
	}

	if m.CreatedAt == "" {
		m.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}

	return m, nil
}

func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DeserializeManifest(data)
}

func SaveManifest(path string, m *Manifest) error {
	data, err := m.Serialize()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
