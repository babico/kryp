package db

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewManifest(t *testing.T) {
	m := NewManifest()
	if m == nil {
		t.Fatal("NewManifest returned nil")
	}
	if m.Version != "1" {
		t.Errorf("Version = %q, want %q", m.Version, "1")
	}
	if m.CreatedAt == "" {
		t.Error("CreatedAt should not be empty")
	}
	if len(m.Files) != 0 {
		t.Errorf("Files should be empty, got %d", len(m.Files))
	}
}

func TestAddFile(t *testing.T) {
	m := NewManifest()
	entry := m.AddFile("path/to/file.txt", "file.txt", 1024, 2048, "XChaCha20-Poly1305")

	if entry == nil {
		t.Fatal("AddFile returned nil")
	}
	if entry.UUID == "" {
		t.Error("UUID should not be empty")
	}
	if entry.OriginalPath != "path/to/file.txt" {
		t.Errorf("OriginalPath = %q, want %q", entry.OriginalPath, "path/to/file.txt")
	}
	if entry.OriginalName != "file.txt" {
		t.Errorf("OriginalName = %q, want %q", entry.OriginalName, "file.txt")
	}
	if entry.Size != 1024 {
		t.Errorf("Size = %d, want %d", entry.Size, 1024)
	}
	if entry.EncryptedSize != 2048 {
		t.Errorf("EncryptedSize = %d, want %d", entry.EncryptedSize, 2048)
	}
	if entry.Algorithm != "XChaCha20-Poly1305" {
		t.Errorf("Algorithm = %q, want %q", entry.Algorithm, "XChaCha20-Poly1305")
	}
	if m.Count() != 1 {
		t.Errorf("Count = %d, want %d", m.Count(), 1)
	}
}

func TestAddMultipleFiles(t *testing.T) {
	m := NewManifest()
	m.AddFile("file1.txt", "file1.txt", 100, 200, "AES-256-GCM")
	m.AddFile("file2.txt", "file2.txt", 200, 400, "AES-256-GCM")
	m.AddFile("file3.txt", "file3.txt", 300, 600, "AES-256-GCM")

	if m.Count() != 3 {
		t.Errorf("Count = %d, want %d", m.Count(), 3)
	}
}

func TestGetByUUID(t *testing.T) {
	m := NewManifest()
	added := m.AddFile("test.txt", "test.txt", 100, 200, "ChaCha20-Poly1305")

	found := m.GetByUUID(added.UUID)
	if found == nil {
		t.Fatal("GetByUUID returned nil")
	}
	if found.OriginalName != "test.txt" {
		t.Errorf("OriginalName = %q, want %q", found.OriginalName, "test.txt")
	}

	notFound := m.GetByUUID("non-existent-uuid")
	if notFound != nil {
		t.Error("GetByUUID should return nil for non-existent UUID")
	}
}

func TestGetByOriginalPath(t *testing.T) {
	m := NewManifest()
	m.AddFile("path/to/doc.txt", "doc.txt", 100, 200, "AES-256-CTR+HMAC")

	found := m.GetByOriginalPath("path/to/doc.txt")
	if found == nil {
		t.Fatal("GetByOriginalPath returned nil")
	}
	if found.OriginalName != "doc.txt" {
		t.Errorf("OriginalName = %q, want %q", found.OriginalName, "doc.txt")
	}

	notFound := m.GetByOriginalPath("non-existent-path")
	if notFound != nil {
		t.Error("GetByOriginalPath should return nil for non-existent path")
	}
}

func TestListFiles(t *testing.T) {
	m := NewManifest()
	m.AddFile("a.txt", "a.txt", 10, 20, "AES-256-GCM")
	m.AddFile("b.txt", "b.txt", 20, 40, "AES-256-GCM")

	files := m.ListFiles()
	if len(files) != 2 {
		t.Fatalf("ListFiles returned %d files, want 2", len(files))
	}
}

func TestSerializeDeserialize(t *testing.T) {
	m := NewManifest()
	m.AddFile("confidential.doc", "confidential.doc", 50000, 100000, "XChaCha20-Poly1305")
	m.AddFile("secret.pdf", "secret.pdf", 100000, 200000, "AES-256-GCM")

	data, err := m.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("Serialize returned empty data")
	}

	restored, err := DeserializeManifest(data)
	if err != nil {
		t.Fatalf("DeserializeManifest failed: %v", err)
	}

	if restored.Count() != 2 {
		t.Errorf("restored count = %d, want %d", restored.Count(), 2)
	}

	originalFile := m.ListFiles()[0]
	restoredFile := restored.GetByUUID(originalFile.UUID)
	if restoredFile == nil {
		t.Fatal("restored file not found by UUID")
	}
	if restoredFile.OriginalName != originalFile.OriginalName {
		t.Errorf("OriginalName = %q, want %q", restoredFile.OriginalName, originalFile.OriginalName)
	}
	if restoredFile.Algorithm != originalFile.Algorithm {
		t.Errorf("Algorithm = %q, want %q", restoredFile.Algorithm, originalFile.Algorithm)
	}
}

func TestSerializeDeserializeEmpty(t *testing.T) {
	m := NewManifest()
	data, err := m.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	restored, err := DeserializeManifest(data)
	if err != nil {
		t.Fatalf("DeserializeManifest failed: %v", err)
	}

	if restored.Count() != 0 {
		t.Errorf("restored count = %d, want 0", restored.Count())
	}
}

func TestSaveLoadManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	m := NewManifest()
	m.AddFile("data.bin", "data.bin", 999, 1998, "SecretBox")

	err := SaveManifest(path, m)
	if err != nil {
		t.Fatalf("SaveManifest failed: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("manifest file was not created")
	}

	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest failed: %v", err)
	}

	if loaded.Count() != 1 {
		t.Errorf("loaded count = %d, want %d", loaded.Count(), 1)
	}

	original := m.ListFiles()[0]
	loadedFile := loaded.GetByUUID(original.UUID)
	if loadedFile == nil {
		t.Fatal("loaded file not found by UUID")
	}
	if loadedFile.OriginalName != "data.bin" {
		t.Errorf("loaded OriginalName = %q, want %q", loadedFile.OriginalName, "data.bin")
	}
}

func TestConcurrentAccess(t *testing.T) {
	m := NewManifest()

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			m.AddFile(
				filepath.Join("path", "file.txt"),
				"file.txt",
				int64(idx*100),
				int64(idx*200),
				"AES-256-GCM",
			)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if m.Count() != 10 {
		t.Errorf("expected 10 files, got %d", m.Count())
	}
}

func TestManifestJsonFormat(t *testing.T) {
	m := NewManifest()
	m.AddFile("test.bin", "test.bin", 1000, 2000, "ChaCha20-Poly1305")

	data, err := m.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	dataStr := string(data)

	// Verify it's valid JSON with expected fields
	if !containsStr(dataStr, `"version"`) {
		t.Error("missing version field")
	}
	if !containsStr(dataStr, `"files"`) {
		t.Error("missing files field")
	}
	if !containsStr(dataStr, `"uuid"`) {
		t.Error("missing uuid field in file entry")
	}
	if !containsStr(dataStr, `"original_name"`) {
		t.Error("missing original_name field")
	}
	if !containsStr(dataStr, `"algorithm"`) {
		t.Error("missing algorithm field")
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
