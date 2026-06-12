package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptCompatibleNoHeader(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.bin")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}

	opts := &EncryptFileOptions{
		Algorithm:  AlgoAES256GCM,
		KeyFile:    keyPath,
		Compatible: true,
	}

	data := []byte("test data for compatible mode")
	result, err := EncryptFileBytes(data, opts)
	if err != nil {
		t.Fatal(err)
	}

	if len(result) >= 4 && string(result[:4]) == "ENCR" {
		t.Error("compatible output should not have ENCR header")
	}

	nonceSize := 12
	if len(result) <= nonceSize {
		t.Fatal("result too short")
	}

	nonce := result[:nonceSize]
	ct := result[nonceSize:]

	enc, err := GetEncryptor(AlgoAES256GCM)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := enc.Decrypt(ct, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(data) {
		t.Errorf("decrypted content mismatch: got %q, want %q", string(decrypted), string(data))
	}
}

func TestEncryptCompatibleIncompatibleFlags(t *testing.T) {
	opts := &EncryptFileOptions{
		Algorithm:     AlgoAES256GCM,
		Compatible:    true,
		EmbedMetadata: true,
	}
	_, err := EncryptFileBytes([]byte("data"), opts)
	if err == nil {
		t.Error("expected error for --compatible with --embed-metadata")
	}

	opts2 := &EncryptFileOptions{
		Algorithm:  AlgoAES256GCM,
		Compatible: true,
		UUIDRename: true,
	}
	_, err = EncryptFileBytes([]byte("data"), opts2)
	if err == nil {
		t.Error("expected error for --compatible with --uuid-rename")
	}
}
