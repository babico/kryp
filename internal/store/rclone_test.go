package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewRcloneUploader(t *testing.T) {
	r := NewRcloneUploader("rclone", "myremote:path", true, "-v --progress")
	if r.Binary != "rclone" {
		t.Errorf("Binary = %q, want rclone", r.Binary)
	}
	if r.RemotePath != "myremote:path" {
		t.Errorf("RemotePath = %q", r.RemotePath)
	}
	if r.Incremental != true {
		t.Error("Incremental should be true")
	}
	if r.ExtraArgs != "-v --progress" {
		t.Errorf("ExtraArgs = %q", r.ExtraArgs)
	}
}

func TestNewRcloneUploaderDefaults(t *testing.T) {
	r := NewRcloneUploader("", "", false, "")
	if r.Binary != "" {
		t.Errorf("Binary = %q, want empty", r.Binary)
	}
	if r.Incremental != false {
		t.Error("Incremental should be false")
	}
}

func TestSplitArgsEmpty(t *testing.T) {
	result := splitArgs("")
	if len(result) != 0 {
		t.Errorf("expected empty, got %v", result)
	}
}

func TestSplitArgsSingle(t *testing.T) {
	result := splitArgs("-v")
	if len(result) != 1 || result[0] != "-v" {
		t.Errorf("got %v, want [-v]", result)
	}
}

func TestSplitArgsMultiple(t *testing.T) {
	result := splitArgs("-v --progress --checksum")
	expected := []string{"-v", "--progress", "--checksum"}
	if len(result) != len(expected) {
		t.Fatalf("got %v, want %v", result, expected)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("arg[%d] = %q, want %q", i, result[i], expected[i])
		}
	}
}

func TestSplitArgsWithQuotes(t *testing.T) {
	result := splitArgs(`--exclude "*.txt" --include "*.go"`)
	expected := []string{"--exclude", "*.txt", "--include", "*.go"}
	if len(result) != len(expected) {
		t.Fatalf("got %v, want %v", result, expected)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("arg[%d] = %q, want %q", i, result[i], expected[i])
		}
	}
}

func TestSplitArgsWithSingleQuotes(t *testing.T) {
	result := splitArgs(`--filter '*.log'`)
	expected := []string{"--filter", "*.log"}
	if len(result) != len(expected) {
		t.Fatalf("got %v, want %v", result, expected)
	}
	if result[0] != "--filter" || result[1] != "*.log" {
		t.Errorf("got %v, want %v", result, expected)
	}
}

func TestSplitArgsLeadingTrailingSpaces(t *testing.T) {
	result := splitArgs("  --verbose  --progress  ")
	expected := []string{"--verbose", "--progress"}
	if len(result) != len(expected) {
		t.Fatalf("got %v, want %v", result, expected)
	}
}

func TestUploadBinaryNotFound(t *testing.T) {
	r := NewRcloneUploader("/nonexistent/rclone-binary", "remote:path", false, "")
	err := r.Upload("/tmp")
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}
}

func TestUploadLocalPathNotExists(t *testing.T) {
	r := NewRcloneUploader("rclone", "remote:path", false, "")
	err := r.Upload("/nonexistent-path-12345")
	if err == nil {
		t.Fatal("expected error for nonexistent local path")
	}
}

func TestCheckBinaryNotFound(t *testing.T) {
	r := NewRcloneUploader("/nonexistent/rclone-binary", "", false, "")
	err := r.Check()
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}
}

func TestListRemoteBinaryNotFound(t *testing.T) {
	r := NewRcloneUploader("/nonexistent/rclone-binary", "remote:path", false, "")
	err := r.ListRemote()
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}
}

func TestSplitArgsMixed(t *testing.T) {
	result := splitArgs(`-v --exclude="*.log" --progress`)
	expected := []string{"-v", `--exclude=*.log`, "--progress"}
	if len(result) != len(expected) {
		t.Fatalf("got %v, want %v", result, expected)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("arg[%d] = %q, want %q", i, result[i], expected[i])
		}
	}
}

func TestUploaderStringValues(t *testing.T) {
	r := NewRcloneUploader("rclone", "myremote:backups/encrypted", true, "-v --checksum")

	if r.Binary != "rclone" {
		t.Errorf("Binary = %q", r.Binary)
	}
	if r.RemotePath != "myremote:backups/encrypted" {
		t.Errorf("RemotePath = %q", r.RemotePath)
	}
}

func TestUploaderWithNonExistentLocalPath(t *testing.T) {
	dir := t.TempDir()
	r := NewRcloneUploader("rclone", "remote:path", false, "")

	err := r.Upload(filepath.Join(dir, "nonexistent-folder"))
	if err == nil {
		t.Fatal("expected error for nonexistent local path")
	}
}

func TestUploaderStatOnBinary(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "rclone.sh")
	os.WriteFile(binaryPath, []byte("#!/bin/sh\necho mock"), 0755)

	r := NewRcloneUploader(binaryPath, "remote:path", false, "")
	err := r.Upload("/tmp")
	if err != nil {
		t.Logf("expected mock binary may fail to exec: %v", err)
	}
}
