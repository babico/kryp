package store

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const defaultRcloneTimeout = 30 * time.Minute

type RcloneUploader struct {
	Binary      string
	RemotePath  string
	Incremental bool
	ExtraArgs   string
}

func NewRcloneUploader(binary, remotePath string, incremental bool, extraArgs string) *RcloneUploader {
	return &RcloneUploader{
		Binary:      binary,
		RemotePath:  remotePath,
		Incremental: incremental,
		ExtraArgs:   extraArgs,
	}
}

func (r *RcloneUploader) Upload(localPath string) error {
	if _, err := os.Stat(r.Binary); os.IsNotExist(err) {
		path, err := exec.LookPath(r.Binary)
		if err != nil {
			return fmt.Errorf("rclone not found in PATH or at %s: %w", r.Binary, err)
		}
		r.Binary = path
	}

	if r.Incremental {
		return r.sync(localPath)
	}
	return r.copy(localPath)
}

func (r *RcloneUploader) sync(localPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultRcloneTimeout)
	defer cancel()

	args := []string{"sync", localPath, r.RemotePath}
	if r.ExtraArgs != "" {
		args = append(args, splitArgs(r.ExtraArgs)...)
	}

	cmd := exec.CommandContext(ctx, r.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("[rclone] syncing %s → %s\n", localPath, r.RemotePath)
	return cmd.Run()
}

func (r *RcloneUploader) copy(localPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultRcloneTimeout)
	defer cancel()

	args := []string{"copy", localPath, r.RemotePath}
	if r.ExtraArgs != "" {
		args = append(args, splitArgs(r.ExtraArgs)...)
	}

	cmd := exec.CommandContext(ctx, r.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("[rclone] copying %s → %s\n", localPath, r.RemotePath)
	return cmd.Run()
}

func (r *RcloneUploader) ListRemote() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultRcloneTimeout)
	defer cancel()

	args := []string{"ls", r.RemotePath}
	cmd := exec.CommandContext(ctx, r.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *RcloneUploader) Check() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.Binary, "version")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("rclone not available: %w", err)
	}
	fmt.Printf("[rclone] %s", out)
	return nil
}

func splitArgs(args string) []string {
	result := make([]string, 0)
	current := ""
	inQuote := false
	for _, c := range args {
		if c == '"' || c == '\'' {
			inQuote = !inQuote
			continue
		}
		if c == ' ' && !inQuote {
			if current != "" {
				result = append(result, current)
				current = ""
			}
			continue
		}
		current += string(c)
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
