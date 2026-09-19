package backup

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/underhax/mihomo-warp-proxy/internal/fsutil"
)

func TestConfigFileNonExistent(t *testing.T) {
	dir := t.TempDir()
	err := ConfigFile(filepath.Join(dir, "nonexistent.yaml"))
	if err != nil {
		t.Errorf("missing source file should not error, got: %v", err)
	}
}

func TestConfigFileEmpty(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(src, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ConfigFile(src); err != nil {
		t.Errorf("empty source file should not error, got: %v", err)
	}

	if _, err := os.Stat(src + ".back"); !os.IsNotExist(err) {
		t.Error("backup file should not exist for empty source")
	}
}

func TestConfigFileCreatesBackup(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "config.yaml")
	content := []byte("mode: rule\nmixed-port: 7890\n")

	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ConfigFile(src); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	back := src + ".back"
	got, err := os.ReadFile(filepath.Clean(back))
	if err != nil {
		t.Fatalf("backup file not created: %v", err)
	}

	if !bytes.Equal(got, content) {
		t.Errorf("backup content mismatch: got %q, want %q", got, content)
	}
}

func TestConfigFileBackupPermissions(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(src, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ConfigFile(src); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, err := os.Stat(src + ".back")
	if err != nil {
		t.Fatalf("backup file not found: %v", err)
	}

	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("backup file permissions: got %04o, want 0o600", perm)
	}
}

func TestConfigFileOverwritesExistingBackup(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "config.yaml")
	back := src + ".back"

	oldContent := []byte("old content")
	newContent := []byte("new content")

	if err := os.WriteFile(back, oldContent, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(src, newContent, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ConfigFile(src); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(back))
	if err != nil {
		t.Fatalf("backup file not found: %v", err)
	}

	if !bytes.Equal(got, newContent) {
		t.Errorf("backup not updated: got %q, want %q", got, newContent)
	}
}

func TestConfigFileSymlink(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real_config.yaml")
	link := filepath.Join(dir, "config.yaml")
	content := []byte("real content via symlink")

	if err := os.WriteFile(realFile, content, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(realFile, link); err != nil {
		t.Fatal(err)
	}

	if err := ConfigFile(link); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	back := realFile + ".back"
	got, err := os.ReadFile(filepath.Clean(back))
	if err != nil {
		t.Fatalf("backup file not created: %v", err)
	}

	if !bytes.Equal(got, content) {
		t.Errorf("symlink backup content mismatch: got %q, want %q", got, content)
	}

	info, err := os.Lstat(back)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error("backup file must not be a symlink")
	}
}

func TestConfigFileSourceNotRegular(t *testing.T) {
	dir := t.TempDir()
	err := ConfigFile(dir)
	if err == nil {
		t.Error("expected error for directory source, got nil")
	}
}

func TestIsDirWritable(t *testing.T) {
	dir := t.TempDir()
	if !fsutil.IsDirWritable(dir) {
		t.Error("temp dir should be writable")
	}

	if fsutil.IsDirWritable("/proc/1") {
		t.Error("/proc/1 should not be writable")
	}
}

func TestConfigFileErrors(t *testing.T) {
	if err := ConfigFile("relative.yaml"); err == nil {
		t.Error("expected error for relative path, got nil")
	}

	if err := ConfigFile("/nonexistent_dir_12345/file.yaml"); err == nil {
		t.Error("expected error for unwritable parent dir, got nil")
	}

	dir := t.TempDir()
	largeFile := filepath.Join(dir, "large.yaml")
	oversized := make([]byte, maxBackupSize+10)
	if err := os.WriteFile(largeFile, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ConfigFile(largeFile); err == nil {
		t.Error("expected error for file exceeding maxBackupSize, got nil")
	}
}

func TestConfigFileSymlinkLoop(t *testing.T) {
	dir := t.TempDir()
	linkA := filepath.Join(dir, "linkA")
	linkB := filepath.Join(dir, "linkB")
	if err := os.Symlink(linkB, linkA); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(linkA, linkB); err != nil {
		t.Fatal(err)
	}
	if err := ConfigFile(linkA); err == nil {
		t.Error("expected error for symlink loop, got nil")
	}
}

func TestAtomicCopyOpenPermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "no_read.yaml")
	if err := os.WriteFile(src, []byte("data"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(src, 0o600); err != nil {
			t.Log(err)
		}
	})

	err := atomicCopy(src, filepath.Join(dir, "out.yaml"))
	if err == nil {
		t.Error("expected error opening unreadable file, got nil")
	}
}

func TestAtomicCopyDstWriteError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "valid.yaml")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := atomicCopy(src, "/nonexistent_dir_99999/out.yaml")
	if err == nil {
		t.Error("expected error writing to invalid dst, got nil")
	}
}

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, errors.New("mock read error")
}

func TestDefaultFileOperations(t *testing.T) {
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "backup-ops-*")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := defaultFileStat(f); err != nil {
		t.Errorf("expected success from defaultFileStat, got: %v", err)
	}
	if _, err := defaultFileReadAll(strings.NewReader("content")); err != nil {
		t.Errorf("expected success from defaultFileReadAll, got: %v", err)
	}
	if _, err := defaultFileReadAll(errReader{}); err == nil {
		t.Error("expected error from defaultFileReadAll on errReader, got nil")
	}

	if err := f.Close(); err != nil {
		t.Log(err)
	}

	if err := defaultFileClose(f); err == nil {
		t.Error("expected error closing already closed file")
	}
	if _, err := defaultFileStat(f); err == nil {
		t.Error("expected error statting already closed file")
	}
}

func TestAtomicCopyCloseError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "close_err.yaml")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	origClose := fileClose
	defer func() { fileClose = origClose }()
	fileClose = func(_ *os.File) error {
		return errors.New("mock close error")
	}

	if err := atomicCopy(src, filepath.Join(dir, "out.yaml")); err == nil {
		t.Error("expected error when fileClose fails, got nil")
	}
}

func TestAtomicCopyStatError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "stat_err.yaml")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	origStat := fileStat
	defer func() { fileStat = origStat }()
	fileStat = func(_ *os.File) (os.FileInfo, error) {
		return nil, errors.New("mock stat error")
	}

	if err := atomicCopy(src, filepath.Join(dir, "out.yaml")); err == nil {
		t.Error("expected error when fileStat fails, got nil")
	}
}

func TestAtomicCopyReadAllError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "read_err.yaml")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	origRead := fileReadAll
	defer func() { fileReadAll = origRead }()
	fileReadAll = func(_ io.Reader) ([]byte, error) {
		return nil, errors.New("mock read error")
	}

	if err := atomicCopy(src, filepath.Join(dir, "out.yaml")); err == nil {
		t.Error("expected error when fileReadAll fails, got nil")
	}
}
