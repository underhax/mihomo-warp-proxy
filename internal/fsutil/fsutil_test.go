package fsutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test_write.txt")
	data := []byte("hello world")

	if err := AtomicWrite(file, data, 0o600); err != nil {
		t.Fatalf("AtomicWrite failed: %v", err)
	}

	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("Got permissions %v, want 0o600", info.Mode().Perm())
	}

	got, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		t.Fatalf("Failed to read written file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("Got %q, want %q", got, data)
	}
}

func TestAtomicWriteError(t *testing.T) {
	dir := t.TempDir()
	nonExistentDirFile := filepath.Join(dir, "sub", "test.txt")
	if err := AtomicWrite(nonExistentDirFile, []byte("data"), 0o600); err == nil {
		t.Error("expected error for non-existent directory, got nil")
	}

	existingDir := filepath.Join(dir, "target_is_dir")
	if err := os.Mkdir(existingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(existingDir, []byte("data"), 0o600); err == nil {
		t.Error("expected error when destination is a directory, got nil")
	}
}

func TestIsDirWritable(t *testing.T) {
	dir := t.TempDir()
	if !IsDirWritable(dir) {
		t.Errorf("expected temp dir %s to be writable", dir)
	}

	nonExistent := filepath.Join(dir, "nonexistent")
	if IsDirWritable(nonExistent) {
		t.Errorf("expected non-existent dir %s to not be writable", nonExistent)
	}

	regularFile := filepath.Join(dir, "not_a_dir")
	if err := os.WriteFile(regularFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if IsDirWritable(regularFile) {
		t.Errorf("expected regular file path %s to not be writable as dir", regularFile)
	}
}

func TestAtomicFinishAlreadyClosed(t *testing.T) {
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "finish_*")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	if closeErr := f.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	t.Cleanup(func() {
		if remErr := os.Remove(name); remErr != nil && !os.IsNotExist(remErr) {
			t.Log(remErr)
		}
	})

	err = atomicFinish(f, name, filepath.Join(dir, "dst"))
	if err == nil {
		t.Error("expected error from atomicFinish on closed file, got nil")
	}
}

func TestCreateAtomicTempUnwritableDir(t *testing.T) {
	_, _, err := createAtomicTemp("/proc/nonexistent_1234/test.txt", 0o600)
	if err == nil {
		t.Error("expected error creating temp in unwritable dir, got nil")
	}
}

func TestDefaultTempFileOperations(t *testing.T) {
	tempFile, err := os.CreateTemp(t.TempDir(), "fsutil-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	if err := defaultTempFileSync(tempFile); err != nil {
		t.Errorf("expected success syncing temp file, got: %v", err)
	}
	if err := defaultTempFileChmod(tempFile, 0o600); err != nil {
		t.Errorf("expected success chmoding temp file, got: %v", err)
	}
	if n, err := defaultTempFileWrite(tempFile, []byte("ok")); err != nil || n != 2 {
		t.Errorf("expected success writing temp file, got n=%d, err=%v", n, err)
	}

	if err := tempFile.Close(); err != nil {
		t.Logf("temp file close: %v", err)
	}

	if err := defaultTempFileClose(tempFile); err == nil {
		t.Error("expected error closing already closed file")
	}
	if err := defaultTempFileSync(tempFile); err == nil {
		t.Error("expected error syncing already closed file")
	}
	if err := defaultTempFileChmod(tempFile, 0o600); err == nil {
		t.Error("expected error chmoding already closed file")
	}
	if _, err := defaultTempFileWrite(tempFile, []byte("fail")); err == nil {
		t.Error("expected error writing to closed file")
	}
}

func TestAtomicFinishCloseAndRenameErrors(t *testing.T) {
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "finish-err-*")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	t.Cleanup(func() {
		if cErr := f.Close(); cErr != nil {
			t.Log(cErr)
		}
		if rErr := os.Remove(name); rErr != nil {
			t.Log(rErr)
		}
	})

	origClose := tempFileClose
	origRename := osRename
	defer func() {
		tempFileClose = origClose
		osRename = origRename
	}()

	tempFileClose = func(_ *os.File) error {
		return errors.New("mock close error")
	}
	if err := atomicFinish(f, name, filepath.Join(dir, "dst")); err == nil {
		t.Error("expected error when tempFileClose fails, got nil")
	}

	tempFileClose = origClose
	osRename = func(_, _ string) error {
		return errors.New("mock rename error")
	}
	if err := atomicFinish(f, name, filepath.Join(dir, "dst")); err == nil {
		t.Error("expected error when osRename fails, got nil")
	}
}

func TestCreateAtomicTempChmodError(t *testing.T) {
	origChmod := tempFileChmod
	defer func() { tempFileChmod = origChmod }()

	tempFileChmod = func(_ *os.File, _ os.FileMode) error {
		return errors.New("mock chmod error")
	}

	dir := t.TempDir()
	_, _, err := createAtomicTemp(filepath.Join(dir, "out.txt"), 0o600)
	if err == nil {
		t.Error("expected error when chmod fails, got nil")
	}
}

func TestAtomicWriteErrorsAndCleanup(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "atomic_err.txt")

	origWrite := tempFileWrite
	origClose := tempFileClose
	origRemove := osRemove
	defer func() {
		tempFileWrite = origWrite
		tempFileClose = origClose
		osRemove = origRemove
	}()

	tempFileWrite = func(_ *os.File, _ []byte) (int, error) {
		return 0, errors.New("mock write failure")
	}
	tempFileClose = func(_ *os.File) error {
		return errors.New("mock defer close failure")
	}
	osRemove = func(_ string) error {
		return errors.New("mock defer remove failure")
	}

	if err := AtomicWrite(target, []byte("data"), 0o600); err == nil {
		t.Error("expected error from AtomicWrite on write failure, got nil")
	}
}

func TestIsDirWritableCloseAndRemoveErrors(t *testing.T) {
	dir := t.TempDir()

	origClose := tempFileClose
	origRemove := osRemove
	defer func() {
		tempFileClose = origClose
		osRemove = origRemove
	}()

	tempFileClose = func(_ *os.File) error {
		return errors.New("mock close error")
	}
	if IsDirWritable(dir) {
		t.Error("expected false when tempFileClose fails")
	}

	tempFileClose = origClose
	osRemove = func(_ string) error {
		return errors.New("mock remove error")
	}
	if IsDirWritable(dir) {
		t.Error("expected false when osRemove fails")
	}
}
