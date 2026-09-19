// Package fsutil provides atomic filesystem operations to ensure file
// integrity during writes and updates.
package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func defaultTempFileClose(f *os.File) error {
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	return nil
}

func defaultTempFileSync(f *os.File) error {
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	return nil
}

func defaultTempFileChmod(f *os.File, perm os.FileMode) error {
	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	return nil
}

func defaultTempFileWrite(f *os.File, b []byte) (int, error) {
	n, err := f.Write(b)
	if err != nil {
		return n, fmt.Errorf("write data: %w", err)
	}
	return n, nil
}

var (
	osRename      = os.Rename
	osRemove      = os.Remove
	osCreateTemp  = os.CreateTemp
	tempFileClose = defaultTempFileClose
	tempFileSync  = defaultTempFileSync
	tempFileChmod = defaultTempFileChmod
	tempFileWrite = defaultTempFileWrite
)

func atomicFinish(f *os.File, tmpName, dst string) error {
	if err := tempFileSync(f); err != nil {
		return err
	}
	if err := tempFileClose(f); err != nil {
		return err
	}
	if err := osRename(tmpName, dst); err != nil {
		return fmt.Errorf("rename to destination: %w", err)
	}
	return nil
}

func createAtomicTemp(dst string, perm os.FileMode) (*os.File, string, error) {
	dir := filepath.Dir(dst)
	f, err := osCreateTemp(dir, filepath.Base(dst)+".*")
	if err != nil {
		return nil, "", fmt.Errorf("create temp file: %w", err)
	}
	tmpName := f.Name()
	if err := tempFileChmod(f, perm); err != nil {
		closeErr := tempFileClose(f)
		removeErr := osRemove(tmpName)
		return nil, "", errors.Join(err, closeErr, removeErr)
	}
	return f, tmpName, nil
}

// AtomicWrite writes data to filename atomically.
func AtomicWrite(filename string, data []byte, perm os.FileMode) (retErr error) {
	f, tmpName, err := createAtomicTemp(filename, perm)
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			closeErr := tempFileClose(f)
			removeErr := osRemove(tmpName)
			retErr = errors.Join(retErr, closeErr, removeErr)
		}
	}()

	if _, writeErr := tempFileWrite(f, data); writeErr != nil {
		return writeErr
	}
	if finishErr := atomicFinish(f, tmpName, filename); finishErr != nil {
		return finishErr
	}
	done = true
	return nil
}

// IsDirWritable probes write access to dir by attempting to create and
// immediately remove a temporary file.
func IsDirWritable(dir string) bool {
	f, err := osCreateTemp(dir, ".write_probe_*.tmp")
	if err != nil {
		return false
	}
	name := f.Name()
	closeErr := tempFileClose(f)
	removeErr := osRemove(name)
	return closeErr == nil && removeErr == nil
}
