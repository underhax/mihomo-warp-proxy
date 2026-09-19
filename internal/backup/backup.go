// Package backup provides atomic backup of the mihomo config file.
// A backup is created before any mutation so that a failed config update
// never leaves the user without a recoverable previous state.
package backup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/underhax/mihomo-warp-proxy/internal/fsutil"
	"github.com/underhax/mihomo-warp-proxy/internal/validate"
)

const maxBackupSize = 1024 * 1024

// ConfigFile atomically copies src to src+".back" if src exists, is non-empty,
// and its parent directory is writable by the current process.
func ConfigFile(src string) error {
	if resolved, err := filepath.EvalSymlinks(src); err == nil {
		src = resolved
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("backup: resolve path %q: %w", src, err)
	}

	if err := validate.Path(src, "backup_source"); err != nil {
		return fmt.Errorf("backup: security violation on resolved path: %w", err)
	}

	dir := filepath.Dir(src)
	if !fsutil.IsDirWritable(dir) {
		return fmt.Errorf("backup: parent directory %q is not writable", dir)
	}

	return atomicCopy(src, src+".back")
}

func defaultFileClose(f *os.File) error {
	if err := f.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}
	return nil
}

func defaultFileStat(f *os.File) (os.FileInfo, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}
	return info, nil
}

func defaultFileReadAll(r io.Reader) ([]byte, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return buf, nil
}

var (
	fileClose   = defaultFileClose
	fileStat    = defaultFileStat
	fileReadAll = defaultFileReadAll
)

func atomicCopy(src, dst string) (retErr error) {
	in, err := os.Open(filepath.Clean(src))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("backup: open source %q: %w", src, err)
	}
	defer func() {
		if cerr := fileClose(in); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("backup: close source %q: %w", src, cerr)
		}
	}()

	info, err := fileStat(in)
	if err != nil {
		return fmt.Errorf("backup: stat opened file %q: %w", src, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("backup: %q is not a regular file", src)
	}

	if info.Size() == 0 {
		return nil
	}

	limited := io.LimitReader(in, maxBackupSize+1)
	buf, err := fileReadAll(limited)
	if err != nil {
		return fmt.Errorf("backup: copy content to temp file: %w", err)
	}
	if int64(len(buf)) > maxBackupSize {
		return fmt.Errorf("backup: source file %q exceeds 1MB limit", src)
	}

	if err := fsutil.AtomicWrite(dst, buf, 0o600); err != nil {
		return fmt.Errorf("backup: write %q: %w", dst, err)
	}
	return nil
}
