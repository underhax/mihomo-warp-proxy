//go:build !windows

package usermode

import (
	"os"
	"syscall"
	"testing"
)

func TestIsDirOwnedBy(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat temp dir: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat sys is not *syscall.Stat_t")
	}

	uid := stat.Uid
	gid := stat.Gid

	if !isDirOwnedBy(dir, uid, gid) {
		t.Errorf("isDirOwnedBy: expected true for actual uid:gid %d:%d", uid, gid)
	}
	if isDirOwnedBy(dir, uid+1, gid) {
		t.Error("isDirOwnedBy: expected false for wrong uid")
	}
	if isDirOwnedBy(dir, uid, gid+1) {
		t.Error("isDirOwnedBy: expected false for wrong gid")
	}
	if isDirOwnedBy("/nonexistent", uid, gid) {
		t.Error("isDirOwnedBy: expected false for nonexistent path")
	}
}

type mockNonSysStatFileInfo struct {
	os.FileInfo
}

func (m mockNonSysStatFileInfo) Sys() any {
	return nil
}

func TestIsDirOwnedByNotSysStat(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	origStat := osStat
	defer func() { osStat = origStat }()

	osStat = func(_ string) (os.FileInfo, error) {
		return mockNonSysStatFileInfo{FileInfo: info}, nil
	}

	if isDirOwnedBy(dir, 0, 0) {
		t.Error("expected false when Sys() is not *syscall.Stat_t")
	}
}
