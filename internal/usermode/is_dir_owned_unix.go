//go:build !windows

package usermode

import (
	"syscall"
)

func isDirOwnedBy(dir string, uid, gid uint32) bool {
	info, err := osStat(dir)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Uid == uid && stat.Gid == gid
}
