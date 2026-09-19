//go:build !windows

package wgcf

import "syscall"

const oNoFollow = syscall.O_NOFOLLOW
