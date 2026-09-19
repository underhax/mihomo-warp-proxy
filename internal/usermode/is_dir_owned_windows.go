//go:build windows

package usermode

func isDirOwnedBy(_ string, _, _ uint32) bool {
	return false
}
