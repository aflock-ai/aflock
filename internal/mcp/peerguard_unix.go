//go:build unix

package mcp

import (
	"fmt"
	"os"
	"syscall"
)

// assertParentDirSecure verifies that the directory holding the UDS
// socket path is owned by the current UID and has mode exactly 0700.
//
// MkdirAll is a no-op on existing directories, so without this check a
// caller passing `--unix /tmp/aflock.sock` would bind under /tmp's
// world-writable 1777 perms — leaving an attacker the Lstat→Listen
// window to pre-create the path and win the bind race. With this check,
// the kernel-attested-identity property is enforceable: either the
// operator owns and tightly controls the parent directory, or we refuse
// to bind.
func assertParentDirSecure(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat parent dir: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("parent path %q is not a directory", dir)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		return fmt.Errorf("parent dir %q must be mode 0700, got %#o", dir, perm)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("parent dir %q: cannot read ownership metadata", dir)
	}
	//nolint:gosec // G115: os.Getuid() is non-negative on unix
	if st.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("parent dir %q is owned by uid %d, not current uid %d", dir, st.Uid, os.Getuid())
	}
	return nil
}
