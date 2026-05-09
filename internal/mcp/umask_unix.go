//go:build unix

package mcp

import "syscall"

// withRestrictiveUmask sets the process umask to 0077 and returns a
// callback to restore the previous value. Used to ensure that files
// (notably the UDS socket created by net.Listen) appear with 0600
// permissions from the moment they exist on disk, eliminating the
// brief umask-derived window where the socket is world-readable
// before our explicit Chmod tightens it.
//
// Process-wide umask is not goroutine-local. ServeUnix is the only
// caller and runs once at startup; if multi-server sequencing is
// added later, the caller must serialize.
func withRestrictiveUmask() func() {
	old := syscall.Umask(0o077)
	return func() { syscall.Umask(old) }
}
