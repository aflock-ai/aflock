//go:build linux || darwin

package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// hashReader returns the SHA-256 hex digest of all bytes read from r.
// Used by platform-specific introspection to digest a binary FD on Linux
// (the FD is pinned to the inode the kernel attested) and an opened
// path on Darwin.
func hashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
