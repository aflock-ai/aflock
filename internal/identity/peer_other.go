//go:build !linux && !darwin

package identity

import "fmt"

// Stubs for platforms without UDS peer-cred support. ServeUnix already
// rejects connections on these platforms (peercred.ErrUnsupportedPlatform)
// before identity discovery is reached, so these should never run — but we
// keep them here to satisfy the build.

func peerBinaryPath(_ int) (string, error) {
	return "", fmt.Errorf("peer introspection not supported on this platform")
}
func peerContainerID(_ int) string                 { return "" }
func peerEnviron(_ int) (map[string]string, error) { return nil, nil }
func peerUIDFallback(_ int) (int, error) {
	return 0, fmt.Errorf("peer introspection not supported on this platform")
}
