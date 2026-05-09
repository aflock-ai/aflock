//go:build !unix

package mcp

// withRestrictiveUmask is a no-op on non-unix platforms. ServeUnix
// rejects connections on those platforms before reaching the umask
// guard anyway (peercred.ErrUnsupportedPlatform).
func withRestrictiveUmask() func() {
	return func() {}
}
