//go:build !unix

package mcp

import "fmt"

// assertParentDirSecure is unix-only. ServeUnix's peercred extraction
// fails on non-unix platforms before reaching this guard, but return an
// error here so that any future caller is forced to think about the
// trust model rather than getting a silent pass.
func assertParentDirSecure(dir string) error {
	return fmt.Errorf("UDS parent-dir security check is unix-only")
}
