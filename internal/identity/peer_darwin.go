//go:build darwin

package identity

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// peerBinaryPath returns the peer's executable path on macOS via
// `ps -o comm=`. macOS exposes no /proc, and the libproc proc_pidpath
// syscall would require cgo — `ps` is the same fallback the rest of
// internal/identity already uses for macOS process introspection.
func peerBinaryPath(pid int) (string, error) {
	cmd := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid)) //nolint:gosec // G204: pid is kernel-attested
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ps: %w", err)
	}
	path := strings.TrimSpace(string(out))
	if path == "" {
		return "", fmt.Errorf("ps returned empty path for pid %d", pid)
	}
	return path, nil
}

// peerContainerID returns "" on macOS — there is no /proc/<pid>/cgroup
// equivalent. macOS containers (e.g. Docker Desktop) run inside a Linux
// VM, so a container ID would belong to that VM and be meaningless on
// the host. Document the gap rather than fake a value.
func peerContainerID(_ int) string {
	return ""
}

// peerEnviron returns nil on macOS. KERN_PROCARGS2 is the only public
// API for reading another process's environment, and it requires same-uid
// (which we already enforce via SO_PEERCRED) plus is documented as
// best-effort with no stability guarantees. We choose to return nothing
// rather than partial data that could mask real env vars from a verifier.
func peerEnviron(_ int) (map[string]string, error) {
	return nil, nil
}

// peerUIDFallback returns the peer's real UID via `ps -o uid=`. Used only
// in the heuristic discovery path; the peercred path uses kernel-attested
// UID from LOCAL_PEERCRED's xucred instead.
func peerUIDFallback(pid int) (int, error) {
	cmd := exec.Command("ps", "-o", "uid=", "-p", strconv.Itoa(pid)) //nolint:gosec // G204: pid from caller
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("ps: %w", err)
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}
