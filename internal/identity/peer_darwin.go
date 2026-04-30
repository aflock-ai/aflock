//go:build darwin

package identity

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// peerBinaryAndDigest returns the peer's executable path and SHA-256
// digest on macOS. The path comes from `lsof -p <pid> -Fn` (lsof uses
// libproc internally — same kernel mechanism `proc_pidpath()` exposes,
// but accessible without cgo) and is the resolved on-disk path of the
// active executable mapping. We deliberately do NOT fall back to
// `ps -o comm=`: that returns a 15-char-truncated process name which is
// not openable, silently producing empty digests for any binary whose
// basename is longer than 15 characters.
//
// macOS lacks /proc/<pid>/exe-style FD pinning, so we cannot bind the
// digest to a specific inode the way peer_linux.go does — there is a
// race window between lsof's libproc lookup and our open of the
// returned path. We mitigate by sending signal 0 after hashing to
// confirm the PID is still alive (catches outright recycle); in-flight
// exec() races within the same PID are not detectable on darwin without
// a pidfd analog. Treat darwin attestation as "hardened heuristic," not
// equivalent to the Linux guarantee.
func peerBinaryAndDigest(pid int) (string, string, error) {
	path, err := lsofExecPath(pid)
	if err != nil {
		return "", "", err
	}
	f, err := os.Open(path) //nolint:gosec // G304: path resolved by libproc via lsof
	if err != nil {
		return "", "", fmt.Errorf("open peer binary %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	digest, err := hashReader(f)
	if err != nil {
		return "", "", fmt.Errorf("hash peer binary: %w", err)
	}
	// Confirm the PID is still alive after the hash. signal 0 is the
	// probe-only signal; ESRCH means the process exited or was recycled.
	// Same caveat as SPIRE's darwin attestor: this catches recycle but
	// not in-flight exec().
	if err := syscall.Kill(pid, 0); err != nil {
		return "", "", fmt.Errorf("peer process exited during introspection: %w", err)
	}
	return path, digest, nil
}

// lsofExecPath parses `lsof -p <pid> -Fn` for the path of the active
// executable mapping (the "txt" file descriptor in lsof's vocabulary).
// Output format with -F is one record per line, each starting with a
// type letter:
//
//	p<pid>
//	ftxt
//	n<absolute path to executable>
//	fcwd
//	n<absolute path to cwd>
//	...
//
// The 'n' line that immediately follows 'ftxt' is the executable path.
func lsofExecPath(pid int) (string, error) {
	lsofPath, err := exec.LookPath("lsof")
	if err != nil {
		// macOS ships lsof at /usr/sbin/lsof, but /usr/sbin is not always in PATH
		// for non-interactive launches.
		if _, statErr := os.Stat("/usr/sbin/lsof"); statErr == nil {
			lsofPath = "/usr/sbin/lsof"
		} else {
			return "", fmt.Errorf("lsof not found in PATH and /usr/sbin/lsof missing: %w", err)
		}
	}

	cmd := exec.Command(lsofPath, "-p", strconv.Itoa(pid), "-Fn") //nolint:gosec // G204: kernel-attested PID
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("lsof: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	atTxt := false
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "ftxt":
			atTxt = true
		case strings.HasPrefix(line, "f"):
			atTxt = false
		case atTxt && strings.HasPrefix(line, "n"):
			return line[1:], nil
		}
	}
	return "", fmt.Errorf("no ftxt entry in lsof output for pid %d", pid)
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
