//go:build linux

package identity

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// peerBinaryPath resolves the peer's executable via /proc/<pid>/exe.
// The symlink target is the absolute on-disk path the kernel mapped into
// the process — not derivable from argv[0] or PATH.
func peerBinaryPath(pid int) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}

// peerContainerID returns a 12-char container ID extracted from
// /proc/<pid>/cgroup, or "" if the peer is not in a container the kernel
// reports as docker/containerd. We only inspect the peer's view of the
// cgroup hierarchy — aflock's own /proc/self/cgroup is irrelevant here.
func peerContainerID(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid)) //nolint:gosec // G304: kernel-attested PID
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.Contains(line, "docker") && !strings.Contains(line, "containerd") {
			continue
		}
		parts := strings.Split(line, "/")
		if len(parts) == 0 {
			continue
		}
		id := parts[len(parts)-1]
		if len(id) > 12 {
			id = id[:12]
		}
		return id
	}
	return ""
}

// peerEnviron parses /proc/<pid>/environ into a key→value map. The peer's
// env block is null-separated `KEY=VALUE` pairs. Reading other processes'
// environ requires same-uid or CAP_SYS_PTRACE; under our trust model the
// aflock process is expected to run as the same UID as the peer (verified
// via SO_PEERCRED before this is called).
func peerEnviron(pid int) (map[string]string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)) //nolint:gosec // G304: kernel-attested PID
	if err != nil {
		return nil, err
	}
	env := make(map[string]string)
	for kv := range strings.SplitSeq(string(data), "\x00") {
		if idx := strings.Index(kv, "="); idx > 0 {
			env[kv[:idx]] = kv[idx+1:]
		}
	}
	return env, nil
}

// peerUIDFallback parses /proc/<pid>/status for the real UID. Used only
// in the heuristic (non-peercred) discovery path, where we don't have a
// kernel-attested UID. The first field after "Uid:" is the real UID; the
// rest are effective/saved/fs UIDs which we don't need.
func peerUIDFallback(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)) //nolint:gosec // G304: PID from caller
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		return strconv.Atoi(fields[1])
	}
	return 0, fmt.Errorf("Uid not found in /proc/%d/status", pid)
}
