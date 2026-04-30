//go:build linux

package identity

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// peerStartTime returns the process start time (jiffies since boot) from
// /proc/<pid>/stat field 22. Used to detect PID recycle across our own
// introspection: if starttime changes between two reads, the original
// process exited and the kernel assigned the same PID to a new process.
//
// /proc/<pid>/stat format is: pid (comm) state ppid ... where comm is
// wrapped in parens and may itself contain spaces or close-parens. We
// find the LAST ')' and split fields after that — which is what every
// /proc parser does for this reason.
func peerStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)) //nolint:gosec // G304: kernel-attested PID
	if err != nil {
		return 0, err
	}
	end := strings.LastIndex(string(data), ")")
	if end < 0 || end+1 >= len(data) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	rest := strings.Fields(string(data[end+1:]))
	// After the trailing ')' the next field is "state" (man-page field 3),
	// so starttime (field 22) is at index 22-3 = 19 in this slice.
	const starttimeIdx = 19
	if len(rest) <= starttimeIdx {
		return 0, fmt.Errorf("/proc/%d/stat: not enough fields after comm", pid)
	}
	return strconv.ParseUint(rest[starttimeIdx], 10, 64)
}

// peerBinaryAndDigest pins the peer's binary inode by opening
// /proc/<pid>/exe (the kernel resolves the symlink at open time, so the
// resulting FD references the executable mapped at that moment — even if
// the peer later exec()s or exits) and SHA-256-digests it through that FD.
// Detects PID recycle by reading /proc/<pid>/stat's starttime before and
// after the open: if it changed, the original process exited
// mid-introspection and the FD might now point to a different process's
// binary, so we refuse to attest.
//
// Returns an error rather than partial data — the caller must fail
// closed when binary attestation fails.
func peerBinaryAndDigest(pid int) (string, string, error) {
	t1, err := peerStartTime(pid)
	if err != nil {
		return "", "", fmt.Errorf("starttime pre-open: %w", err)
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid)) //nolint:gosec // G304: kernel-attested PID
	if err != nil {
		return "", "", fmt.Errorf("open /proc/%d/exe: %w", pid, err)
	}
	defer func() { _ = f.Close() }()
	t2, err := peerStartTime(pid)
	if err != nil {
		return "", "", fmt.Errorf("starttime post-open: %w", err)
	}
	if t1 != t2 {
		return "", "", fmt.Errorf("PID %d recycled during introspection (starttime %d→%d)", pid, t1, t2)
	}

	// Resolve the path of the inode our FD references — NOT the current
	// /proc/<pid>/exe target. If the peer exec()s during introspection
	// (exec doesn't change starttime, so the t1==t2 check above doesn't
	// catch it), /proc/<pid>/exe now points to the new binary while our
	// FD is still pinned to the old one. /proc/self/fd/<fd> resolves the
	// actual inode behind the FD, keeping the path consistent with the
	// digest we're about to compute.
	//
	// If the readlink fails (rare — file unlinked, etc.) we accept an
	// empty path; peerBinaryIdentity preserves the digest in that case.
	path, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))

	digest, err := hashReader(f)
	if err != nil {
		return "", "", fmt.Errorf("hash exe fd: %w", err)
	}
	return path, digest, nil
}

// containerHexID matches the 64-hex-char container ID inside cgroup
// paths. Modern systemd-managed Docker writes paths like
//
//	0::/system.slice/docker-<64hex>.scope
//
// and cri-containerd writes
//
//	0::/system.slice/cri-containerd-<64hex>.scope
//
// Older cgroup v1 layouts use /docker/<64hex>. In every case the ID is a
// 64-character hex run; everything else (the runtime prefix, the .scope
// suffix, the hierarchy prefix) is noise the previous "last path segment"
// extraction got wrong on systemd hosts (returning e.g. "docker-abcde").
var containerHexID = regexp.MustCompile(`[0-9a-f]{64}`)

// extractContainerHexID isolates the cgroup-parsing logic from the
// /proc-reading wrapper so it's directly testable. Returns the first
// 12-char prefix of the longest hex run on a docker- or containerd-tagged
// line, or "" if no such line is found.
func extractContainerHexID(contents string) string {
	for line := range strings.SplitSeq(contents, "\n") {
		if !strings.Contains(line, "docker") && !strings.Contains(line, "containerd") {
			continue
		}
		if id := containerHexID.FindString(line); id != "" {
			return id[:12]
		}
	}
	return ""
}

// peerContainerID returns a 12-char container ID extracted from
// /proc/<pid>/cgroup, or — if cgroup is empty (modern Docker with
// cgroup-namespace unsharing reports `0::/` from inside the container)
// — from /proc/<pid>/mountinfo, where Docker still leaks the ID
// through overlay-fs lowerdir/upperdir paths and bind-mount sources
// like /docker/containers/<id>/hostname. We only inspect the peer's
// view; aflock's own /proc/self files are irrelevant here.
func peerContainerID(pid int) string {
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid)); err == nil { //nolint:gosec // G304: kernel-attested PID
		if id := extractContainerHexID(string(data)); id != "" {
			return id
		}
	}
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid)); err == nil { //nolint:gosec // G304: kernel-attested PID
		return extractContainerHexID(string(data))
	}
	return ""
}

// peerEnviron parses /proc/<pid>/environ into a key→value map. The peer's
// env block is null-separated `KEY=VALUE` pairs. Reading other processes'
// environ requires same-uid or CAP_SYS_PTRACE; under our trust model
// aflock runs as the same UID as the peer (verified via SO_PEERCRED
// before this is called).
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
