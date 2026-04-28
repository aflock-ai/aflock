//go:build linux || darwin

package identity

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// startSleeper spawns `sleep 30` and returns its PID. Tests use this as a
// stable, predictable peer process: known binary path, known argv,
// guaranteed alive long enough to introspect.
func startSleeper(t *testing.T) (*exec.Cmd, int) {
	t.Helper()
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("sleep not on PATH: %v", err)
	}
	cmd := exec.Command(sleepBin, "30") //nolint:gosec // G204: test fixture
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	// Brief delay so /proc/<pid>/exe is populated on Linux and `ps` on
	// macOS sees the process. Without this, on a busy CI box the readlink
	// can race the kernel's own PID setup.
	time.Sleep(50 * time.Millisecond)
	return cmd, cmd.Process.Pid
}

// TestIntrospectPeer_BinaryPathFromKernel verifies that the peer's binary
// path comes from the kernel-attested PID — /proc/<pid>/exe on Linux,
// `ps -o comm=` on macOS — not from aflock's PATH. This is the core paper
// §3.1 guarantee.
func TestIntrospectPeer_BinaryPathFromKernel(t *testing.T) {
	_, pid := startSleeper(t)

	info := IntrospectPeer(pid, uint32(os.Getuid()), uint32(os.Getgid())) //nolint:gosec // G115: uid fits in uint32

	if info.BinaryPath == "" {
		t.Fatal("BinaryPath is empty — kernel PID introspection failed")
	}
	if !strings.Contains(filepath.Base(info.BinaryPath), "sleep") {
		t.Errorf("BinaryPath = %q, expected to contain 'sleep'", info.BinaryPath)
	}
	if info.BinaryDigest == "" {
		t.Errorf("BinaryDigest is empty — file hashing failed")
	}
	if len(info.BinaryDigest) != 64 {
		t.Errorf("BinaryDigest len = %d, want 64 hex chars", len(info.BinaryDigest))
	}
}

// TestIntrospectPeer_EnvironLinuxOnly checks that on Linux we read the
// peer's /proc/<pid>/environ. macOS intentionally returns nil (we don't
// fake env data we cannot attest), so the test is platform-gated.
func TestIntrospectPeer_EnvironLinuxOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("peer environ readable only on Linux, not %s", runtime.GOOS)
	}
	_, pid := startSleeper(t)

	info := IntrospectPeer(pid, uint32(os.Getuid()), uint32(os.Getgid())) //nolint:gosec // G115

	if info.Environ == nil {
		t.Fatal("Environ is nil on Linux — expected map populated from /proc/<pid>/environ")
	}
	// Sleep inherits this test process's env, so PATH should be there.
	if _, ok := info.Environ["PATH"]; !ok {
		t.Errorf("PATH not in peer environ — expected inherited from parent test process")
	}
}

// TestDiscoverAgentIdentityFromPeer_BinaryNotFromAflockPATH is the
// security-property test. Before this branch, identity.Binary was
// populated by `exec.LookPath("claude")` regardless of who connected —
// meaning a malicious binary at any path could connect via UDS and the
// resulting identity hash would still pin to whatever "claude" happened
// to be on PATH. Verify that DiscoverAgentIdentityFromPeer uses the
// PEER's binary, not aflock's PATH lookup.
func TestDiscoverAgentIdentityFromPeer_BinaryNotFromAflockPATH(t *testing.T) {
	_, pid := startSleeper(t)

	id, err := DiscoverAgentIdentityFromPeer(pid, uint32(os.Getuid()), uint32(os.Getgid())) //nolint:gosec // G115
	if err != nil {
		t.Fatalf("DiscoverAgentIdentityFromPeer: %v", err)
	}
	if id.Binary == nil {
		t.Fatal("Binary is nil")
	}

	if !strings.Contains(filepath.Base(id.Binary.Path), "sleep") {
		t.Errorf("Binary.Path = %q, expected sleep — peer binary, not aflock's PATH lookup",
			id.Binary.Path)
	}
	if id.Binary.Digest == "" {
		t.Errorf("Binary.Digest empty — peer binary was not hashed")
	}
}

// TestDiscoverAgentIdentityFromPeer_DifferentBinariesDistinctHash verifies
// the integrity property: two peers running different binaries must
// produce different identity hashes. If this regresses, an attacker could
// connect with an arbitrary binary and have aflock attest them as
// identical to a legit Claude.
func TestDiscoverAgentIdentityFromPeer_DifferentBinariesDistinctHash(t *testing.T) {
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("sleep not on PATH: %v", err)
	}
	tailBin, err := exec.LookPath("tail")
	if err != nil {
		t.Skipf("tail not on PATH: %v", err)
	}

	c1 := exec.Command(sleepBin, "30") //nolint:gosec // G204: test fixture
	if err := c1.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() { _ = c1.Process.Kill(); _ = c1.Wait() })

	c2 := exec.Command(tailBin, "-f", "/dev/null") //nolint:gosec // G204: test fixture
	if err := c2.Start(); err != nil {
		t.Fatalf("start tail: %v", err)
	}
	t.Cleanup(func() { _ = c2.Process.Kill(); _ = c2.Wait() })

	time.Sleep(50 * time.Millisecond)

	uid, gid := uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // G115

	id1, err := DiscoverAgentIdentityFromPeer(c1.Process.Pid, uid, gid)
	if err != nil {
		t.Fatalf("Discover c1: %v", err)
	}
	id2, err := DiscoverAgentIdentityFromPeer(c2.Process.Pid, uid, gid)
	if err != nil {
		t.Fatalf("Discover c2: %v", err)
	}

	if id1.Binary.Digest == "" || id2.Binary.Digest == "" {
		t.Fatal("expected non-empty digests for both peers")
	}
	if id1.Binary.Digest == id2.Binary.Digest {
		t.Errorf("different peer binaries produced same digest %q", id1.Binary.Digest)
	}
	if id1.IdentityHash == id2.IdentityHash {
		t.Errorf("different peer binaries produced same identity hash %q", id1.IdentityHash)
	}
}

// TestDiscoverAgentIdentityFromPeer_UIDFromKernel verifies that the UID
// passed in (from SO_PEERCRED) lands in Environment.UserID — not
// os.Getuid() of the aflock process. The values happen to match in this
// test because we're connecting to ourselves, but the wiring is what
// matters: pass in a synthetic UID and check it round-trips.
func TestDiscoverAgentIdentityFromPeer_UIDFromKernel(t *testing.T) {
	_, pid := startSleeper(t)

	// Pass a deliberately wrong UID to prove the field comes from the
	// argument, not from os.Getuid(). Use 99999 — unlikely to match any
	// real UID on the test host.
	const syntheticUID uint32 = 99999

	id, err := DiscoverAgentIdentityFromPeer(pid, syntheticUID, uint32(os.Getgid())) //nolint:gosec // G115
	if err != nil {
		t.Fatalf("DiscoverAgentIdentityFromPeer: %v", err)
	}
	if id.Environment == nil {
		t.Fatal("Environment nil")
	}
	if id.Environment.UserID != int(syntheticUID) {
		t.Errorf("Environment.UserID = %d, want %d (the kernel-attested UID we passed)",
			id.Environment.UserID, syntheticUID)
	}
}
