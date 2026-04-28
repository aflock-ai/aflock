package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
)

// PeerInfo bundles peer-process introspection results derived from a
// kernel-attested PID (via SO_PEERCRED on Linux or LOCAL_PEERPID on macOS).
//
// Each field is best-effort: an introspection failure leaves the field at
// its zero value rather than aborting identity derivation. This keeps a
// partial-information attestation strictly better than today's heuristic
// fallback while documenting the asymmetry between platforms.
type PeerInfo struct {
	PID          int
	UID          uint32
	GID          uint32
	BinaryPath   string            // /proc/<pid>/exe (Linux) or `ps -o comm=` (macOS)
	BinaryDigest string            // sha256 hex of BinaryPath
	ContainerID  string            // /proc/<pid>/cgroup (Linux); empty on macOS
	Environ      map[string]string // /proc/<pid>/environ (Linux); empty on macOS
}

// hashFile returns the SHA-256 hex digest of the file at path. Used by
// IntrospectPeer to digest the peer's binary; declared here so the
// implementation is shared across build tags.
func hashFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is from kernel-attested /proc/<pid>/exe or ps lookup
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// IntrospectPeer reads everything we can about a peer process by PID +
// kernel-attested UID/GID. Each field is best-effort; failures leave the
// field zero rather than aborting. Callers are expected to have validated
// PID/UID/GID via SO_PEERCRED (Linux) or LOCAL_PEERPID + LOCAL_PEERCRED
// (macOS) before calling this.
func IntrospectPeer(pid int, uid, gid uint32) PeerInfo {
	info := PeerInfo{PID: pid, UID: uid, GID: gid}
	if path, err := peerBinaryPath(pid); err == nil {
		info.BinaryPath = path
		if digest, err := hashFile(path); err == nil {
			info.BinaryDigest = digest
		}
	}
	info.ContainerID = peerContainerID(pid)
	if env, err := peerEnviron(pid); err == nil {
		info.Environ = env
	}
	return info
}

// peerBinaryIdentity constructs a BinaryIdentity from peer-derived data.
// Unlike discoverBinary(), it does not read PATH or the CLAUDE_BINARY env
// var — the binary path comes from the kernel via /proc/<pid>/exe (Linux)
// or `ps -o comm=` (macOS), so an attacker cannot redirect us to a
// different binary by manipulating PATH or env.
//
// Name is derived from the basename so a verifier sees something
// human-readable in addition to the digest. Version is intentionally not
// inferred — the digest is the authoritative version identifier.
func peerBinaryIdentity(p *PeerInfo) *BinaryIdentity {
	if p == nil || p.BinaryPath == "" {
		return &BinaryIdentity{Version: "0.0.0"}
	}
	return &BinaryIdentity{
		Path:    p.BinaryPath,
		Name:    filepath.Base(p.BinaryPath),
		Version: "0.0.0",
		Digest:  p.BinaryDigest,
	}
}

// peerEnvironmentIdentity constructs an EnvironmentIdentity using
// kernel-attested peer UID and peer-derived container ID. Hostname comes
// from the local OS — UDS connections cannot cross hosts, so the peer's
// hostname is by construction the same as ours.
func peerEnvironmentIdentity(p *PeerInfo) *EnvironmentIdentity {
	env := &EnvironmentIdentity{Type: "local"}
	if p == nil {
		return env
	}
	env.UserID = int(p.UID)
	if p.ContainerID != "" {
		env.Type = "container"
		env.ContainerID = p.ContainerID
	}
	if hostname, err := os.Hostname(); err == nil {
		env.Hostname = hostname
	}
	return env
}
