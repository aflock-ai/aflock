package identity

import (
	"os"
	"path/filepath"
)

// PeerInfo bundles peer-process introspection results derived from a
// kernel-attested PID (via SO_PEERCRED on Linux or LOCAL_PEERPID on macOS).
//
// BinaryPath and BinaryDigest are load-bearing: a non-empty PeerInfo
// returned by IntrospectPeer always has a digest the kernel-attested PID
// was running at the moment of introspection, validated against PID
// recycle on Linux. ContainerID and Environ are best-effort metadata —
// they may be empty without invalidating the attestation.
type PeerInfo struct {
	PID          int
	UID          uint32
	GID          uint32
	BinaryPath   string            // /proc/<pid>/exe (Linux) or libproc via lsof (macOS)
	BinaryDigest string            // sha256 hex of the binary inode
	ContainerID  string            // /proc/<pid>/cgroup (Linux); empty on macOS
	Environ      map[string]string // /proc/<pid>/environ (Linux); empty on macOS
}

// IntrospectPeer reads everything we can about a peer process by PID +
// kernel-attested UID/GID. Binary-path-and-digest are TOCTOU-validated
// where the platform supports it (Linux: /proc/<pid>/exe FD pin +
// starttime check across the read). A failure to obtain a digest is
// fatal and surfaces as an error — the caller must refuse to attest
// a peer whose binary we can't bind to the kernel-reported PID.
//
// ContainerID and Environ are best-effort: failures leave the field zero.
//
// The caller is expected to have validated PID/UID/GID via SO_PEERCRED
// (Linux) or LOCAL_PEERPID + LOCAL_PEERCRED (macOS) before calling this.
func IntrospectPeer(pid int, uid, gid uint32) (PeerInfo, error) {
	info := PeerInfo{PID: pid, UID: uid, GID: gid}

	path, digest, err := peerBinaryAndDigest(pid)
	if err != nil {
		return info, err
	}
	info.BinaryPath = path
	info.BinaryDigest = digest

	info.ContainerID = peerContainerID(pid)
	if env, err := peerEnviron(pid); err == nil {
		info.Environ = env
	}
	return info, nil
}

// peerBinaryIdentity constructs a BinaryIdentity from peer-derived data.
// Unlike discoverBinary(), it does not read PATH or the CLAUDE_BINARY env
// var — the binary path comes from the kernel via /proc/<pid>/exe (Linux)
// or libproc-via-lsof (macOS), so an attacker cannot redirect us to a
// different binary by manipulating PATH or env.
//
// Name is derived from the basename so a verifier sees something
// human-readable in addition to the digest. Version is intentionally
// left empty — the digest is the authoritative version identifier and
// faking a placeholder like "0.0.0" only adds noise to the canonical
// hash without adding information.
//
// Critically, the digest is preserved even when the path is empty
// (e.g. if Readlink fails after a successful FD-bound hash on Linux).
// The digest is the load-bearing identity component; dropping it
// silently because of an unrelated path-resolution failure would let a
// half-working introspection attest with a strictly weaker hash.
func peerBinaryIdentity(p *PeerInfo) *BinaryIdentity {
	if p == nil {
		return &BinaryIdentity{}
	}
	bid := &BinaryIdentity{Digest: p.BinaryDigest}
	if p.BinaryPath != "" {
		bid.Path = p.BinaryPath
		bid.Name = filepath.Base(p.BinaryPath)
	}
	return bid
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

