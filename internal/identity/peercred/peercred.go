// Package peercred extracts kernel-attested peer credentials (PID, UID, GID)
// from an accepted Unix-domain-socket connection.
//
// On Linux this uses SO_PEERCRED. On macOS this uses LOCAL_PEERPID for the PID
// and LOCAL_PEERCRED for UID/GID, matching SPIRE's unix workload attestor.
package peercred

import (
	"errors"
	"net"
)

// PeerCred is the set of kernel-attested credentials of the connecting peer.
type PeerCred struct {
	PID int
	UID uint32
	GID uint32
}

// ErrUnsupportedPlatform is returned by FromConn on platforms that do not
// expose peer credentials (e.g. Windows).
var ErrUnsupportedPlatform = errors.New("peercred: unsupported platform")

// FromConn extracts peer credentials from an accepted Unix-domain-socket
// connection. The connection must be a *net.UnixConn (or wrap one); other
// connection types are rejected.
func FromConn(conn net.Conn) (PeerCred, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return PeerCred{}, errors.New("peercred: connection is not a *net.UnixConn")
	}
	return fromUnixConn(uc)
}
