//go:build !linux && !darwin

package peercred

import "net"

func fromUnixConn(_ *net.UnixConn) (PeerCred, error) {
	return PeerCred{}, ErrUnsupportedPlatform
}
