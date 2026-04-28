//go:build linux

package peercred

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func fromUnixConn(uc *net.UnixConn) (PeerCred, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return PeerCred{}, fmt.Errorf("peercred: SyscallConn: %w", err)
	}

	var ucred *unix.Ucred
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return PeerCred{}, fmt.Errorf("peercred: Control: %w", ctrlErr)
	}
	if sockErr != nil {
		return PeerCred{}, fmt.Errorf("peercred: SO_PEERCRED: %w", sockErr)
	}

	return PeerCred{
		PID: int(ucred.Pid),
		UID: ucred.Uid,
		GID: ucred.Gid,
	}, nil
}
