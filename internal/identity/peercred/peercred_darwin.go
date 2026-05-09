//go:build darwin

package peercred

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// On macOS, LOCAL_PEERCRED returns a struct xucred (uid + group list) and does
// NOT include the connecting PID. For the PID we have to call
// LOCAL_PEERPID separately. SPIRE's unix attestor uses the same pattern.
func fromUnixConn(uc *net.UnixConn) (PeerCred, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return PeerCred{}, fmt.Errorf("peercred: SyscallConn: %w", err)
	}

	var (
		pid     int
		xucred  *unix.Xucred
		pidErr  error
		credErr error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		pid, pidErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if pidErr != nil {
			return
		}
		xucred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if ctrlErr != nil {
		return PeerCred{}, fmt.Errorf("peercred: Control: %w", ctrlErr)
	}
	if pidErr != nil {
		return PeerCred{}, fmt.Errorf("peercred: LOCAL_PEERPID: %w", pidErr)
	}
	if credErr != nil {
		return PeerCred{}, fmt.Errorf("peercred: LOCAL_PEERCRED: %w", credErr)
	}

	pc := PeerCred{PID: pid, UID: xucred.Uid}
	if xucred.Ngroups > 0 {
		pc.GID = xucred.Groups[0]
	}
	return pc, nil
}
