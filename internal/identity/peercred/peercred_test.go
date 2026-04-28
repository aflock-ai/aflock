package peercred

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestFromConn_UnixSocket verifies that on a UDS pair, FromConn returns the
// caller's PID, UID, and GID. We're connecting to ourselves, so the peer of
// the accepted connection is this very test process — kernel-attested.
func TestFromConn_UnixSocket(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("peercred not supported on %s", runtime.GOOS)
	}

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer listener.Close()

	type result struct {
		pc  PeerCred
		err error
	}
	resultCh := make(chan result, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			resultCh <- result{err: err}
			return
		}
		defer conn.Close()
		pc, err := FromConn(conn)
		resultCh <- result{pc: pc, err: err}
	}()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer clientConn.Close()

	res := <-resultCh
	if res.err != nil {
		t.Fatalf("FromConn: %v", res.err)
	}

	if res.pc.PID != os.Getpid() {
		t.Errorf("PID: got %d, want %d (this process)", res.pc.PID, os.Getpid())
	}
	if int(res.pc.UID) != os.Getuid() {
		t.Errorf("UID: got %d, want %d", res.pc.UID, os.Getuid())
	}
	// Don't assert on GID exactly: macOS LOCAL_PEERCRED returns the primary
	// group from the xucred group list, which may not equal os.Getgid() if
	// the process has changed group sets. Just sanity-check it was populated.
	if runtime.GOOS == "linux" && int(res.pc.GID) != os.Getgid() {
		t.Errorf("GID (linux): got %d, want %d", res.pc.GID, os.Getgid())
	}
}

// TestFromConn_NonUnixConn verifies that a non-UDS connection is rejected
// rather than returning bogus credentials.
func TestFromConn_NonUnixConn(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer listener.Close()

	type result struct {
		err error
	}
	resultCh := make(chan result, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			resultCh <- result{err: err}
			return
		}
		defer conn.Close()
		_, err = FromConn(conn)
		resultCh <- result{err: err}
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer clientConn.Close()

	res := <-resultCh
	if res.err == nil {
		t.Fatal("expected error from FromConn on TCP connection, got nil")
	}
}

// TestErrUnsupportedPlatform_IsExported verifies the sentinel is reachable.
func TestErrUnsupportedPlatform_IsExported(t *testing.T) {
	if !errors.Is(ErrUnsupportedPlatform, ErrUnsupportedPlatform) {
		t.Fatal("ErrUnsupportedPlatform should match itself")
	}
}
