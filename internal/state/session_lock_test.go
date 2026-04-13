package state

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// TestLockSession_MutualExclusion verifies that LockSession provides mutual
// exclusion: while one holder has the lock, a second Acquire blocks until the
// first releases.
func TestLockSession_MutualExclusion(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	unlock1, err := m.LockSession("lock-excl")
	if err != nil {
		t.Fatalf("first LockSession: %v", err)
	}

	acquired := make(chan struct{})
	go func() {
		unlock2, err := m.LockSession("lock-excl")
		if err != nil {
			t.Errorf("second LockSession: %v", err)
			close(acquired)
			return
		}
		close(acquired)
		unlock2()
	}()

	select {
	case <-acquired:
		t.Fatal("second LockSession acquired while first holder still active")
	case <-time.After(100 * time.Millisecond):
		// Expected: second goroutine is blocked.
	}

	unlock1()

	select {
	case <-acquired:
		// Expected: second goroutine now succeeds.
	case <-time.After(2 * time.Second):
		t.Fatal("second LockSession did not acquire after unlock")
	}
}

// TestLockSession_IndependentSessions verifies that different session IDs do
// not block each other.
func TestLockSession_IndependentSessions(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	unlockA, err := m.LockSession("session-a")
	if err != nil {
		t.Fatalf("lock A: %v", err)
	}
	defer unlockA()

	done := make(chan struct{})
	go func() {
		unlockB, err := m.LockSession("session-b")
		if err != nil {
			t.Errorf("lock B: %v", err)
		} else {
			unlockB()
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("independent session B was blocked by A")
	}
}

// TestLockSession_InvalidSessionID ensures lock acquisition rejects unsafe IDs.
func TestLockSession_InvalidSessionID(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	if _, err := m.LockSession("../evil"); err == nil {
		t.Fatal("expected error for path-traversal session ID")
	}
}

// TestConcurrentRecordAction_NoLostWrites verifies that when each writer wraps
// its load-modify-save cycle in LockSession, concurrent goroutines do not lose
// action records. Without locking, the classic read-modify-write race produces
// ToolCalls < N.
func TestConcurrentRecordAction_NoLostWrites(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	// Seed initial state.
	seed := m.Initialize("concurrent-rw", &aflock.Policy{Name: "p"}, "/p/.aflock")
	if err := m.Save(seed); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	const writers = 20
	var wg sync.WaitGroup
	var successes atomic.Int32

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			unlock, err := m.LockSession("concurrent-rw")
			if err != nil {
				t.Errorf("lock: %v", err)
				return
			}
			defer unlock()

			s, err := m.Load("concurrent-rw")
			if err != nil || s == nil {
				t.Errorf("load: %v nil=%v", err, s == nil)
				return
			}
			m.RecordAction(s, aflock.ActionRecord{
				Timestamp: time.Now(),
				ToolName:  "Read",
				Decision:  "allow",
			})
			if err := m.Save(s); err != nil {
				t.Errorf("save: %v", err)
				return
			}
			successes.Add(1)
		}(i)
	}
	wg.Wait()

	if successes.Load() != writers {
		t.Fatalf("successful writers = %d, want %d", successes.Load(), writers)
	}

	final, err := m.Load("concurrent-rw")
	if err != nil {
		t.Fatalf("final load: %v", err)
	}
	if got := final.Metrics.ToolCalls; got != writers {
		t.Errorf("persisted ToolCalls = %d, want %d (records were lost to a race)", got, writers)
	}
	if got := len(final.Actions); got != writers {
		t.Errorf("persisted Actions = %d, want %d (records were lost to a race)", got, writers)
	}
}

// TestSave_AtomicRename verifies Save writes via a temp file and leaves no
// partially written state.json visible, and that concurrent loads always see
// either the previous or the new valid state (never truncated bytes).
func TestSave_AtomicRename(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	s := m.Initialize("atomic", &aflock.Policy{Name: "p"}, "/p/.aflock")
	s.Metrics.ToolCalls = 1
	if err := m.Save(s); err != nil {
		t.Fatalf("initial save: %v", err)
	}

	// No temp files should remain after a successful save.
	entries, err := os.ReadDir(filepath.Join(tmpDir, "atomic"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" || len(e.Name()) > 0 && e.Name()[0] == '.' {
			// Allow dotfiles like .state.lock; only fail on leftover tmp.
			if strings.HasPrefix(e.Name(), ".state.json.tmp") {
				t.Errorf("leftover temp file: %s", e.Name())
			}
		}
	}

	// Concurrent loads during rapid saves must never observe a parse error.
	ctx := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			select {
			case <-ctx:
				return
			default:
			}
			s.Metrics.ToolCalls++
			_ = m.Save(s)
		}
	}()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := m.Load("atomic"); err != nil {
			close(ctx)
			t.Fatalf("Load observed torn write: %v", err)
		}
	}
	close(ctx)
	wg.Wait()
}
