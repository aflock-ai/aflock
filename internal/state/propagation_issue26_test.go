package state

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Issue #26 gap 6 — multiple spawns of the same parent policy must each
// produce a distinct propagation file so concurrent children can all claim
// inheritance. The old code keyed by policy path only and silently
// overwrote, leaving all-but-one child empty-handed.
//
// NOTE on isolation: propagationBaseDir() points at ~/.aflock/propagation/
// (real user home, not the test's tmpDir — pre-existing behavior). Each
// test here uses a unique policy path and cleans up its own files at
// teardown so cross-test pollution stays bounded.

func uniquePolicyPath(t *testing.T) string {
	t.Helper()
	return "/test-issue26/" + t.Name() + "/.aflock"
}

// cleanupPropagation removes any leftover files for the test's policy path
// at end of test, defending against state shared via the real ~/.aflock
// dir from concurrent failures.
func cleanupPropagation(t *testing.T, policyPath string) {
	t.Helper()
	t.Cleanup(func() {
		prefix := propagationKeyPrefix(policyPath)
		dir := propagationBaseDir()
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
				_ = os.Remove(filepath.Join(dir, name))
			}
		}
	})
}

func TestPropagation_ConcurrentWritesAreDistinctFiles(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)
	policyPath := uniquePolicyPath(t)
	cleanupPropagation(t, policyPath)

	const N = 5
	for i := 0; i < N; i++ {
		parent := testParentState()
		parent.PolicyPath = policyPath
		parent.SessionID = "parent"
		if err := m.WritePropagation(parent); err != nil {
			t.Fatalf("WritePropagation %d: %v", i, err)
		}
	}

	prefix := propagationKeyPrefix(policyPath)
	entries, err := os.ReadDir(propagationBaseDir())
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) > len(prefix) && name[:len(prefix)] == prefix && !containsConsumedMarker(name) {
			count++
		}
	}
	if count != N {
		t.Errorf("expected %d distinct propagation files, got %d", N, count)
	}
}

func TestPropagation_MultipleReadersEachGetARecord(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)
	policyPath := uniquePolicyPath(t)
	cleanupPropagation(t, policyPath)

	const N = 4
	for i := 0; i < N; i++ {
		parent := testParentState()
		parent.PolicyPath = policyPath
		if err := m.WritePropagation(parent); err != nil {
			t.Fatalf("WritePropagation %d: %v", i, err)
		}
	}

	results := make([]*aflock.PropagationRecord, N)
	errs := make([]error, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, err := m.ReadPropagation(policyPath)
			results[i] = rec
			errs[i] = err
		}(i)
	}
	wg.Wait()

	wins := 0
	for i, rec := range results {
		if errs[i] != nil {
			t.Errorf("reader %d returned error: %v", i, errs[i])
		}
		if rec != nil {
			wins++
		}
	}
	if wins != N {
		t.Errorf("expected all %d readers to claim a record, got %d", N, wins)
	}

	rec, err := m.ReadPropagation(policyPath)
	if err != nil {
		t.Fatalf("trailing ReadPropagation: %v", err)
	}
	if rec != nil {
		t.Errorf("expected nil after pool drained, got record from session %q", rec.ParentSessionID)
	}
}

func TestPropagation_PrefixOnlyMatchesOwnPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)
	pathA := uniquePolicyPath(t) + "/a"
	pathB := uniquePolicyPath(t) + "/b"
	cleanupPropagation(t, pathA)
	cleanupPropagation(t, pathB)

	parentA := testParentState()
	parentA.PolicyPath = pathA
	parentB := testParentState()
	parentB.PolicyPath = pathB

	if err := m.WritePropagation(parentA); err != nil {
		t.Fatalf("WritePropagation A: %v", err)
	}
	if err := m.WritePropagation(parentB); err != nil {
		t.Fatalf("WritePropagation B: %v", err)
	}

	rec, err := m.ReadPropagation(pathA)
	if err != nil || rec == nil {
		t.Fatalf("ReadPropagation A: rec=%v err=%v", rec, err)
	}
	if rec.PolicyPath != pathA {
		t.Errorf("got record for %q, want %q", rec.PolicyPath, pathA)
	}

	rec, err = m.ReadPropagation(pathA)
	if err != nil {
		t.Fatalf("trailing read A: %v", err)
	}
	if rec != nil {
		t.Error("A pool should be empty after consume")
	}

	rec, err = m.ReadPropagation(pathB)
	if err != nil || rec == nil {
		t.Fatalf("ReadPropagation B: rec=%v err=%v", rec, err)
	}
	if rec.PolicyPath != pathB {
		t.Errorf("got record for %q, want %q", rec.PolicyPath, pathB)
	}
}
