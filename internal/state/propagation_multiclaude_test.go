package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Multi-Claude safety: a child session must only consume a propagation
// record written by one of its OWN ancestor processes. With two concurrent
// Claude sessions sharing a policy path, the old FIFO-by-prefix claim let an
// unrelated SessionStart steal a parent's handoff — inheriting its materials
// and attenuated limits, and later corrupting the parent's state when
// SubagentStop merged the wrong child.

// writeRawPropagation writes a record directly so tests can control ParentPID.
func writeRawPropagation(t *testing.T, policyPath string, rec *aflock.PropagationRecord) {
	t.Helper()
	dir := propagationBaseDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir propagation: %v", err)
	}
	name, err := propagationFilename(policyPath)
	if err != nil {
		t.Fatalf("propagation filename: %v", err)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		t.Fatalf("write record: %v", err)
	}
}

func TestPropagation_ChildOnlyConsumesOwnParentRecord(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	m := NewManager(t.TempDir())
	policyPath := "/project/.aflock"

	// Parent A wrote first (FIFO would pick it), parent B second.
	writeRawPropagation(t, policyPath, &aflock.PropagationRecord{
		ParentSessionID: "parent-A", ParentPID: 11111, CreatedAt: time.Now(),
	})
	time.Sleep(10 * time.Millisecond)
	writeRawPropagation(t, policyPath, &aflock.PropagationRecord{
		ParentSessionID: "parent-B", ParentPID: 22222, CreatedAt: time.Now(),
	})

	// A child of parent B must get B's record even though A's is older…
	rec, err := m.ReadPropagationForChild(policyPath, []int{999, 22222})
	if err != nil {
		t.Fatalf("ReadPropagationForChild: %v", err)
	}
	if rec == nil || rec.ParentSessionID != "parent-B" {
		t.Fatalf("got %+v, want parent-B's record", rec)
	}

	// …and A's record must still be on disk for A's own child.
	rec, err = m.ReadPropagationForChild(policyPath, []int{11111})
	if err != nil {
		t.Fatalf("ReadPropagationForChild(A): %v", err)
	}
	if rec == nil || rec.ParentSessionID != "parent-A" {
		t.Fatalf("got %+v, want parent-A's record left intact", rec)
	}
}

func TestPropagation_UnrelatedSessionCannotStealRecord(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	m := NewManager(t.TempDir())
	policyPath := "/project/.aflock"

	writeRawPropagation(t, policyPath, &aflock.PropagationRecord{
		ParentSessionID: "parent-A", ParentPID: 11111, CreatedAt: time.Now(),
	})

	// A concurrent, unrelated session (no matching ancestor) gets nothing…
	rec, err := m.ReadPropagationForChild(policyPath, []int{33333, 44444})
	if err != nil {
		t.Fatalf("ReadPropagationForChild: %v", err)
	}
	if rec != nil {
		t.Fatalf("unrelated session stole record: %+v", rec)
	}

	// …and the record survives for the rightful child.
	rec, err = m.ReadPropagationForChild(policyPath, []int{11111})
	if err != nil {
		t.Fatalf("ReadPropagationForChild(rightful): %v", err)
	}
	if rec == nil || rec.ParentSessionID != "parent-A" {
		t.Fatalf("rightful child got %+v, want parent-A's record", rec)
	}
}

func TestPropagation_LegacyRecordWithoutParentPIDIsConsumed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	m := NewManager(t.TempDir())
	policyPath := "/project/.aflock"

	// Record from an older aflock build: no parent_pid field.
	writeRawPropagation(t, policyPath, &aflock.PropagationRecord{
		ParentSessionID: "parent-legacy", CreatedAt: time.Now(),
	})

	rec, err := m.ReadPropagationForChild(policyPath, []int{42})
	if err != nil {
		t.Fatalf("ReadPropagationForChild: %v", err)
	}
	if rec == nil || rec.ParentSessionID != "parent-legacy" {
		t.Fatalf("got %+v, want legacy record accepted for compatibility", rec)
	}
}

func TestPropagation_WriteStampsParentPID(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	m := NewManager(t.TempDir())

	parent := testParentState()
	if err := m.WritePropagation(parent); err != nil {
		t.Fatalf("WritePropagation: %v", err)
	}

	rec, err := m.ReadPropagation(parent.PolicyPath)
	if err != nil {
		t.Fatalf("ReadPropagation: %v", err)
	}
	if rec == nil {
		t.Fatal("ReadPropagation returned nil")
	}
	if rec.ParentPID != os.Getppid() {
		t.Errorf("ParentPID = %d, want writer's Claude PID %d", rec.ParentPID, os.Getppid())
	}
}
