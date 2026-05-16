package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

func testParentState() *aflock.SessionState {
	return &aflock.SessionState{
		SessionID:  "parent-session-1",
		PolicyPath: "/project/.aflock",
		Materials: []aflock.MaterialClassification{
			{Label: "internal", Source: "Read:/project/internal/secret.go", Timestamp: time.Now()},
			{Label: "pii", Source: "Read:/project/data/users.csv", Timestamp: time.Now()},
		},
		Metrics: &aflock.SessionMetrics{
			TokensIn:  5000,
			TokensOut: 2000,
			CostUSD:   0.15,
			Turns:     3,
			ToolCalls: 10,
			Tools:     map[string]int{"Read": 5, "Bash": 3, "Write": 2},
		},
		Policy: &aflock.Policy{
			Name:    "test-policy",
			Version: "1.0",
			Limits: &aflock.LimitsPolicy{
				MaxSpendUSD:  &aflock.Limit{Value: 1.0, Enforcement: "fail-fast"},
				MaxToolCalls: &aflock.Limit{Value: 50, Enforcement: "post-hoc"},
			},
		},
	}
}

func TestPropagation_WriteReadRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

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

	if rec.ParentSessionID != "parent-session-1" {
		t.Errorf("ParentSessionID = %q, want %q", rec.ParentSessionID, "parent-session-1")
	}
	if len(rec.Materials) != 2 {
		t.Errorf("Materials count = %d, want 2", len(rec.Materials))
	}
	if rec.Materials[0].Label != "internal" {
		t.Errorf("Materials[0].Label = %q, want %q", rec.Materials[0].Label, "internal")
	}
	if rec.ParentMetrics.TokensIn != 5000 {
		t.Errorf("ParentMetrics.TokensIn = %d, want 5000", rec.ParentMetrics.TokensIn)
	}
	if rec.ParentLimits == nil {
		t.Fatal("ParentLimits should not be nil")
	}
	if rec.ParentLimits.MaxSpendUSD.Value != 1.0 {
		t.Errorf("ParentLimits.MaxSpendUSD = %f, want 1.0", rec.ParentLimits.MaxSpendUSD.Value)
	}
}

func TestPropagation_ConsumeOnce(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	parent := testParentState()
	if err := m.WritePropagation(parent); err != nil {
		t.Fatalf("WritePropagation: %v", err)
	}

	// First read succeeds
	rec, err := m.ReadPropagation(parent.PolicyPath)
	if err != nil {
		t.Fatalf("first ReadPropagation: %v", err)
	}
	if rec == nil {
		t.Fatal("first read should return record")
	}

	// Second read returns nil (file consumed)
	rec, err = m.ReadPropagation(parent.PolicyPath)
	if err != nil {
		t.Fatalf("second ReadPropagation: %v", err)
	}
	if rec != nil {
		t.Error("second read should return nil (consume-once)")
	}
}

func TestPropagation_TTLExpiration(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	parent := testParentState()
	if err := m.WritePropagation(parent); err != nil {
		t.Fatalf("WritePropagation: %v", err)
	}

	// Tamper with the file to set an old CreatedAt. Files now have a random
	// per-write suffix (issue #26 gap 6) so look up by the policy's prefix.
	path := singlePropagationFile(t, parent.PolicyPath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read propagation file: %v", err)
	}

	var rec aflock.PropagationRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rec.CreatedAt = time.Now().Add(-2 * PropagationTTL)
	data, _ = json.Marshal(&rec)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write modified propagation: %v", err)
	}

	// Read should return nil (expired)
	result, err := m.ReadPropagation(parent.PolicyPath)
	if err != nil {
		t.Fatalf("ReadPropagation: %v", err)
	}
	if result != nil {
		t.Error("expired propagation should return nil")
	}
}

func TestPropagation_KeyIsolation(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	// Write propagation for policy A
	parentA := testParentState()
	parentA.PolicyPath = "/project-a/.aflock"
	parentA.Materials = []aflock.MaterialClassification{
		{Label: "secret-a", Source: "Read:/project-a/secret"},
	}
	if err := m.WritePropagation(parentA); err != nil {
		t.Fatalf("WritePropagation A: %v", err)
	}

	// Reading with policy B's path should return nil
	rec, err := m.ReadPropagation("/project-b/.aflock")
	if err != nil {
		t.Fatalf("ReadPropagation B: %v", err)
	}
	if rec != nil {
		t.Error("different policy path should not match propagation")
	}

	// Reading with policy A's path should succeed
	rec, err = m.ReadPropagation("/project-a/.aflock")
	if err != nil {
		t.Fatalf("ReadPropagation A: %v", err)
	}
	if rec == nil {
		t.Fatal("same policy path should match propagation")
	}
	if rec.Materials[0].Label != "secret-a" {
		t.Errorf("Materials[0].Label = %q, want %q", rec.Materials[0].Label, "secret-a")
	}
}

func TestPropagation_MalformedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	// Write garbage to the propagation file. Use the prefix-only key form so
	// ReadPropagation finds it via its enumeration step (issue #26 gap 6).
	dir := propagationBaseDir()
	_ = os.MkdirAll(dir, 0700)
	prefix := propagationKeyPrefix("/project/.aflock")
	path := filepath.Join(dir, prefix+".garbage.json")
	_ = os.WriteFile(path, []byte("not json{{{"), 0600)

	rec, err := m.ReadPropagation("/project/.aflock")
	if err == nil {
		t.Error("malformed JSON should return error")
	}
	if rec != nil {
		t.Error("malformed JSON should return nil record")
	}

	// File should be consumed even on error
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Error("malformed file should be consumed (deleted)")
	}
}

func TestPropagation_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	rec, err := m.ReadPropagation("/nonexistent/.aflock")
	if err != nil {
		t.Errorf("ReadPropagation should not error for missing file: %v", err)
	}
	if rec != nil {
		t.Error("missing file should return nil")
	}
}

func TestPropagation_CleanStalePropagation(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	dir := propagationBaseDir()
	os.MkdirAll(dir, 0700)

	// Create a "stale" file with old mod time
	stalePath := filepath.Join(dir, "stale.json")
	os.WriteFile(stalePath, []byte("{}"), 0600)
	staleTime := time.Now().Add(-3 * PropagationTTL)
	if err := os.Chtimes(stalePath, staleTime, staleTime); err != nil {
		t.Fatalf("failed to set file times: %v", err)
	}

	// Create a "fresh" file
	freshPath := filepath.Join(dir, "fresh.json")
	os.WriteFile(freshPath, []byte("{}"), 0600)

	m.CleanStalePropagation()

	// Stale file should be removed
	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Error("stale file should be cleaned up")
	}
	// Fresh file should remain
	if _, err := os.Stat(freshPath); err != nil {
		t.Error("fresh file should remain after cleanup")
	}
}

func TestPropagation_EmptyMaterials(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	parent := testParentState()
	parent.Materials = nil // no materials
	if err := m.WritePropagation(parent); err != nil {
		t.Fatalf("WritePropagation: %v", err)
	}

	rec, err := m.ReadPropagation(parent.PolicyPath)
	if err != nil {
		t.Fatalf("ReadPropagation: %v", err)
	}
	if rec == nil {
		t.Fatal("should return record even with empty materials")
	}
	if len(rec.Materials) != 0 {
		t.Errorf("Materials count = %d, want 0", len(rec.Materials))
	}
}

func TestPropagation_NilLimits(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	parent := testParentState()
	parent.Policy.Limits = nil // no limits
	if err := m.WritePropagation(parent); err != nil {
		t.Fatalf("WritePropagation: %v", err)
	}

	rec, err := m.ReadPropagation(parent.PolicyPath)
	if err != nil {
		t.Fatalf("ReadPropagation: %v", err)
	}
	if rec == nil {
		t.Fatal("should return record even with nil limits")
	}
	if rec.ParentLimits != nil {
		t.Error("ParentLimits should be nil when parent has no limits")
	}
}

// TestPropagation_ConcurrentConsumeOnce exercises the atomic rename-based
// consume-once path: N goroutines race to read the same propagation file,
// exactly one should receive the record.
func TestPropagation_ConcurrentConsumeOnce(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	parent := testParentState()
	parent.PolicyPath = "/concurrent/consume/.aflock"
	if err := m.WritePropagation(parent); err != nil {
		t.Fatalf("WritePropagation: %v", err)
	}

	const readers = 10
	results := make(chan *aflock.PropagationRecord, readers)
	errs := make(chan error, readers)
	start := make(chan struct{})
	for i := 0; i < readers; i++ {
		go func() {
			<-start
			rec, err := m.ReadPropagation(parent.PolicyPath)
			errs <- err
			results <- rec
		}()
	}
	close(start)

	winners := 0
	for i := 0; i < readers; i++ {
		if err := <-errs; err != nil {
			t.Errorf("reader error: %v", err)
		}
		if rec := <-results; rec != nil {
			winners++
		}
	}
	if winners != 1 {
		t.Errorf("got %d winners, want exactly 1 (consume-once violated)", winners)
	}
}

func TestPropagationKey_Deterministic(t *testing.T) {
	k1 := propagationKeyPrefix("/project/.aflock")
	k2 := propagationKeyPrefix("/project/.aflock")
	if k1 != k2 {
		t.Errorf("same path should produce same prefix: %q != %q", k1, k2)
	}

	k3 := propagationKeyPrefix("/other/.aflock")
	if k1 == k3 {
		t.Error("different paths should produce different prefixes")
	}
}

// singlePropagationFile locates the single propagation file under the test's
// state dir for the given policy path, failing if there is none or more than
// one. Helper for tests that need to introspect or tamper with the on-disk
// file when filenames carry a random per-write suffix (issue #26 gap 6).
func singlePropagationFile(t *testing.T, policyPath string) string {
	t.Helper()
	prefix := propagationKeyPrefix(policyPath)
	dir := propagationBaseDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read propagation dir: %v", err)
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) < len(prefix)+1 || name[:len(prefix)] != prefix || name[len(prefix)] != '.' {
			continue
		}
		if containsConsumedMarker(name) {
			continue
		}
		found = append(found, filepath.Join(dir, name))
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly 1 propagation file for %q, got %d", policyPath, len(found))
	}
	return found[0]
}
