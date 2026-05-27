package verify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	aflockMerkle "github.com/aflock-ai/aflock/internal/merkle"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// computeMerkleRootForTest mirrors what SessionEnd does: marshal each
// action to JSON, build the RFC 6962 root, return hex. Used so tests
// can stamp a "matching" SessionMerkleRoot before calling
// verifySessionMerkle, simulating the self-anchored attack path where
// an attacker recomputes the root over tampered actions.
func computeMerkleRootForTest(t *testing.T, actions []aflock.ActionRecord) string {
	t.Helper()
	entries := make([][]byte, 0, len(actions))
	for _, a := range actions {
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("marshal action: %v", err)
		}
		entries = append(entries, data)
	}
	root, err := aflockMerkle.BuildRoot(entries)
	if err != nil {
		t.Fatalf("build root: %v", err)
	}
	return root
}

// actionsHappyPath builds a sequence of well-formed action records:
// monotonic timestamps, contiguous Seq starting from 0.
func actionsHappyPath(t *testing.T, n int) []aflock.ActionRecord {
	t.Helper()
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	out := make([]aflock.ActionRecord, n)
	for i := 0; i < n; i++ {
		out[i] = aflock.ActionRecord{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Seq:       int64(i),
			ToolName:  "Read",
			ToolUseID: "tu-x",
			Decision:  "allow",
		}
	}
	return out
}

// TestVerifyActionOrderingAndDistance_HappyPath — well-formed
// sequence produces no violations.
func TestVerifyActionOrderingAndDistance_HappyPath(t *testing.T) {
	if v := verifyActionOrderingAndDistance("s", actionsHappyPath(t, 5)); len(v) != 0 {
		t.Errorf("expected no violations, got %v", v)
	}
}

// TestVerifyActionOrderingAndDistance_ReorderFails — paper §4.4 Order:
// a timestamp that goes backward between two adjacent actions fails
// with a precise "ordering violation" message.
func TestVerifyActionOrderingAndDistance_ReorderFails(t *testing.T) {
	a := actionsHappyPath(t, 3)
	a[2].Timestamp = a[1].Timestamp.Add(-1 * time.Second) // step backwards
	v := verifyActionOrderingAndDistance("s", a)
	if len(v) != 1 || !strings.Contains(v[0], "ordering violation at action 2") {
		t.Errorf("expected one ordering-violation message at index 2, got %v", v)
	}
}

// TestVerifyActionOrderingAndDistance_DistanceFails — paper §4.4
// Distance: out-of-place seq values at index 2 and index 3 each
// produce one "distance violation" message with the expected index.
func TestVerifyActionOrderingAndDistance_DistanceFails(t *testing.T) {
	a := actionsHappyPath(t, 4) // seq: 0,1,2,3
	a[2].Seq = 5                // expected 2, got 5
	a[3].Seq = 99               // expected 3, got 99
	v := verifyActionOrderingAndDistance("s", a)
	hits := 0
	for _, msg := range v {
		if strings.Contains(msg, "distance violation") {
			hits++
		}
	}
	if hits != 2 {
		t.Errorf("expected 2 distance violations, got %d: %v", hits, v)
	}
}

// TestVerifyActionOrderingAndDistance_MixedSessionSkipsDistance —
// a session that crosses an aflock upgrade: legacy actions at the
// start (Seq=0) followed by new actions with non-zero Seq. Partial
// enforcement would false-fail the legacy prefix, so distance must
// be skipped entirely. Order check still runs.
func TestVerifyActionOrderingAndDistance_MixedSessionSkipsDistance(t *testing.T) {
	a := actionsHappyPath(t, 4) // would normally have seq 0,1,2,3
	a[0].Seq = 0                // legacy
	a[1].Seq = 0                // legacy
	a[2].Seq = 2                // post-upgrade, stamped
	a[3].Seq = 3                // post-upgrade, stamped
	if v := verifyActionOrderingAndDistance("s", a); len(v) != 0 {
		t.Errorf("mixed-session must skip distance and produce no violations, got %v", v)
	}
}

// TestVerifyActionOrderingAndDistance_LegacyAllZeroSkipped —
// records written by older aflock versions all carry Seq=0. The
// distance check must skip those (logging a line is fine) so legacy
// sessions don't suddenly fail verify. Order check still applies.
func TestVerifyActionOrderingAndDistance_LegacyAllZeroSkipped(t *testing.T) {
	a := actionsHappyPath(t, 3)
	for i := range a {
		a[i].Seq = 0 // simulate pre-#146 records
	}
	if v := verifyActionOrderingAndDistance("s", a); len(v) != 0 {
		t.Errorf("legacy all-zero seq must pass distance check, got %v", v)
	}

	// But the order check still fires for legacy records.
	a[1].Timestamp = a[0].Timestamp.Add(-1 * time.Second)
	v := verifyActionOrderingAndDistance("s", a)
	if len(v) != 1 || !strings.Contains(v[0], "ordering violation") {
		t.Errorf("legacy session must still get order check, got %v", v)
	}
}

// TestVerifyActionOrderingAndDistance_ShortSequence — zero or one
// action is trivially well-formed; no violations.
func TestVerifyActionOrderingAndDistance_ShortSequence(t *testing.T) {
	if v := verifyActionOrderingAndDistance("s", nil); len(v) != 0 {
		t.Errorf("nil actions should produce no violations, got %v", v)
	}
	if v := verifyActionOrderingAndDistance("s", actionsHappyPath(t, 1)); len(v) != 0 {
		t.Errorf("single action should produce no violations, got %v", v)
	}
}

// TestVerifySessionMerkle_OrderViolationAfterRootMatch — end-to-end:
// simulate the self-anchored attack path. Build a happy-path session,
// swap actions[1] and actions[2] in place so the resulting slice has a
// timestamp going backwards at index 2, then recompute the merkle root
// over the reordered slice and stamp it as SessionMerkleRoot. The
// root-match check now passes (the recorded root matches the tampered
// leaves) and only the new Order proof catches the reordering.
func TestVerifySessionMerkle_OrderViolationAfterRootMatch(t *testing.T) {
	state := &aflock.SessionState{
		SessionID: "ocd-order",
		Policy:    &aflock.Policy{Name: "p", Version: "1.0"},
		Metrics:   &aflock.SessionMetrics{},
		Actions:   actionsHappyPath(t, 3),
	}
	// Reorder in-place: swap index 1 and 2 so timestamps go forward,
	// backward, then we recompute the merkle root over THIS new order.
	state.Actions[1], state.Actions[2] = state.Actions[2], state.Actions[1]
	// Now Actions: ts0, ts2, ts1 — ordering violation at index 2.
	// Compute and stamp a fresh root so root-match passes.
	root := computeMerkleRootForTest(t, state.Actions)
	state.SessionMerkleRoot = root

	msgs := verifySessionMerkle(state)
	foundOrder := false
	for _, m := range msgs {
		if strings.Contains(m, "ordering violation") {
			foundOrder = true
		}
	}
	if !foundOrder {
		t.Errorf("expected an ordering-violation message after self-anchored root match, got %v", msgs)
	}
}
