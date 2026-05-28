package hooks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

func writeTranscript(t *testing.T, model string) string {
	t.Helper()
	line := `{"type":"assistant","sessionId":"s1","requestId":"r1","message":{"id":"m1","model":"` +
		model + `","usage":{"input_tokens":1000,"output_tokens":2000}}}` + "\n"
	p := filepath.Join(t.TempDir(), "transcript.jsonl")
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newState() *aflock.SessionState {
	return &aflock.SessionState{SessionID: "s1", Metrics: &aflock.SessionMetrics{}}
}

// TestRefreshUsage_KnownModelMeasured — a priced model under api_key
// yields an authoritative cost (CostMeasured true).
func TestRefreshUsage_KnownModelMeasured(t *testing.T) {
	st := newState()
	refreshUsageFromTranscript(st, writeTranscript(t, "claude-opus-4-7"), "api_key")
	if !st.Metrics.CostMeasured {
		t.Error("known model under api_key must be CostMeasured")
	}
	if st.Metrics.CostUSD <= 0 {
		t.Errorf("expected non-zero cost, got %v", st.Metrics.CostUSD)
	}
}

// TestRefreshUsage_UnknownModelUnmeasured pins the #127 review fix: an
// unpriced model computes $0, so cost must NOT be treated as measured —
// otherwise maxSpendUSD would enforce against an under-count.
func TestRefreshUsage_UnknownModelUnmeasured(t *testing.T) {
	st := newState()
	refreshUsageFromTranscript(st, writeTranscript(t, "claude-future-9"), "api_key")
	if st.Metrics.CostMeasured {
		t.Error("unpriced model under api_key must NOT be CostMeasured (would let maxSpendUSD bypass)")
	}
}

// TestRefreshUsage_SubscriptionUnmeasured — subscription is never
// authoritative for cost regardless of model.
func TestRefreshUsage_SubscriptionUnmeasured(t *testing.T) {
	st := newState()
	refreshUsageFromTranscript(st, writeTranscript(t, "claude-opus-4-7"), "subscription")
	if st.Metrics.CostMeasured {
		t.Error("subscription cost must never be CostMeasured")
	}
}
