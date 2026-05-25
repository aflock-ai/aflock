package hooks

import (
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// TestRollupUnmergedChildren_IncludesInFlight is the central correctness
// claim of #135: a parent's PostToolUse must observe spend from children
// whose SubagentStop hasn't fired yet, or fail-fast will rubber-stamp a
// session that's already past the ceiling.
func TestRollupUnmergedChildren_IncludesInFlight(t *testing.T) {
	parent := &aflock.SessionState{
		SessionID: "parent-1",
		Metrics: &aflock.SessionMetrics{
			CostUSD:   9.0,
			TokensIn:  100,
			TokensOut: 50,
			ToolCalls: 3,
		},
	}
	child := &aflock.SessionState{
		SessionID:       "child-1",
		ParentSessionID: "parent-1",
		Metrics: &aflock.SessionMetrics{
			CostUSD:   5.0,
			TokensIn:  200,
			TokensOut: 75,
			ToolCalls: 2,
		},
	}

	effective, included := rollupUnmergedChildren(parent, []*aflock.SessionState{child})

	if got, want := effective.CostUSD, 14.0; got != want {
		t.Errorf("CostUSD = %v, want %v", got, want)
	}
	if got, want := effective.TokensIn, int64(300); got != want {
		t.Errorf("TokensIn = %v, want %v", got, want)
	}
	if got, want := effective.TokensOut, int64(125); got != want {
		t.Errorf("TokensOut = %v, want %v", got, want)
	}
	if got, want := effective.ToolCalls, 5; got != want {
		t.Errorf("ToolCalls = %v, want %v", got, want)
	}
	if len(included) != 1 || included[0] != "child-1" {
		t.Errorf("included = %v, want [child-1]", included)
	}
}

// TestRollupUnmergedChildren_SkipsAlreadyMerged proves no double-counting:
// once SubagentStop has merged a child (recording its ID in
// parent.ChildSessionIDs), the child's metrics are already in
// parent.Metrics. Rolling them up again would duplicate the spend.
func TestRollupUnmergedChildren_SkipsAlreadyMerged(t *testing.T) {
	parent := &aflock.SessionState{
		SessionID:       "parent-1",
		ChildSessionIDs: []string{"child-1"}, // already merged
		Metrics: &aflock.SessionMetrics{
			CostUSD: 14.0, // 9 own + 5 from child-1 already merged
		},
	}
	child := &aflock.SessionState{
		SessionID:       "child-1",
		ParentSessionID: "parent-1",
		Metrics:         &aflock.SessionMetrics{CostUSD: 5.0},
	}

	effective, included := rollupUnmergedChildren(parent, []*aflock.SessionState{child})

	if got, want := effective.CostUSD, 14.0; got != want {
		t.Errorf("CostUSD = %v (double-counted), want %v", got, want)
	}
	if len(included) != 0 {
		t.Errorf("included = %v, want empty (already merged)", included)
	}
}

// TestRollupUnmergedChildren_DoesNotMutateParent guards against a subtle
// bug where the helper accidentally mutates parent.Metrics in place. The
// durable merge happens later at SubagentStop; if we mutate the parent
// here, the SubagentStop merge will double-count.
func TestRollupUnmergedChildren_DoesNotMutateParent(t *testing.T) {
	parent := &aflock.SessionState{
		SessionID: "parent-1",
		Metrics: &aflock.SessionMetrics{
			CostUSD: 9.0,
			Tools:   map[string]int{"Bash": 2},
		},
	}
	child := &aflock.SessionState{
		SessionID:       "child-1",
		ParentSessionID: "parent-1",
		Metrics:         &aflock.SessionMetrics{CostUSD: 5.0},
	}

	_, _ = rollupUnmergedChildren(parent, []*aflock.SessionState{child})

	if got, want := parent.Metrics.CostUSD, 9.0; got != want {
		t.Errorf("parent.Metrics.CostUSD mutated: got %v, want %v", got, want)
	}
	// Also verify the Tools map wasn't aliased — mutating the returned
	// effective.Tools must not bleed back into parent.
	effective, _ := rollupUnmergedChildren(parent, []*aflock.SessionState{child})
	effective.Tools["Edit"] = 99
	if _, leaked := parent.Metrics.Tools["Edit"]; leaked {
		t.Error("Tools map aliased: parent.Metrics.Tools leaked write through effective")
	}
}
