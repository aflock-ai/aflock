package hooks

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Issue #26 — spawn-time sublayout matching + refusal + attenuation gate.
// These tests pin the three new gates in PreToolUse handling of
// Agent/Task spawns:
//
//  1. Sublayouts declared, spawn matches by subagent_type → propagation
//     carries the matched sublayout name and its promised limits.
//  2. Sublayouts declared, spawn doesn't match → refused (R3-291).
//  3. Matched sublayout has limits HIGHER than parent → refused at
//     spawn time (attenuation violation).

func policyWithSublayouts(subs ...aflock.Sublayout) *aflock.Policy {
	return &aflock.Policy{
		Name:    "issue-26",
		Version: "1.0",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Task", "Agent"}},
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD: &aflock.Limit{Value: 10.0, Enforcement: "fail-fast"},
		},
		Sublayouts: subs,
	}
}

func TestSpawn_MatchingSublayout_BindsAndAttenuates(t *testing.T) {
	h := newTestHandler(t)
	pol := policyWithSublayouts(aflock.Sublayout{
		Name:   "research",
		Policy: "./research.aflock",
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD: &aflock.Limit{Value: 2.0, Enforcement: "fail-fast"},
		},
	})
	ss := seedSession(t, h, "parent-match", pol)
	ss.Materials = append(ss.Materials, aflock.MaterialClassification{
		Label: "internal", Source: "Read:/x.go", Timestamp: time.Now(),
	})
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}

	input := &aflock.HookInput{
		SessionID: "parent-match",
		ToolName:  "Task",
		ToolInput: json.RawMessage(`{"prompt":"go research","subagent_type":"research"}`),
	}
	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal: %v (raw: %s)", err, got)
	}
	if out.HookSpecificOutput == nil || out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Fatalf("expected allow, got %+v", out.HookSpecificOutput)
	}

	rec, err := h.stateManager.ReadPropagation(ss.PolicyPath)
	if err != nil || rec == nil {
		t.Fatalf("expected propagation record, err=%v rec=%v", err, rec)
	}
	if rec.SublayoutName != "research" {
		t.Errorf("SublayoutName = %q, want %q", rec.SublayoutName, "research")
	}
	if rec.ParentLimits == nil || rec.ParentLimits.MaxSpendUSD == nil || rec.ParentLimits.MaxSpendUSD.Value != 2.0 {
		t.Errorf("ParentLimits should be sublayout-promised (2.0), got %+v", rec.ParentLimits)
	}
}

func TestSpawn_UnmatchedSublayout_Refused(t *testing.T) {
	h := newTestHandler(t)
	pol := policyWithSublayouts(aflock.Sublayout{
		Name: "research",
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD: &aflock.Limit{Value: 2.0},
		},
	})
	ss := seedSession(t, h, "parent-unmatched", pol)
	_ = ss

	input := &aflock.HookInput{
		SessionID: "parent-unmatched",
		ToolName:  "Task",
		ToolInput: json.RawMessage(`{"prompt":"x","subagent_type":"lint"}`), // not declared
	}
	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal: %v (raw: %s)", err, got)
	}
	if out.HookSpecificOutput == nil || out.HookSpecificOutput.PermissionDecision != aflock.DecisionDeny {
		t.Errorf("unmatched subagent_type must be refused, got %+v", out.HookSpecificOutput)
	}

	// And no propagation should have been written.
	rec, _ := h.stateManager.ReadPropagation(ss.PolicyPath)
	if rec != nil {
		t.Error("refused spawn must not write a propagation record")
	}
}

func TestSpawn_AttenuationViolation_Refused(t *testing.T) {
	h := newTestHandler(t)
	// Sublayout promises HIGHER spend than parent allows — invalid policy
	// that must be refused at spawn time (issue #26 gap 4).
	pol := policyWithSublayouts(aflock.Sublayout{
		Name: "greedy",
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD: &aflock.Limit{Value: 100.0},
		},
	})
	ss := seedSession(t, h, "parent-greedy", pol)
	_ = ss

	input := &aflock.HookInput{
		SessionID: "parent-greedy",
		ToolName:  "Task",
		ToolInput: json.RawMessage(`{"prompt":"x","subagent_type":"greedy"}`),
	}
	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal: %v (raw: %s)", err, got)
	}
	if out.HookSpecificOutput == nil || out.HookSpecificOutput.PermissionDecision != aflock.DecisionDeny {
		t.Errorf("attenuation-violating sublayout must be refused, got %+v", out.HookSpecificOutput)
	}
}

func TestSpawn_NoSublayoutsDeclared_LegacyBehaviorPreserved(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:    "legacy",
		Version: "1.0",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Task"}},
	}
	ss := seedSession(t, h, "parent-legacy", pol)
	_ = ss

	input := &aflock.HookInput{
		SessionID: "parent-legacy",
		ToolName:  "Task",
		ToolInput: json.RawMessage(`{"prompt":"x","subagent_type":"anything"}`),
	}
	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.HookSpecificOutput == nil || out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("no sublayouts declared must allow (legacy compat), got %+v", out.HookSpecificOutput)
	}
	rec, _ := h.stateManager.ReadPropagation(ss.PolicyPath)
	if rec == nil {
		t.Fatal("legacy path must still write propagation with parent's limits")
	}
	if rec.SublayoutName != "" {
		t.Errorf("legacy path must leave SublayoutName empty, got %q", rec.SublayoutName)
	}
}

// TestSpawn_AgentToolName_MatchesSubagentType pins the regression caught
// during real-Claude integration testing: Claude Code's subagent spawn
// tool is named "Agent" (not "Task" — Task is a different family). An
// earlier version of matchSublayoutForSpawn only parsed subagent_type when
// toolName == "Task", causing every Agent spawn to be reported as
// "no match" and refused, even when the requested sublayout was declared.
func TestSpawn_AgentToolName_MatchesSubagentType(t *testing.T) {
	h := newTestHandler(t)
	pol := policyWithSublayouts(aflock.Sublayout{
		Name:   "general-purpose",
		Policy: "./gp.aflock",
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD: &aflock.Limit{Value: 1.0},
		},
	})
	ss := seedSession(t, h, "parent-agent-tool", pol)
	_ = ss

	for _, toolName := range []string{"Agent", "Task"} {
		t.Run("toolName="+toolName, func(t *testing.T) {
			input := &aflock.HookInput{
				SessionID: "parent-agent-tool",
				ToolName:  toolName,
				ToolInput: json.RawMessage(`{"prompt":"x","subagent_type":"general-purpose"}`),
			}
			got := captureStdout(t, func() {
				if err := h.handlePreToolUse(input); err != nil {
					t.Fatalf("handlePreToolUse: %v", err)
				}
			})
			var out aflock.HookOutput
			if err := json.Unmarshal([]byte(got), &out); err != nil {
				t.Fatalf("unmarshal: %v (raw: %s)", err, got)
			}
			if out.HookSpecificOutput == nil || out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
				t.Errorf("matching sublayout via tool=%q must be allowed, got %+v",
					toolName, out.HookSpecificOutput)
			}
		})
	}
}
