package hooks

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// dataFlowPolicy returns a policy with internal->public data flow blocking.
func dataFlowPolicy() *aflock.Policy {
	return &aflock.Policy{
		Name:    "test-sublayout",
		Version: "1.0",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Write", "Edit", "Bash", "Agent", "Task"},
		},
		DataFlow: &aflock.DataFlowPolicy{
			Classify: map[string][]string{
				"internal": {"Read:**/internal/**"},
				"public":   {"Write:**/public/**", "Bash:*curl*public*"},
			},
			FlowRules: []aflock.DataFlowRule{
				{Deny: "internal->public", Message: "Cannot send internal data to public destinations"},
			},
		},
	}
}

// ----- PreToolUse: Agent tool triggers propagation write -----

func TestSublayout_AgentToolWritesPropagation(t *testing.T) {
	h := newTestHandler(t)
	pol := dataFlowPolicy()
	pol.Limits = &aflock.LimitsPolicy{
		MaxSpendUSD:  &aflock.Limit{Value: 1.0, Enforcement: "fail-fast"},
		MaxToolCalls: &aflock.Limit{Value: 50, Enforcement: "post-hoc"},
	}

	ss := seedSession(t, h, "parent-1", pol)
	// Add materials to the parent (simulate reading internal data)
	ss.Materials = append(ss.Materials, aflock.MaterialClassification{
		Label: "internal", Source: "Read:/project/internal/secret.go", Timestamp: time.Now(),
	})
	ss.Metrics.TokensIn = 1000
	ss.Metrics.CostUSD = 0.10
	ss.Metrics.ToolCalls = 5
	h.stateManager.Save(ss)

	// Trigger Agent tool
	input := &aflock.HookInput{
		SessionID: "parent-1",
		ToolName:  "Agent",
		ToolInput: json.RawMessage(`{"prompt":"do something","subagent_type":"general-purpose"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	// Verify Agent tool was allowed
	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("expected Agent tool allowed, got %v", out.HookSpecificOutput.PermissionDecision)
	}

	// Verify propagation was written - read it to check
	rec, err := h.stateManager.ReadPropagation(ss.PolicyPath)
	if err != nil {
		t.Fatalf("ReadPropagation: %v", err)
	}
	if rec == nil {
		t.Fatal("propagation record should exist after Agent tool")
	}
	if rec.ParentSessionID != "parent-1" {
		t.Errorf("ParentSessionID = %q, want %q", rec.ParentSessionID, "parent-1")
	}
	if len(rec.Materials) != 1 || rec.Materials[0].Label != "internal" {
		t.Errorf("expected 1 internal material, got %v", rec.Materials)
	}
	if rec.ParentMetrics.CostUSD != 0.10 {
		t.Errorf("ParentMetrics.CostUSD = %f, want 0.10", rec.ParentMetrics.CostUSD)
	}
}

func TestSublayout_TaskToolWritesPropagation(t *testing.T) {
	h := newTestHandler(t)
	pol := dataFlowPolicy()

	ss := seedSession(t, h, "parent-task", pol)
	ss.Materials = append(ss.Materials, aflock.MaterialClassification{
		Label: "internal", Source: "Read:/project/internal/config.go", Timestamp: time.Now(),
	})
	h.stateManager.Save(ss)

	input := &aflock.HookInput{
		SessionID: "parent-task",
		ToolName:  "Task",
		ToolInput: json.RawMessage(`{"prompt":"run tests"}`),
	}

	captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	rec, err := h.stateManager.ReadPropagation(ss.PolicyPath)
	if err != nil {
		t.Fatalf("ReadPropagation: %v", err)
	}
	if rec == nil {
		t.Fatal("Task tool should trigger propagation write")
	}
}

func TestSublayout_NonAgentToolNoPropagation(t *testing.T) {
	h := newTestHandler(t)
	pol := dataFlowPolicy()

	ss := seedSession(t, h, "parent-noagent", pol)
	ss.Materials = append(ss.Materials, aflock.MaterialClassification{
		Label: "internal", Source: "Read:/project/internal/data.go", Timestamp: time.Now(),
	})
	h.stateManager.Save(ss)

	// Use Read tool (not Agent)
	input := &aflock.HookInput{
		SessionID: "parent-noagent",
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path":"/project/readme.md"}`),
	}

	captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	rec, err := h.stateManager.ReadPropagation(ss.PolicyPath)
	if err != nil {
		t.Fatalf("ReadPropagation: %v", err)
	}
	if rec != nil {
		t.Error("non-Agent tool should NOT trigger propagation write")
	}
}

// ----- SessionStart: inherits materials from propagation -----

func TestSublayout_SessionStartInheritsMaterials(t *testing.T) {
	h := newTestHandler(t)
	pol := dataFlowPolicy()

	// Simulate parent writing propagation
	parentState := &aflock.SessionState{
		SessionID:  "parent-inherit",
		PolicyPath: "/fake/policy.aflock",
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
			Tools:     map[string]int{"Read": 5},
		},
		Policy: pol,
	}
	if err := h.stateManager.WritePropagation(parentState); err != nil {
		t.Fatalf("WritePropagation: %v", err)
	}

	// Child session starts with the same policy path
	childState := h.stateManager.Initialize("child-1", pol, "/fake/policy.aflock")

	// Simulate what handleSessionStart does after Initialize
	prop, err := h.stateManager.ReadPropagation("/fake/policy.aflock")
	if err != nil {
		t.Fatalf("ReadPropagation: %v", err)
	}
	if prop == nil {
		t.Fatal("propagation record should exist")
	}

	childState.ParentSessionID = prop.ParentSessionID
	childState.Materials = prop.Materials

	if childState.ParentSessionID != "parent-inherit" {
		t.Errorf("ParentSessionID = %q, want %q", childState.ParentSessionID, "parent-inherit")
	}
	if len(childState.Materials) != 2 {
		t.Fatalf("expected 2 inherited materials, got %d", len(childState.Materials))
	}
	if childState.Materials[0].Label != "internal" {
		t.Errorf("Materials[0].Label = %q, want %q", childState.Materials[0].Label, "internal")
	}
	if childState.Materials[1].Label != "pii" {
		t.Errorf("Materials[1].Label = %q, want %q", childState.Materials[1].Label, "pii")
	}
}

// ----- SessionStart: attenuates limits -----

func TestSublayout_LimitAttenuation(t *testing.T) {
	tests := []struct {
		name          string
		childLimit    *aflock.Limit
		parentLimit   *aflock.Limit
		parentUsed    float64
		wantEffective float64
	}{
		{
			name:          "child has no limit, parent has limit",
			childLimit:    nil,
			parentLimit:   &aflock.Limit{Value: 100, Enforcement: "fail-fast"},
			parentUsed:    30,
			wantEffective: 70,
		},
		{
			name:          "child limit smaller than parent remaining",
			childLimit:    &aflock.Limit{Value: 20, Enforcement: "fail-fast"},
			parentLimit:   &aflock.Limit{Value: 100, Enforcement: "fail-fast"},
			parentUsed:    30,
			wantEffective: 20,
		},
		{
			name:          "child limit larger than parent remaining",
			childLimit:    &aflock.Limit{Value: 200, Enforcement: "fail-fast"},
			parentLimit:   &aflock.Limit{Value: 100, Enforcement: "fail-fast"},
			parentUsed:    30,
			wantEffective: 70,
		},
		{
			name:          "parent exhausted budget",
			childLimit:    &aflock.Limit{Value: 50, Enforcement: "fail-fast"},
			parentLimit:   &aflock.Limit{Value: 100, Enforcement: "fail-fast"},
			parentUsed:    100,
			wantEffective: 0,
		},
		{
			name:          "parent over budget",
			childLimit:    &aflock.Limit{Value: 50, Enforcement: "fail-fast"},
			parentLimit:   &aflock.Limit{Value: 100, Enforcement: "fail-fast"},
			parentUsed:    150,
			wantEffective: 0,
		},
		{
			name:          "no parent limit",
			childLimit:    &aflock.Limit{Value: 50, Enforcement: "fail-fast"},
			parentLimit:   nil,
			parentUsed:    0,
			wantEffective: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			childLimits := &aflock.LimitsPolicy{MaxToolCalls: tt.childLimit}
			parentLimits := &aflock.LimitsPolicy{MaxToolCalls: tt.parentLimit}
			parentMetrics := &aflock.SessionMetrics{ToolCalls: int(tt.parentUsed)}

			result := attenuateLimits(childLimits, parentLimits, parentMetrics)
			if result.MaxToolCalls == nil {
				if tt.wantEffective != 0 || tt.parentLimit != nil {
					t.Fatal("MaxToolCalls should not be nil")
				}
				return
			}
			if result.MaxToolCalls.Value != tt.wantEffective {
				t.Errorf("effective limit = %f, want %f", result.MaxToolCalls.Value, tt.wantEffective)
			}
		})
	}
}

func TestSublayout_AttenuateLimits_NilParent(t *testing.T) {
	childLimits := &aflock.LimitsPolicy{
		MaxSpendUSD: &aflock.Limit{Value: 5.0, Enforcement: "fail-fast"},
	}
	result := attenuateLimits(childLimits, nil, &aflock.SessionMetrics{})
	if result != childLimits {
		t.Error("nil parent limits should return child limits unchanged")
	}
}

func TestSublayout_AttenuateLimits_NilChild(t *testing.T) {
	parentLimits := &aflock.LimitsPolicy{
		MaxSpendUSD: &aflock.Limit{Value: 10.0, Enforcement: "fail-fast"},
	}
	parentMetrics := &aflock.SessionMetrics{CostUSD: 3.0}

	result := attenuateLimits(nil, parentLimits, parentMetrics)
	if result.MaxSpendUSD == nil {
		t.Fatal("MaxSpendUSD should not be nil")
	}
	if result.MaxSpendUSD.Value != 7.0 {
		t.Errorf("effective limit = %f, want 7.0", result.MaxSpendUSD.Value)
	}
}

// ----- SubagentStop: merges actions/metrics/materials to parent -----

func TestSublayout_SubagentStopMerge(t *testing.T) {
	h := newTestHandler(t)
	pol := dataFlowPolicy()

	// Create parent session
	parentSS := seedSession(t, h, "parent-merge", pol)
	parentSS.Materials = append(parentSS.Materials, aflock.MaterialClassification{
		Label: "internal", Source: "Read:/project/internal/a.go", Timestamp: time.Now(),
	})
	parentSS.Metrics.TokensIn = 1000
	parentSS.Metrics.ToolCalls = 5
	h.stateManager.Save(parentSS)

	// Create child session with parent reference
	childSS := h.stateManager.Initialize("child-merge", pol, "/fake/policy.aflock")
	childSS.ParentSessionID = "parent-merge"
	childSS.Materials = append(childSS.Materials,
		aflock.MaterialClassification{Label: "internal", Source: "Read:/project/internal/a.go", Timestamp: time.Now()},
		aflock.MaterialClassification{Label: "pii", Source: "Read:/project/data/users.csv", Timestamp: time.Now()},
	)
	childSS.Metrics.TokensIn = 500
	childSS.Metrics.TokensOut = 200
	childSS.Metrics.CostUSD = 0.05
	childSS.Metrics.ToolCalls = 3
	childSS.Metrics.Tools = map[string]int{"Read": 2, "Write": 1}
	childSS.Actions = append(childSS.Actions, aflock.ActionRecord{
		Timestamp: time.Now(), ToolName: "Read", ToolUseID: "tu_c1", Decision: "allow",
	})
	h.stateManager.Save(childSS)

	// Call SubagentStop
	input := &aflock.HookInput{SessionID: "child-merge"}
	got := captureStdout(t, func() {
		if err := h.handleSubagentStop(input); err != nil {
			t.Fatalf("handleSubagentStop: %v", err)
		}
	})

	// Should allow
	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// StopAllow returns empty HookOutput, check no block
	if out.Decision == "block" {
		t.Errorf("expected allow, got block: %s", out.Reason)
	}

	// Verify parent was updated
	parent, err := h.stateManager.Load("parent-merge")
	if err != nil {
		t.Fatalf("load parent: %v", err)
	}

	// Check metrics merged
	if parent.Metrics.TokensIn != 1500 { // 1000 + 500
		t.Errorf("parent TokensIn = %d, want 1500", parent.Metrics.TokensIn)
	}
	if parent.Metrics.ToolCalls != 8 { // 5 + 3
		t.Errorf("parent ToolCalls = %d, want 8", parent.Metrics.ToolCalls)
	}

	// Check actions merged with annotation
	foundAnnotated := false
	for _, a := range parent.Actions {
		if a.ToolName == "Read" && a.ToolUseID == "tu_c1" {
			foundAnnotated = true
			if len(a.Reason) == 0 || a.Reason[:10] != "[subagent:" {
				t.Errorf("expected annotated reason, got %q", a.Reason)
			}
		}
	}
	if !foundAnnotated {
		t.Error("child action should be merged into parent")
	}

	// Check materials merged (deduplicated)
	if len(parent.Materials) != 2 { // internal (dedup) + pii (new)
		t.Errorf("parent materials = %d, want 2", len(parent.Materials))
	}

	// Check child tracked
	if len(parent.ChildSessionIDs) != 1 || parent.ChildSessionIDs[0] != "child-merge" {
		t.Errorf("ChildSessionIDs = %v, want [child-merge]", parent.ChildSessionIDs)
	}
}

func TestSublayout_SubagentStopNoParent(t *testing.T) {
	h := newTestHandler(t)
	pol := dataFlowPolicy()

	// Child with no parent reference
	childSS := h.stateManager.Initialize("orphan-child", pol, "/fake/policy.aflock")
	h.stateManager.Save(childSS)

	input := &aflock.HookInput{SessionID: "orphan-child"}
	got := captureStdout(t, func() {
		if err := h.handleSubagentStop(input); err != nil {
			t.Fatalf("handleSubagentStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}
	if out.Decision == "block" {
		t.Error("orphan child should be allowed to stop")
	}
}

func TestSublayout_SubagentStopNoSession(t *testing.T) {
	h := newTestHandler(t)

	input := &aflock.HookInput{SessionID: ""}
	got := captureStdout(t, func() {
		if err := h.handleSubagentStop(input); err != nil {
			t.Fatalf("handleSubagentStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}
	if out.Decision == "block" {
		t.Error("no session should be allowed to stop")
	}
}

// ----- R3-300: Full fail-02 scenario -----
// Parent reads confidential data, spawns child, child tries to write to public -> DENIED

func TestSublayout_R3_300_Fail02_SubagentEscape(t *testing.T) {
	h := newTestHandler(t)
	pol := dataFlowPolicy()

	// Step 1: Parent reads internal data
	seedSession(t, h, "parent-fail02", pol)

	readInput := &aflock.HookInput{
		SessionID: "parent-fail02",
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "/project/internal/secrets.go"}`),
	}
	captureStdout(t, func() {
		if err := h.handlePreToolUse(readInput); err != nil {
			t.Fatalf("parent read: %v", err)
		}
	})

	// Verify parent has "internal" material
	parentSS, _ := h.stateManager.Load("parent-fail02")
	if len(parentSS.Materials) != 1 || parentSS.Materials[0].Label != "internal" {
		t.Fatalf("parent should have internal material, got: %v", parentSS.Materials)
	}

	// Step 2: Parent spawns Agent tool -> propagation written
	agentInput := &aflock.HookInput{
		SessionID: "parent-fail02",
		ToolName:  "Agent",
		ToolInput: json.RawMessage(`{"prompt":"write to public"}`),
	}
	captureStdout(t, func() {
		if err := h.handlePreToolUse(agentInput); err != nil {
			t.Fatalf("parent Agent: %v", err)
		}
	})

	// Step 3: Child session starts, inherits materials via propagation
	childSS := h.stateManager.Initialize("child-fail02", pol, "/fake/policy.aflock")

	prop, err := h.stateManager.ReadPropagation("/fake/policy.aflock")
	if err != nil {
		t.Fatalf("ReadPropagation: %v", err)
	}
	if prop == nil {
		t.Fatal("child should find propagation from parent")
	}
	childSS.ParentSessionID = prop.ParentSessionID
	childSS.Materials = prop.Materials
	h.stateManager.Save(childSS)

	// Verify child inherited the "internal" taint
	if len(childSS.Materials) != 1 || childSS.Materials[0].Label != "internal" {
		t.Fatalf("child should inherit internal material, got: %v", childSS.Materials)
	}

	// Step 4: Child tries to write to public destination -> DENIED by data flow
	writeInput := &aflock.HookInput{
		SessionID: "child-fail02",
		ToolName:  "Write",
		ToolInput: json.RawMessage(`{"file_path": "/project/public/output.txt", "content": "secret data"}`),
	}
	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(writeInput); err != nil {
			t.Fatalf("child write: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionDeny {
		t.Errorf("SECURITY: child should be DENIED writing internal data to public. Got: %v",
			out.HookSpecificOutput.PermissionDecision)
	}
}

// ----- Nested subagent propagation (A -> B -> C) -----

func TestSublayout_NestedPropagation(t *testing.T) {
	h := newTestHandler(t)
	pol := dataFlowPolicy()

	// A reads internal, spawns B
	seedSession(t, h, "agent-A", pol)

	captureStdout(t, func() {
		if err := h.handlePreToolUse(&aflock.HookInput{
			SessionID: "agent-A",
			ToolName:  "Read",
			ToolInput: json.RawMessage(`{"file_path": "/project/internal/deep-secret.go"}`),
		}); err != nil {
			t.Errorf("handlePreToolUse failed: %v", err)
		}
	})

	captureStdout(t, func() {
		if err := h.handlePreToolUse(&aflock.HookInput{
			SessionID: "agent-A",
			ToolName:  "Agent",
			ToolInput: json.RawMessage(`{"prompt":"delegate to B"}`),
		}); err != nil {
			t.Errorf("handlePreToolUse failed: %v", err)
		}
	})

	// B starts, inherits A's materials
	bSS := h.stateManager.Initialize("agent-B", pol, "/fake/policy.aflock")
	prop, _ := h.stateManager.ReadPropagation("/fake/policy.aflock")
	if prop == nil {
		t.Fatal("B should find propagation from A")
	}
	bSS.ParentSessionID = prop.ParentSessionID
	bSS.Materials = prop.Materials
	h.stateManager.Save(bSS)

	// B spawns C
	captureStdout(t, func() {
		if err := h.handlePreToolUse(&aflock.HookInput{
			SessionID: "agent-B",
			ToolName:  "Agent",
			ToolInput: json.RawMessage(`{"prompt":"delegate to C"}`),
		}); err != nil {
			t.Errorf("handlePreToolUse failed: %v", err)
		}
	})

	// C starts, should inherit B's materials (which include A's taint)
	cSS := h.stateManager.Initialize("agent-C", pol, "/fake/policy.aflock")
	prop, _ = h.stateManager.ReadPropagation("/fake/policy.aflock")
	if prop == nil {
		t.Fatal("C should find propagation from B")
	}
	cSS.ParentSessionID = prop.ParentSessionID
	cSS.Materials = prop.Materials
	h.stateManager.Save(cSS)

	// C has inherited A's original "internal" taint
	if len(cSS.Materials) != 1 || cSS.Materials[0].Label != "internal" {
		t.Fatalf("C should inherit internal taint from A via B, got: %v", cSS.Materials)
	}

	// C tries to write to public -> DENIED
	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(&aflock.HookInput{
			SessionID: "agent-C",
			ToolName:  "Write",
			ToolInput: json.RawMessage(`{"file_path": "/project/public/leak.txt", "content": "secret"}`),
		}); err != nil {
			t.Errorf("handlePreToolUse failed: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionDeny {
		t.Errorf("SECURITY: nested child C should be DENIED writing to public. Got: %v",
			out.HookSpecificOutput.PermissionDecision)
	}
}

// ----- No regression when no DataFlow policy -----

func TestSublayout_NoDataFlowPolicy_NoRegression(t *testing.T) {
	h := newTestHandler(t)
	// Policy without DataFlow
	pol := &aflock.Policy{
		Name: "simple-policy",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Write", "Agent"},
		},
	}

	seedSession(t, h, "parent-nodf", pol)

	// Agent tool should still work
	agentInput := &aflock.HookInput{
		SessionID: "parent-nodf",
		ToolName:  "Agent",
		ToolInput: json.RawMessage(`{"prompt":"test"}`),
	}
	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(agentInput); err != nil {
			t.Errorf("handlePreToolUse failed: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("Agent should be allowed without DataFlow policy, got %v",
			out.HookSpecificOutput.PermissionDecision)
	}

	// Child starts - propagation exists but has empty materials
	childSS := h.stateManager.Initialize("child-nodf", pol, "/fake/policy.aflock")
	prop, _ := h.stateManager.ReadPropagation("/fake/policy.aflock")
	if prop != nil {
		childSS.ParentSessionID = prop.ParentSessionID
		childSS.Materials = prop.Materials
	}
	h.stateManager.Save(childSS)

	// Child writes should be unrestricted
	writeInput := &aflock.HookInput{
		SessionID: "child-nodf",
		ToolName:  "Write",
		ToolInput: json.RawMessage(`{"file_path": "/project/public/out.txt", "content": "ok"}`),
	}
	got = captureStdout(t, func() {
		if err := h.handlePreToolUse(writeInput); err != nil {
			t.Errorf("handlePreToolUse failed: %v", err)
		}
	})

	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("write should be allowed without DataFlow, got %v",
			out.HookSpecificOutput.PermissionDecision)
	}
}

// ----- isSubagentSpawn helper -----

func TestIsSubagentSpawn(t *testing.T) {
	tests := []struct {
		toolName string
		want     bool
	}{
		{"Agent", true},
		{"Task", true},
		{"Read", false},
		{"Write", false},
		{"Bash", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isSubagentSpawn(tt.toolName); got != tt.want {
			t.Errorf("isSubagentSpawn(%q) = %v, want %v", tt.toolName, got, tt.want)
		}
	}
}

// ----- mergeChildIntoParent -----

func TestMergeChildIntoParent(t *testing.T) {
	parent := &aflock.SessionState{
		SessionID: "p1",
		Metrics: &aflock.SessionMetrics{
			TokensIn:  1000,
			TokensOut: 500,
			CostUSD:   0.10,
			ToolCalls: 5,
			Tools:     map[string]int{"Read": 3, "Bash": 2},
		},
		Materials: []aflock.MaterialClassification{
			{Label: "internal", Source: "Read:/a"},
		},
	}

	child := &aflock.SessionState{
		SessionID: "c1",
		Metrics: &aflock.SessionMetrics{
			TokensIn:  200,
			TokensOut: 100,
			CostUSD:   0.02,
			ToolCalls: 2,
			Tools:     map[string]int{"Read": 1, "Write": 1},
		},
		Materials: []aflock.MaterialClassification{
			{Label: "internal", Source: "Read:/a"},     // duplicate
			{Label: "pii", Source: "Read:/data/users"}, // new
		},
		Actions: []aflock.ActionRecord{
			{ToolName: "Read", ToolUseID: "tu1", Decision: "allow", Reason: "ok"},
		},
	}

	mergeChildIntoParent(parent, child)

	// Metrics accumulated
	if parent.Metrics.TokensIn != 1200 {
		t.Errorf("TokensIn = %d, want 1200", parent.Metrics.TokensIn)
	}
	if parent.Metrics.CostUSD < 0.119 || parent.Metrics.CostUSD > 0.121 {
		t.Errorf("CostUSD = %f, want ~0.12", parent.Metrics.CostUSD)
	}
	if parent.Metrics.ToolCalls != 7 {
		t.Errorf("ToolCalls = %d, want 7", parent.Metrics.ToolCalls)
	}
	if parent.Metrics.Tools["Read"] != 4 {
		t.Errorf("Tools[Read] = %d, want 4", parent.Metrics.Tools["Read"])
	}
	if parent.Metrics.Tools["Write"] != 1 {
		t.Errorf("Tools[Write] = %d, want 1", parent.Metrics.Tools["Write"])
	}

	// Materials deduplicated
	if len(parent.Materials) != 2 {
		t.Errorf("Materials = %d, want 2", len(parent.Materials))
	}

	// Actions annotated
	if len(parent.Actions) != 1 {
		t.Fatalf("Actions = %d, want 1", len(parent.Actions))
	}
	if parent.Actions[0].Reason != "[subagent:c1] ok" {
		t.Errorf("Action reason = %q", parent.Actions[0].Reason)
	}

	// Child tracked
	if len(parent.ChildSessionIDs) != 1 || parent.ChildSessionIDs[0] != "c1" {
		t.Errorf("ChildSessionIDs = %v", parent.ChildSessionIDs)
	}
}

// TestMergeChildIntoParent_RenumbersSeq pins the issue-#146 fix: merged
// child actions must extend the parent's contiguous Seq sequence so
// verify's Distance proof still fires. Without renumbering, the child's
// local Seq (which restarts at 0) would land at a non-zero index in
// the parent and trip the legacy/mixed detection.
func TestMergeChildIntoParent_RenumbersSeq(t *testing.T) {
	parent := &aflock.SessionState{
		SessionID: "p1",
		Metrics:   &aflock.SessionMetrics{Tools: map[string]int{}},
		Actions: []aflock.ActionRecord{
			{Seq: 0, ToolName: "Read", ToolUseID: "p-tu-0", Decision: "allow"},
			{Seq: 1, ToolName: "Read", ToolUseID: "p-tu-1", Decision: "allow"},
		},
	}
	child := &aflock.SessionState{
		SessionID: "c1",
		Metrics:   &aflock.SessionMetrics{Tools: map[string]int{}},
		Actions: []aflock.ActionRecord{
			{Seq: 0, ToolName: "Read", ToolUseID: "c-tu-0", Decision: "allow"},
			{Seq: 1, ToolName: "Read", ToolUseID: "c-tu-1", Decision: "allow"},
		},
	}

	mergeChildIntoParent(parent, child)

	for i, a := range parent.Actions {
		if a.Seq != int64(i) {
			t.Errorf("parent.Actions[%d].Seq = %d, want %d (child actions must be renumbered)", i, a.Seq, i)
		}
	}
}
