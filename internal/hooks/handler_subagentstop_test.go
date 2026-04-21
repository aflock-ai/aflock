package hooks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// TestHandleSubagentStop_BlocksMissingRequiredAttestation proves issue
// #59 / M12: a child session that used a tool listed in RequiredAttestations
// without producing the matching attestation file must be blocked. Before
// the fix, handleSubagentStop skipped this check entirely.
func TestHandleSubagentStop_BlocksMissingRequiredAttestation(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "subagent-stop",
		Tools:                &aflock.ToolsPolicy{Allow: []string{"Bash"}},
		RequiredAttestations: []string{"Bash"},
	}
	ss := seedSession(t, h, "child-session-missing-attest", pol)
	// Record an allowed Bash action — but DO NOT produce an attestation file.
	ss.Actions = append(ss.Actions, aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Bash",
		ToolUseID: "tu-1",
		Decision:  "allow",
	})
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}

	input := &aflock.HookInput{SessionID: "child-session-missing-attest"}
	got := captureStdout(t, func() {
		if err := h.handleSubagentStop(input); err != nil {
			t.Fatalf("handleSubagentStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse: %v (raw: %s)", err, got)
	}
	if out.Decision != "block" {
		t.Errorf("expected block, got decision=%q reason=%q", out.Decision, out.Reason)
	}
	if !strings.Contains(out.Reason, "missing attestations") {
		t.Errorf("reason should mention missing attestations, got %q", out.Reason)
	}
	if !strings.Contains(out.Reason, "Bash") {
		t.Errorf("reason should mention the missing tool (Bash), got %q", out.Reason)
	}
}

// Sanity: a child that did NOT use the required tool should still pass —
// we don't block on tools the agent never used.
func TestHandleSubagentStop_AllowsWhenRequiredToolNotUsed(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "subagent-stop-2",
		Tools:                &aflock.ToolsPolicy{Allow: []string{"Read", "Bash"}},
		RequiredAttestations: []string{"Bash"},
	}
	ss := seedSession(t, h, "child-no-bash", pol)
	// Only Read was used; no Bash → no Bash attestation needed.
	ss.Actions = append(ss.Actions, aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Read",
		Decision:  "allow",
	})
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}

	input := &aflock.HookInput{SessionID: "child-no-bash"}
	got := captureStdout(t, func() {
		if err := h.handleSubagentStop(input); err != nil {
			t.Fatalf("handleSubagentStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse: %v (raw: %s)", err, got)
	}
	if out.Decision == "block" {
		t.Errorf("subagent stop must not block when the required tool was not used: %q", out.Reason)
	}
}
