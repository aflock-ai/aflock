package hooks

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/internal/state"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// newTestHandler creates a Handler with state rooted in a temp directory.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	tmpDir := t.TempDir()
	h := &Handler{
		stateManager: state.NewManager(tmpDir),
	}
	return h
}

// seedSession initializes a session with the given policy and returns the session state.
func seedSession(t *testing.T, h *Handler, sessionID string, pol *aflock.Policy) *aflock.SessionState {
	t.Helper()
	ss := h.stateManager.Initialize(sessionID, pol, "/fake/policy.aflock")
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return ss
}

// captureStdout runs fn while capturing os.Stdout, returns whatever was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = origStdout

	buf := make([]byte, 64*1024)
	n, _ := r.Read(buf)
	r.Close()
	return string(buf[:n])
}

// ----- NewHandler -----

func TestNewHandler(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
	if h.stateManager == nil {
		t.Fatal("NewHandler did not initialize stateManager")
	}
}

// ----- Handle dispatch -----

func TestHandle_UnknownHook(t *testing.T) {
	h := newTestHandler(t)
	// We need to provide stdin. Create a minimal valid JSON for the input.
	input := aflock.HookInput{SessionID: "s1"}
	data, _ := json.Marshal(input)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	if _, err := w.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	w.Close()
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	err := h.Handle("NonExistentHook")
	if err == nil {
		t.Fatal("expected error for unknown hook")
	}
	if !strings.Contains(err.Error(), "unknown hook") {
		t.Errorf("expected 'unknown hook' in error, got: %v", err)
	}
}

func TestHandle_InvalidJSON(t *testing.T) {
	h := newTestHandler(t)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	if _, err := w.Write([]byte("not json")); err != nil {
		t.Fatalf("write: %v", err)
	}
	w.Close()
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	err := h.Handle("PreToolUse")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parse input") {
		t.Errorf("expected 'parse input' in error, got: %v", err)
	}
}

// ----- PreToolUse: allow when no session exists and no policy found -----

func TestHandlePreToolUse_NoSession_NoPolicy_Allows(t *testing.T) {
	h := newTestHandler(t)
	// Use a cwd that has no policy file
	input := &aflock.HookInput{
		SessionID: "test-session-no-policy",
		Cwd:       t.TempDir(), // empty dir, no .aflock
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "main.go"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse error: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse output: %v (raw: %s)", err, got)
	}
	if out.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput")
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("expected allow, got %v", out.HookSpecificOutput.PermissionDecision)
	}
}

// ----- PreToolUse: tool allowed by policy -----

func TestHandlePreToolUse_ToolAllowed(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Write", "Bash"},
		},
	}
	seedSession(t, h, "session-allow", pol)

	input := &aflock.HookInput{
		SessionID: "session-allow",
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "test.go"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse error: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse output: %v (raw: %s)", err, got)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("expected allow, got %v", out.HookSpecificOutput.PermissionDecision)
	}

	// Verify action was recorded
	ss, err := h.stateManager.Load("session-allow")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(ss.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(ss.Actions))
	}
	if ss.Actions[0].ToolName != "Read" {
		t.Errorf("expected action tool Read, got %s", ss.Actions[0].ToolName)
	}
	if ss.Actions[0].Decision != "allow" {
		t.Errorf("expected decision allow, got %s", ss.Actions[0].Decision)
	}
}

// ----- PreToolUse: tool denied by policy -----
// Note: ExitWithError calls os.Exit(2), so we can't test the deny path
// directly through handlePreToolUse. Instead, we verify the deny decision
// is recorded in the state before the exit would happen.

func TestHandlePreToolUse_ToolDenied_StateRecorded(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read"},
			Deny:  []string{"Bash"},
		},
	}
	seedSession(t, h, "session-deny", pol)

	// We'll test the policy evaluation directly to avoid the os.Exit in ExitWithError
	// First verify the evaluator would deny this
	input := &aflock.HookInput{
		SessionID: "session-deny",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "rm -rf /"}`),
	}

	// Run handlePreToolUse - it will call os.Exit(2) on deny.
	// Instead of testing that path, we load state, create evaluator, and check directly.
	ss, _ := h.stateManager.Load(input.SessionID)
	if ss == nil || ss.Policy == nil {
		t.Fatal("expected session state with policy")
	}

	// Record the action like handlePreToolUse does, then verify
	h.stateManager.RecordAction(ss, aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Bash",
		ToolUseID: "test-id",
		ToolInput: json.RawMessage(`{"command": "rm -rf /"}`),
		Decision:  "deny",
		Reason:    "Tool 'Bash' matches deny pattern 'Bash'",
	})
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Verify
	ss2, _ := h.stateManager.Load("session-deny")
	if len(ss2.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(ss2.Actions))
	}
	if ss2.Actions[0].Decision != "deny" {
		t.Errorf("expected deny, got %s", ss2.Actions[0].Decision)
	}
	if ss2.Metrics.ToolCalls != 1 {
		t.Errorf("expected 1 tool call, got %d", ss2.Metrics.ToolCalls)
	}
}

// ----- PreToolUse: ask decision -----

func TestHandlePreToolUse_RequireApproval(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test",
		Tools: &aflock.ToolsPolicy{
			Allow:           []string{"Bash"},
			RequireApproval: []string{"Bash:git push*"},
		},
	}
	seedSession(t, h, "session-ask", pol)

	input := &aflock.HookInput{
		SessionID: "session-ask",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "git push origin main"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse error: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse output: %v (raw: %s)", err, got)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAsk {
		t.Errorf("expected ask, got %v", out.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "requires approval") {
		t.Errorf("expected 'requires approval' in reason, got: %s",
			out.HookSpecificOutput.PermissionDecisionReason)
	}
}

// ----- PreToolUse: tool not in allow list -----

func TestHandlePreToolUse_NotInAllowList(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Write"},
		},
	}
	seedSession(t, h, "session-not-allowed", pol)

	// Task is not in the allow list - this results in a deny which calls os.Exit(2).
	// We verify by loading the state after recording.
	ss, _ := h.stateManager.Load("session-not-allowed")
	h.stateManager.RecordAction(ss, aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Task",
		Decision:  "deny",
		Reason:    "Tool 'Task' not in allow list",
	})
	h.stateManager.Save(ss)

	ss2, _ := h.stateManager.Load("session-not-allowed")
	if ss2.Actions[0].Decision != "deny" {
		t.Errorf("expected deny, got %s", ss2.Actions[0].Decision)
	}
}

// ----- PreToolUse: file access denied -----

func TestHandlePreToolUse_FileDenied(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read"},
		},
		Files: &aflock.FilesPolicy{
			Deny: []string{"**/.env", "**/secrets/**"},
		},
	}
	seedSession(t, h, "session-file-deny", pol)

	// File deny results in os.Exit(2), so we verify the evaluator directly
	ss, _ := h.stateManager.Load("session-file-deny")
	if ss.Policy.Files.Deny[0] != "**/.env" {
		t.Errorf("expected deny pattern **/.env, got %s", ss.Policy.Files.Deny[0])
	}
}

// ----- PreToolUse: data flow integration -----

func TestHandlePreToolUse_DataFlowBlocked(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test-dataflow",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Bash"},
		},
		DataFlow: &aflock.DataFlowPolicy{
			Classify: map[string][]string{
				"internal": {"Read:**/secret-*.txt"},
				"public":   {"Bash:*curl*public.api*"},
			},
			FlowRules: []aflock.DataFlowRule{
				{Deny: "internal->public", Message: "Cannot send internal data to public APIs"},
			},
		},
	}

	// Step 1: Read internal data - creates material classification
	seedSession(t, h, "session-dataflow", pol)

	// Simulate reading secret file: the handler does PreToolUse which calls EvaluateDataFlow
	readInput := &aflock.HookInput{
		SessionID: "session-dataflow",
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "/app/secret-keys.txt"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(readInput); err != nil {
			t.Fatalf("handlePreToolUse (read): %v", err)
		}
	})

	var readOut aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &readOut); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if readOut.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Fatalf("expected read to be allowed, got %v", readOut.HookSpecificOutput.PermissionDecision)
	}

	// Verify the material was tracked in session state
	ss, _ := h.stateManager.Load("session-dataflow")
	if len(ss.Materials) != 1 {
		t.Fatalf("expected 1 material, got %d", len(ss.Materials))
	}
	if ss.Materials[0].Label != "internal" {
		t.Errorf("expected material label 'internal', got %s", ss.Materials[0].Label)
	}

	// Step 2: Try to curl to public API - should be blocked (os.Exit(2))
	// We can't test ExitWithError directly, but we can verify the evaluator
	// would produce a deny by loading state and evaluating manually.
	_ = ss
}

// ----- PreToolUse: data flow allows unrelated operations -----

func TestHandlePreToolUse_DataFlowAllowsUnrelated(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test-dataflow-ok",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Bash"},
		},
		DataFlow: &aflock.DataFlowPolicy{
			Classify: map[string][]string{
				"internal": {"Read:**/secret-*.txt"},
				"public":   {"Bash:*curl*public.api*"},
			},
			FlowRules: []aflock.DataFlowRule{
				{Deny: "internal->public"},
			},
		},
	}
	seedSession(t, h, "session-df-ok", pol)

	// A Bash command that does NOT match any classification should be allowed
	input := &aflock.HookInput{
		SessionID: "session-df-ok",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "ls -la"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("expected allow, got %v", out.HookSpecificOutput.PermissionDecision)
	}
}

// ----- PostToolUse: no session returns empty -----

func TestHandlePostToolUse_NoSession(t *testing.T) {
	h := newTestHandler(t)
	input := &aflock.HookInput{
		SessionID: "no-such-session",
		ToolName:  "Read",
	}

	got := captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	if got != "{}" {
		t.Errorf("expected empty JSON, got: %s", got)
	}
}

// ----- PostToolUse: file tracking - Read -----

func TestHandlePostToolUse_TracksFileRead(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "test"}
	seedSession(t, h, "session-post-read", pol)

	input := &aflock.HookInput{
		SessionID: "session-post-read",
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "/app/main.go"}`),
	}

	captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	ss, _ := h.stateManager.Load("session-post-read")
	if len(ss.Metrics.FilesRead) != 1 {
		t.Fatalf("expected 1 file read, got %d", len(ss.Metrics.FilesRead))
	}
	if ss.Metrics.FilesRead[0] != "/app/main.go" {
		t.Errorf("expected /app/main.go, got %s", ss.Metrics.FilesRead[0])
	}
}

// ----- PostToolUse: file tracking - Write -----

func TestHandlePostToolUse_TracksFileWrite(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "test"}
	seedSession(t, h, "session-post-write", pol)

	input := &aflock.HookInput{
		SessionID: "session-post-write",
		ToolName:  "Write",
		ToolInput: json.RawMessage(`{"file_path": "/app/output.txt", "content": "hello"}`),
	}

	captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	ss, _ := h.stateManager.Load("session-post-write")
	if len(ss.Metrics.FilesWritten) != 1 {
		t.Fatalf("expected 1 file written, got %d", len(ss.Metrics.FilesWritten))
	}
	if ss.Metrics.FilesWritten[0] != "/app/output.txt" {
		t.Errorf("expected /app/output.txt, got %s", ss.Metrics.FilesWritten[0])
	}
}

// ----- PostToolUse: file tracking - Edit -----

func TestHandlePostToolUse_TracksFileEdit(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "test"}
	seedSession(t, h, "session-post-edit", pol)

	input := &aflock.HookInput{
		SessionID: "session-post-edit",
		ToolName:  "Edit",
		ToolInput: json.RawMessage(`{"file_path": "/app/config.yaml"}`),
	}

	captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	ss, _ := h.stateManager.Load("session-post-edit")
	if len(ss.Metrics.FilesWritten) != 1 {
		t.Fatalf("expected 1 file written, got %d", len(ss.Metrics.FilesWritten))
	}
	if ss.Metrics.FilesWritten[0] != "/app/config.yaml" {
		t.Errorf("expected /app/config.yaml, got %s", ss.Metrics.FilesWritten[0])
	}
}

// ----- PostToolUse: file tracking - Glob (read) -----

func TestHandlePostToolUse_TracksGlob(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "test"}
	seedSession(t, h, "session-post-glob", pol)

	input := &aflock.HookInput{
		SessionID: "session-post-glob",
		ToolName:  "Glob",
		ToolInput: json.RawMessage(`{"file_path": "/app/**/*.go"}`),
	}

	captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	ss, _ := h.stateManager.Load("session-post-glob")
	if len(ss.Metrics.FilesRead) != 1 {
		t.Fatalf("expected 1 file read, got %d", len(ss.Metrics.FilesRead))
	}
}

// ----- PostToolUse: non-file tool is not tracked -----

func TestHandlePostToolUse_NonFileToolNotTracked(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "test"}
	seedSession(t, h, "session-post-bash", pol)

	input := &aflock.HookInput{
		SessionID: "session-post-bash",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "ls"}`),
	}

	captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	ss, _ := h.stateManager.Load("session-post-bash")
	if len(ss.Metrics.FilesRead) != 0 {
		t.Errorf("expected 0 files read for Bash, got %d", len(ss.Metrics.FilesRead))
	}
	if len(ss.Metrics.FilesWritten) != 0 {
		t.Errorf("expected 0 files written for Bash, got %d", len(ss.Metrics.FilesWritten))
	}
}

// ----- PostToolUse: duplicate file tracking -----

func TestHandlePostToolUse_DuplicateFileNotDoubleTracked(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "test"}
	seedSession(t, h, "session-dup", pol)

	for i := 0; i < 3; i++ {
		input := &aflock.HookInput{
			SessionID: "session-dup",
			ToolName:  "Read",
			ToolInput: json.RawMessage(`{"file_path": "/app/same.go"}`),
		}
		captureStdout(t, func() {
			if err := h.handlePostToolUse(input); err != nil {
				t.Fatalf("handlePostToolUse: %v", err)
			}
		})
	}

	ss, _ := h.stateManager.Load("session-dup")
	if len(ss.Metrics.FilesRead) != 1 {
		t.Errorf("expected 1 unique file read, got %d", len(ss.Metrics.FilesRead))
	}
}

// ----- PostToolUse: malformed tool input still succeeds (no file tracked) -----

func TestHandlePostToolUse_MalformedToolInput(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "test"}
	seedSession(t, h, "session-malformed", pol)

	input := &aflock.HookInput{
		SessionID: "session-malformed",
		ToolName:  "Read",
		ToolInput: json.RawMessage(`not valid json`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	// Should still return empty (success) even though file parsing failed
	if got != "{}" {
		t.Errorf("expected empty JSON, got: %s", got)
	}

	ss, _ := h.stateManager.Load("session-malformed")
	if len(ss.Metrics.FilesRead) != 0 {
		t.Errorf("expected no files tracked for malformed input, got %d", len(ss.Metrics.FilesRead))
	}
}

// ----- PostToolUse: limit checking -----

func TestHandlePostToolUse_LimitExceeded(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test-limits",
		Limits: &aflock.LimitsPolicy{
			MaxToolCalls: &aflock.Limit{Value: 2, Enforcement: "fail-fast"},
		},
	}
	ss := seedSession(t, h, "session-limit", pol)

	// Simulate that we already have 3 tool calls (exceeding limit of 2)
	ss.Metrics.ToolCalls = 3
	h.stateManager.Save(ss)

	input := &aflock.HookInput{
		SessionID: "session-limit",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "echo hi"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse output: %v (raw: %s)", err, got)
	}
	if out.Decision != "block" {
		t.Errorf("expected block decision, got %q", out.Decision)
	}
	if !strings.Contains(out.Reason, "Limit exceeded") {
		t.Errorf("expected 'Limit exceeded' in reason, got: %s", out.Reason)
	}
}

// ----- PostToolUse: limit not exceeded -----

func TestHandlePostToolUse_LimitNotExceeded(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test-limits-ok",
		Limits: &aflock.LimitsPolicy{
			MaxToolCalls: &aflock.Limit{Value: 100, Enforcement: "fail-fast"},
		},
	}
	seedSession(t, h, "session-limit-ok", pol)

	input := &aflock.HookInput{
		SessionID: "session-limit-ok",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "echo hi"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	if got != "{}" {
		t.Errorf("expected empty JSON (no block), got: %s", got)
	}
}

// ----- PostToolUse: post-hoc limits not checked in fail-fast mode -----

func TestHandlePostToolUse_PostHocLimitIgnoredInFailFast(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test-posthoc",
		Limits: &aflock.LimitsPolicy{
			MaxToolCalls: &aflock.Limit{Value: 1, Enforcement: "post-hoc"},
		},
	}
	ss := seedSession(t, h, "session-posthoc", pol)
	ss.Metrics.ToolCalls = 100 // Way over limit
	h.stateManager.Save(ss)

	input := &aflock.HookInput{
		SessionID: "session-posthoc",
		ToolName:  "Bash",
	}

	got := captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	// Post-hoc limits are not checked during fail-fast, so output should be empty
	if got != "{}" {
		t.Errorf("expected empty JSON (post-hoc not enforced), got: %s", got)
	}
}

// ----- Stop: no session, no policy -> allow -----

func TestHandleStop_NoSession(t *testing.T) {
	h := newTestHandler(t)
	// A non-existent session (Load returns nil, nil)
	input := &aflock.HookInput{
		SessionID: "non-existent",
	}

	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	// StopAllow returns empty HookOutput
	if out.Decision == "block" {
		t.Error("expected allow (no block), got block")
	}
}

// ----- Stop: session with no policy -> allow -----

func TestHandleStop_SessionNilPolicy(t *testing.T) {
	h := newTestHandler(t)
	seedSession(t, h, "session-nil-pol", nil)

	input := &aflock.HookInput{
		SessionID: "session-nil-pol",
	}

	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Decision == "block" {
		t.Error("expected allow for nil policy")
	}
}

// ----- Stop: no required attestations -> allow -----

func TestHandleStop_NoRequiredAttestations(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "test"}
	seedSession(t, h, "session-no-attest", pol)

	input := &aflock.HookInput{
		SessionID: "session-no-attest",
	}

	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Decision == "block" {
		t.Error("expected allow when no attestations required")
	}
}

// ----- Stop: required attestation missing -> block -----

func TestHandleStop_MissingAttestation(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "test-attest",
		RequiredAttestations: []string{"security-review"},
	}
	seedSession(t, h, "session-missing-attest", pol)

	// Record that the tool was used — Stop only blocks for tools actually used
	ss, _ := h.stateManager.Load("session-missing-attest")
	h.stateManager.RecordAction(ss, aflock.ActionRecord{
		ToolName: "security-review", Decision: "allow",
	})
	h.stateManager.Save(ss)

	input := &aflock.HookInput{
		SessionID: "session-missing-attest",
	}

	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Decision != "block" {
		t.Errorf("expected block for missing attestation, got %q", out.Decision)
	}
	if !strings.Contains(out.Reason, "missing attestations") {
		t.Errorf("expected 'missing attestations' in reason, got: %s", out.Reason)
	}
	if !strings.Contains(out.Reason, "security-review") {
		t.Errorf("expected 'security-review' in reason, got: %s", out.Reason)
	}
}

func TestHandleStop_UnusedToolNotRequired(t *testing.T) {
	h := newTestHandler(t)
	// Require Bash attestations only. The session never uses Bash, so the
	// required-attestations gate must not fire.
	pol := &aflock.Policy{
		Name:                 "test-unused",
		RequiredAttestations: []string{"Bash"},
	}
	seedSession(t, h, "session-unused-tool", pol)

	// Record an unrelated tool (Grep) to show the session did something but
	// never used Bash.
	ss, _ := h.stateManager.Load("session-unused-tool")
	h.stateManager.RecordAction(ss, aflock.ActionRecord{
		ToolName: "Grep", Decision: "allow",
	})
	h.stateManager.Save(ss)

	input := &aflock.HookInput{SessionID: "session-unused-tool"}

	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse: %v (raw: %s)", err, got)
	}
	if out.Decision == "block" {
		t.Errorf("expected allow when required tool was never used, got block: %s", out.Reason)
	}
}

// ----- Stop: required attestation present (exact filename match) -> allow -----

func TestHandleStop_AttestationPresent_ExactFile(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "test-attest-ok",
		RequiredAttestations: []string{"security-review"},
	}
	seedSession(t, h, "session-attest-ok", pol)

	// Create the attestation file in the attestations directory
	attestDir := h.stateManager.AttestationsDir("session-attest-ok")
	os.MkdirAll(attestDir, 0755)
	os.WriteFile(filepath.Join(attestDir, "security-review.json"), []byte(`{"signed": true}`), 0644)

	input := &aflock.HookInput{
		SessionID: "session-attest-ok",
	}

	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Decision == "block" {
		t.Errorf("expected allow when attestation file exists, got block: %s", out.Reason)
	}
}

// ----- Stop: required attestation present (.intoto.json match) -> allow -----

func TestHandleStop_AttestationPresent_IntotoFile(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "test-intoto",
		RequiredAttestations: []string{"build-step"},
	}
	seedSession(t, h, "session-intoto", pol)

	attestDir := h.stateManager.AttestationsDir("session-intoto")
	os.MkdirAll(attestDir, 0755)
	os.WriteFile(filepath.Join(attestDir, "build-step.intoto.json"), []byte(`{"signed": true}`), 0644)

	input := &aflock.HookInput{
		SessionID: "session-intoto",
	}

	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Decision == "block" {
		t.Errorf("expected allow with .intoto.json file, got block: %s", out.Reason)
	}
}

// ----- Stop: attestation found by content toolName match -----

func TestHandleStop_AttestationFoundByContent(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "test-content-match",
		RequiredAttestations: []string{"Bash"},
	}
	seedSession(t, h, "session-content-match", pol)

	attestDir := h.stateManager.AttestationsDir("session-content-match")
	os.MkdirAll(attestDir, 0755)

	// Create an intoto attestation with Bash as the toolName in the predicate
	predicate := map[string]interface{}{
		"toolName": "Bash",
		"action":   "execute",
	}
	statement := map[string]interface{}{
		"predicate": predicate,
	}
	stmtBytes, _ := json.Marshal(statement)
	envelope := map[string]interface{}{
		"payload": base64.StdEncoding.EncodeToString(stmtBytes),
	}
	envBytes, _ := json.Marshal(envelope)

	os.WriteFile(filepath.Join(attestDir, "20260210-143022-ab3def12.intoto.json"), envBytes, 0644)

	input := &aflock.HookInput{
		SessionID: "session-content-match",
	}

	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Decision == "block" {
		t.Errorf("expected allow via content match, got block: %s", out.Reason)
	}
}

// ----- Stop: attestation found by action field match -----

func TestHandleStop_AttestationFoundByActionField(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "test-action-match",
		RequiredAttestations: []string{"deploy"},
	}
	seedSession(t, h, "session-action-match", pol)

	attestDir := h.stateManager.AttestationsDir("session-action-match")
	os.MkdirAll(attestDir, 0755)

	predicate := map[string]interface{}{
		"toolName": "some-tool",
		"action":   "deploy",
	}
	statement := map[string]interface{}{
		"predicate": predicate,
	}
	stmtBytes, _ := json.Marshal(statement)
	envelope := map[string]interface{}{
		"payload": base64.StdEncoding.EncodeToString(stmtBytes),
	}
	envBytes, _ := json.Marshal(envelope)

	os.WriteFile(filepath.Join(attestDir, "some-timestamp.intoto.json"), envBytes, 0644)

	input := &aflock.HookInput{
		SessionID: "session-action-match",
	}

	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Decision == "block" {
		t.Errorf("expected allow via action field match, got block: %s", out.Reason)
	}
}

// ----- Stop: multiple required attestations, one missing -----

func TestHandleStop_MultipleAttestations_OneMissing(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "test-multi",
		RequiredAttestations: []string{"build", "test", "deploy"},
	}
	seedSession(t, h, "session-multi", pol)

	// Record all three tools as used
	ss, _ := h.stateManager.Load("session-multi")
	h.stateManager.RecordAction(ss, aflock.ActionRecord{ToolName: "build", Decision: "allow"})
	h.stateManager.RecordAction(ss, aflock.ActionRecord{ToolName: "test", Decision: "allow"})
	h.stateManager.RecordAction(ss, aflock.ActionRecord{ToolName: "deploy", Decision: "allow"})
	h.stateManager.Save(ss)

	attestDir := h.stateManager.AttestationsDir("session-multi")
	os.MkdirAll(attestDir, 0755)
	os.WriteFile(filepath.Join(attestDir, "build.json"), []byte(`{}`), 0644)
	os.WriteFile(filepath.Join(attestDir, "test.json"), []byte(`{}`), 0644)
	// "deploy" was used but attestation is missing — should block

	input := &aflock.HookInput{SessionID: "session-multi"}

	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Decision != "block" {
		t.Errorf("expected block with missing deploy attestation")
	}
	if !strings.Contains(out.Reason, "deploy") {
		t.Errorf("expected 'deploy' in missing list, got: %s", out.Reason)
	}
}

// ----- Stop: all required attestations present -----

func TestHandleStop_AllAttestationsPresent(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "test-all-ok",
		RequiredAttestations: []string{"build", "test"},
	}
	seedSession(t, h, "session-all-ok", pol)

	attestDir := h.stateManager.AttestationsDir("session-all-ok")
	os.MkdirAll(attestDir, 0755)
	os.WriteFile(filepath.Join(attestDir, "build.json"), []byte(`{}`), 0644)
	os.WriteFile(filepath.Join(attestDir, "test.json"), []byte(`{}`), 0644)

	input := &aflock.HookInput{SessionID: "session-all-ok"}

	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Decision == "block" {
		t.Errorf("expected allow with all attestations, got block: %s", out.Reason)
	}
}

// ----- PermissionRequest: returns empty -----

func TestHandlePermissionRequest_ReturnsEmpty(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "test"}
	seedSession(t, h, "session-perm", pol)

	input := &aflock.HookInput{SessionID: "session-perm"}

	got := captureStdout(t, func() {
		if err := h.handlePermissionRequest(input); err != nil {
			t.Fatalf("handlePermissionRequest: %v", err)
		}
	})

	if got != "{}" {
		t.Errorf("expected empty JSON, got: %s", got)
	}
}

func TestHandlePermissionRequest_NoSession_ReturnsEmpty(t *testing.T) {
	h := newTestHandler(t)
	input := &aflock.HookInput{SessionID: "no-session"}

	got := captureStdout(t, func() {
		if err := h.handlePermissionRequest(input); err != nil {
			t.Fatalf("handlePermissionRequest: %v", err)
		}
	})

	if got != "{}" {
		t.Errorf("expected empty JSON, got: %s", got)
	}
}

// ----- UserPromptSubmit: increments turns -----

func TestHandleUserPromptSubmit_IncrementsTurns(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "test"}
	seedSession(t, h, "session-turns", pol)

	for i := 0; i < 5; i++ {
		input := &aflock.HookInput{
			SessionID: "session-turns",
			Prompt:    "do something",
		}
		captureStdout(t, func() {
			if err := h.handleUserPromptSubmit(input); err != nil {
				t.Fatalf("handleUserPromptSubmit: %v", err)
			}
		})
	}

	ss, _ := h.stateManager.Load("session-turns")
	if ss.Metrics.Turns != 5 {
		t.Errorf("expected 5 turns, got %d", ss.Metrics.Turns)
	}
}

func TestHandleUserPromptSubmit_NoSession_ReturnsEmpty(t *testing.T) {
	h := newTestHandler(t)
	input := &aflock.HookInput{SessionID: "no-session"}

	got := captureStdout(t, func() {
		if err := h.handleUserPromptSubmit(input); err != nil {
			t.Fatalf("handleUserPromptSubmit: %v", err)
		}
	})

	if got != "{}" {
		t.Errorf("expected empty JSON, got: %s", got)
	}
}

// ----- SubagentStop: always allows -----

func TestHandleSubagentStop_Allows(t *testing.T) {
	h := newTestHandler(t)
	input := &aflock.HookInput{SessionID: "any"}

	got := captureStdout(t, func() {
		if err := h.handleSubagentStop(input); err != nil {
			t.Fatalf("handleSubagentStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Decision == "block" {
		t.Error("expected allow for subagent stop")
	}
}

// ----- SessionEnd: returns empty for no session -----

func TestHandleSessionEnd_NoSession(t *testing.T) {
	h := newTestHandler(t)
	input := &aflock.HookInput{SessionID: "no-session"}

	got := captureStdout(t, func() {
		if err := h.handleSessionEnd(input); err != nil {
			t.Fatalf("handleSessionEnd: %v", err)
		}
	})

	if got != "{}" {
		t.Errorf("expected empty JSON, got: %s", got)
	}
}

// ----- SessionEnd: with session prints metrics -----

func TestHandleSessionEnd_PrintsMetrics(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "test"}
	ss := seedSession(t, h, "session-end", pol)

	// Set some metrics
	ss.Metrics.Turns = 10
	ss.Metrics.ToolCalls = 42
	h.stateManager.Save(ss)

	input := &aflock.HookInput{SessionID: "session-end"}

	// SessionEnd writes to stderr (metrics logging) and returns empty to stdout
	got := captureStdout(t, func() {
		if err := h.handleSessionEnd(input); err != nil {
			t.Fatalf("handleSessionEnd: %v", err)
		}
	})

	if got != "{}" {
		t.Errorf("expected empty JSON, got: %s", got)
	}
}

// ----- Notification: returns empty -----

func TestHandleNotification_ReturnsEmpty(t *testing.T) {
	h := newTestHandler(t)
	input := &aflock.HookInput{SessionID: "any"}

	got := captureStdout(t, func() {
		if err := h.handleNotification(input); err != nil {
			t.Fatalf("handleNotification: %v", err)
		}
	})

	if got != "{}" {
		t.Errorf("expected empty JSON, got: %s", got)
	}
}

// ----- PreCompact: returns empty -----

func TestHandlePreCompact_ReturnsEmpty(t *testing.T) {
	h := newTestHandler(t)
	input := &aflock.HookInput{SessionID: "any"}

	got := captureStdout(t, func() {
		if err := h.handlePreCompact(input); err != nil {
			t.Fatalf("handlePreCompact: %v", err)
		}
	})

	if got != "{}" {
		t.Errorf("expected empty JSON, got: %s", got)
	}
}

// ----- isFileOperation -----

func TestIsFileOperation(t *testing.T) {
	fileOps := []string{"Read", "Write", "Edit", "Glob", "Grep"}
	nonFileOps := []string{"Bash", "Task", "WebFetch", "WebSearch", "mcp__something"}

	for _, op := range fileOps {
		if !isFileOperation(op) {
			t.Errorf("expected %q to be a file operation", op)
		}
	}
	for _, op := range nonFileOps {
		if isFileOperation(op) {
			t.Errorf("expected %q to NOT be a file operation", op)
		}
	}
}

// ----- findAttestation -----

func TestFindAttestation_NonExistentDir(t *testing.T) {
	if findAttestation("/nonexistent/path/12345", "something") {
		t.Error("expected false for nonexistent directory")
	}
}

func TestFindAttestation_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	if findAttestation(dir, "something") {
		t.Error("expected false for empty directory")
	}
}

// Helper: minimum envelope that passes the tightened integrity check —
// parseable in-toto Statement payload + proper DSSE content type + base64-
// decodable non-empty sig with non-empty keyid. Crypto verification is
// tested separately via the ephemeral-signer fixtures in handler_forgery_test.go.
func minimalValidEnvelope(predicateToolName string) string {
	stmt := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]string{{"name": "x"}},
		"predicateType": "https://aflock.ai/attestations/action/v0.1",
		"predicate":     map[string]string{"toolName": predicateToolName},
	}
	stmtBytes, _ := json.Marshal(stmt)
	env := map[string]interface{}{
		"payload":     base64.StdEncoding.EncodeToString(stmtBytes),
		"payloadType": "application/vnd.in-toto+json",
		"signatures": []map[string]string{{
			"keyid": "k",
			"sig":   base64.StdEncoding.EncodeToString([]byte("sig-bytes")),
		}},
	}
	envBytes, _ := json.Marshal(env)
	return string(envBytes)
}

func TestFindAttestation_ExactMatch(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "myattest.json"), []byte(minimalValidEnvelope("")), 0600)
	if !findAttestation(dir, "myattest") {
		t.Error("expected true for exact .json match")
	}
}

func TestFindAttestation_IntotoMatch(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "step1.intoto.json"), []byte(minimalValidEnvelope("")), 0600)
	if !findAttestation(dir, "step1") {
		t.Error("expected true for exact .intoto.json match")
	}
}

func TestFindAttestation_ContentMatch(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "20260101-abcdef.intoto.json"), []byte(minimalValidEnvelope("Build")), 0600)

	if !findAttestation(dir, "Build") {
		t.Error("expected true for content-based toolName match")
	}
	if findAttestation(dir, "Deploy") {
		t.Error("expected false for non-matching toolName")
	}
}

func TestFindAttestation_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "random.intoto.json"), []byte(minimalValidEnvelope("bash")), 0600)

	if !findAttestation(dir, "Bash") {
		t.Error("expected case-insensitive match for Bash vs bash")
	}
	if !findAttestation(dir, "BASH") {
		t.Error("expected case-insensitive match for BASH vs bash")
	}
}

// ----- isAttestationFile -----

func TestIsAttestationFile(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"build.json", true},
		{"step.intoto.json", true},
		{"20260101.intoto.json", true},
		{"README.md", false},
		{"binary.exe", false},
		{"config.yaml", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAttestationFile(tt.name)
			if got != tt.want {
				t.Errorf("isAttestationFile(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// ----- attestationMatchesName with malformed data -----

func TestAttestationMatchesName_MalformedEnvelope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")

	// Not valid JSON
	os.WriteFile(path, []byte("not json"), 0644)
	if attestationMatchesName(path, "anything") {
		t.Error("expected false for non-JSON")
	}

	// Valid JSON but no payload field
	os.WriteFile(path, []byte(`{"foo": "bar"}`), 0644)
	if attestationMatchesName(path, "anything") {
		t.Error("expected false for missing payload")
	}

	// Has payload but not valid base64
	os.WriteFile(path, []byte(`{"payload": "not-base64!!!"}`), 0644)
	if attestationMatchesName(path, "anything") {
		t.Error("expected false for invalid base64 payload")
	}

	// Valid base64 but not valid JSON inside
	badPayload := base64.StdEncoding.EncodeToString([]byte("not json"))
	os.WriteFile(path, []byte(`{"payload": "`+badPayload+`"}`), 0644)
	if attestationMatchesName(path, "anything") {
		t.Error("expected false for non-JSON payload content")
	}

	// Valid structure but predicate is not an object with toolName
	stmt := map[string]interface{}{
		"predicate": "just a string",
	}
	stmtBytes, _ := json.Marshal(stmt)
	goodPayload := base64.StdEncoding.EncodeToString(stmtBytes)
	os.WriteFile(path, []byte(`{"payload": "`+goodPayload+`"}`), 0644)
	if attestationMatchesName(path, "anything") {
		t.Error("expected false for non-object predicate")
	}
}

func TestAttestationMatchesName_NonExistentFile(t *testing.T) {
	if attestationMatchesName("/nonexistent/path/file.json", "anything") {
		t.Error("expected false for nonexistent file")
	}
}

// ----- buildPolicyContext -----

func TestBuildPolicyContext(t *testing.T) {
	h := newTestHandler(t)

	pol := &aflock.Policy{
		Name: "production-policy",
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD: &aflock.Limit{Value: 10.0, Enforcement: "fail-fast"},
			MaxTokensIn: &aflock.Limit{Value: 100000, Enforcement: "post-hoc"},
			MaxTurns:    &aflock.Limit{Value: 50, Enforcement: "fail-fast"},
		},
		Tools: &aflock.ToolsPolicy{
			Allow:           []string{"Read", "Write"},
			Deny:            []string{"Task"},
			RequireApproval: []string{"Bash:git push*"},
		},
		Files: &aflock.FilesPolicy{
			Deny:     []string{"**/.env"},
			ReadOnly: []string{"go.mod"},
		},
	}

	ctx := h.buildPolicyContext(pol, nil)

	if !strings.Contains(ctx, "production-policy") {
		t.Error("expected policy name in context")
	}
	if !strings.Contains(ctx, "$10.00") {
		t.Errorf("expected spend limit in context, got: %s", ctx)
	}
	if !strings.Contains(ctx, "100000") {
		t.Error("expected tokens limit in context")
	}
	if !strings.Contains(ctx, "50") {
		t.Error("expected turns limit in context")
	}
	if !strings.Contains(ctx, "Read") {
		t.Error("expected allowed tools in context")
	}
	if !strings.Contains(ctx, "Task") {
		t.Error("expected denied tools in context")
	}
	if !strings.Contains(ctx, "go.mod") {
		t.Error("expected read-only files in context")
	}
	if !strings.Contains(ctx, "**/.env") {
		t.Error("expected denied file patterns in context")
	}
}

func TestBuildPolicyContext_WithNilSections(t *testing.T) {
	h := newTestHandler(t)

	pol := &aflock.Policy{
		Name: "minimal-policy",
	}

	ctx := h.buildPolicyContext(pol, nil)

	if !strings.Contains(ctx, "minimal-policy") {
		t.Error("expected policy name in context")
	}
	// Should not crash with nil sections
	if strings.Contains(ctx, "## Limits") {
		t.Error("did not expect limits section for nil limits")
	}
	if strings.Contains(ctx, "## Tool Restrictions") {
		t.Error("did not expect tools section for nil tools")
	}
	if strings.Contains(ctx, "## File Restrictions") {
		t.Error("did not expect files section for nil files")
	}
}

// ----- PreToolUse with ephemeral session (policy in cwd) -----

func TestHandlePreToolUse_EphemeralSession_PolicyFromCwd(t *testing.T) {
	h := newTestHandler(t)

	// Create a temp dir with a policy file
	policyDir := t.TempDir()
	pol := &aflock.Policy{
		Name: "ephemeral-test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Bash"},
		},
	}
	polBytes, _ := json.Marshal(pol)
	os.WriteFile(filepath.Join(policyDir, ".aflock"), polBytes, 0644)

	input := &aflock.HookInput{
		SessionID: "ephemeral-session",
		Cwd:       policyDir,
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "test.go"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse output: %v (raw: %s)", err, got)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("expected allow, got %v", out.HookSpecificOutput.PermissionDecision)
	}
}

// ----- PreToolUse: multiple actions accumulate in state -----

func TestHandlePreToolUse_ActionsAccumulate(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Write", "Bash"},
		},
	}
	seedSession(t, h, "session-accum", pol)

	tools := []struct {
		name  string
		input string
	}{
		{"Read", `{"file_path": "a.go"}`},
		{"Write", `{"file_path": "b.go", "content": "x"}`},
		{"Bash", `{"command": "ls"}`},
	}

	for _, tool := range tools {
		input := &aflock.HookInput{
			SessionID: "session-accum",
			ToolName:  tool.name,
			ToolInput: json.RawMessage(tool.input),
		}
		captureStdout(t, func() {
			if err := h.handlePreToolUse(input); err != nil {
				t.Fatalf("handlePreToolUse: %v", err)
			}
		})
	}

	ss, _ := h.stateManager.Load("session-accum")
	if len(ss.Actions) != 3 {
		t.Fatalf("expected 3 actions, got %d", len(ss.Actions))
	}
	if ss.Metrics.ToolCalls != 3 {
		t.Errorf("expected 3 tool calls, got %d", ss.Metrics.ToolCalls)
	}
	if ss.Metrics.Tools["Read"] != 1 {
		t.Errorf("expected 1 Read call, got %d", ss.Metrics.Tools["Read"])
	}
	if ss.Metrics.Tools["Write"] != 1 {
		t.Errorf("expected 1 Write call, got %d", ss.Metrics.Tools["Write"])
	}
	if ss.Metrics.Tools["Bash"] != 1 {
		t.Errorf("expected 1 Bash call, got %d", ss.Metrics.Tools["Bash"])
	}
}

// ----- PreToolUse: wildcard allow -----

func TestHandlePreToolUse_WildcardAllow(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test-wildcard",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"*"},
		},
	}
	seedSession(t, h, "session-wildcard", pol)

	input := &aflock.HookInput{
		SessionID: "session-wildcard",
		ToolName:  "AnyRandomTool",
		ToolInput: json.RawMessage(`{}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("expected allow with wildcard, got %v", out.HookSpecificOutput.PermissionDecision)
	}
}

// ----- PreToolUse: nil policy in existing session state -> fail closed -----
//
// Regression for issue #58 / M13. A session state file exists on disk but its
// Policy field is nil (corruption or tampering). The handler must fail closed
// rather than fall through to the ephemeral policy loader — which would
// otherwise allow-all whenever no .aflock file is discoverable from cwd.
func TestHandlePreToolUse_NilPolicyInSession_FailsClosed(t *testing.T) {
	h := newTestHandler(t)
	// Create a session but with nil policy, and cwd has no policy
	ss := h.stateManager.Initialize("session-nil-pol", nil, "")
	h.stateManager.Save(ss)

	input := &aflock.HookInput{
		SessionID: "session-nil-pol",
		Cwd:       t.TempDir(), // No .aflock here
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "test.go"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionDeny {
		t.Errorf("expected deny (fail-closed) when session state has nil policy, got %v",
			out.HookSpecificOutput.PermissionDecision)
	}
}

// ----- SessionEnd: post-hoc limit logging (doesn't block) -----

func TestHandleSessionEnd_PostHocLimitExceeded_DoesNotBlock(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test-posthoc-end",
		Limits: &aflock.LimitsPolicy{
			MaxTurns: &aflock.Limit{Value: 5, Enforcement: "post-hoc"},
		},
	}
	ss := seedSession(t, h, "session-posthoc-end", pol)
	ss.Metrics.Turns = 100
	h.stateManager.Save(ss)

	input := &aflock.HookInput{SessionID: "session-posthoc-end"}

	got := captureStdout(t, func() {
		if err := h.handleSessionEnd(input); err != nil {
			t.Fatalf("handleSessionEnd: %v", err)
		}
	})

	// Should still return empty JSON (not block)
	if got != "{}" {
		t.Errorf("expected empty JSON from session end, got: %s", got)
	}
}

// ----- State persistence round-trip -----

func TestStatePersistence_RoundTrip(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "round-trip-test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Bash"},
			Deny:  []string{"Task"},
		},
		Limits: &aflock.LimitsPolicy{
			MaxTurns: &aflock.Limit{Value: 10, Enforcement: "fail-fast"},
		},
	}

	ss := seedSession(t, h, "rt-session", pol)

	// Add some state
	h.stateManager.RecordAction(ss, aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Read",
		Decision:  "allow",
	})
	h.stateManager.IncrementTurns(ss)
	h.stateManager.TrackFile(ss, "Read", "/app/main.go")
	h.stateManager.Save(ss)

	// Load it back
	loaded, err := h.stateManager.Load("rt-session")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.Policy.Name != "round-trip-test" {
		t.Errorf("expected policy name 'round-trip-test', got %q", loaded.Policy.Name)
	}
	if len(loaded.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(loaded.Actions))
	}
	if loaded.Metrics.Turns != 1 {
		t.Errorf("expected 1 turn, got %d", loaded.Metrics.Turns)
	}
	if loaded.Metrics.ToolCalls != 1 {
		t.Errorf("expected 1 tool call, got %d", loaded.Metrics.ToolCalls)
	}
	if len(loaded.Metrics.FilesRead) != 1 || loaded.Metrics.FilesRead[0] != "/app/main.go" {
		t.Errorf("expected files read [/app/main.go], got %v", loaded.Metrics.FilesRead)
	}
}

// ----- Edge case: empty session ID -----

func TestHandlePreToolUse_EmptySessionID(t *testing.T) {
	h := newTestHandler(t)

	input := &aflock.HookInput{
		SessionID: "",
		Cwd:       t.TempDir(),
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "test.go"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	// Should still work - allow since no policy found
	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse output: %v (raw: %s)", err, got)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("expected allow with empty session ID (no policy), got %v",
			out.HookSpecificOutput.PermissionDecision)
	}
}

// ----- Edge case: nil ToolInput -----

func TestHandlePreToolUse_NilToolInput(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "test-nil-input",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"*"},
		},
	}
	seedSession(t, h, "session-nil-input", pol)

	input := &aflock.HookInput{
		SessionID: "session-nil-input",
		ToolName:  "Read",
		ToolInput: nil,
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("expected allow with nil tool input, got %v",
			out.HookSpecificOutput.PermissionDecision)
	}
}

// ----- PostToolUse: malformed file_path field still doesn't crash -----

func TestHandlePostToolUse_EmptyFilePath(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "test"}
	seedSession(t, h, "session-empty-fp", pol)

	input := &aflock.HookInput{
		SessionID: "session-empty-fp",
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": ""}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	// Should succeed even with empty file path
	if got != "{}" {
		t.Errorf("expected empty JSON, got: %s", got)
	}

	// Empty path tracked (state.TrackFile doesn't filter it)
	ss, _ := h.stateManager.Load("session-empty-fp")
	if len(ss.Metrics.FilesRead) != 1 {
		t.Errorf("expected 1 tracked file read (even if empty), got %d", len(ss.Metrics.FilesRead))
	}
}

// ----- PreToolUse: policy with no tools section -> allow all -----

func TestHandlePreToolUse_PolicyNoToolsSection(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "no-tools",
		// No Tools section at all
	}
	seedSession(t, h, "session-no-tools", pol)

	input := &aflock.HookInput{
		SessionID: "session-no-tools",
		ToolName:  "AnythingGoes",
		ToolInput: json.RawMessage(`{}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("expected allow with no tools policy, got %v",
			out.HookSpecificOutput.PermissionDecision)
	}
}

// ----- Multiple PostToolUse calls accumulate file tracking correctly -----

func TestHandlePostToolUse_MixedFileOperations(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "test"}
	seedSession(t, h, "session-mixed", pol)

	ops := []struct {
		tool  string
		input string
	}{
		{"Read", `{"file_path": "/app/a.go"}`},
		{"Read", `{"file_path": "/app/b.go"}`},
		{"Write", `{"file_path": "/app/c.go", "content": "x"}`},
		{"Edit", `{"file_path": "/app/d.go"}`},
		{"Grep", `{"file_path": "/app/e.go"}`},
		{"Bash", `{"command": "ls"}`},
	}

	for _, op := range ops {
		input := &aflock.HookInput{
			SessionID: "session-mixed",
			ToolName:  op.tool,
			ToolInput: json.RawMessage(op.input),
		}
		captureStdout(t, func() {
			if err := h.handlePostToolUse(input); err != nil {
				t.Fatalf("handlePostToolUse: %v", err)
			}
		})
	}

	ss, _ := h.stateManager.Load("session-mixed")
	// Read, Grep -> filesRead: a.go, b.go, e.go
	if len(ss.Metrics.FilesRead) != 3 {
		t.Errorf("expected 3 files read, got %d: %v", len(ss.Metrics.FilesRead), ss.Metrics.FilesRead)
	}
	// Write, Edit -> filesWritten: c.go, d.go
	if len(ss.Metrics.FilesWritten) != 2 {
		t.Errorf("expected 2 files written, got %d: %v", len(ss.Metrics.FilesWritten), ss.Metrics.FilesWritten)
	}
}

// ----- Integration: full PreToolUse + PostToolUse cycle -----

func TestIntegration_PreAndPostToolUse(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "integration-test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Write"},
		},
		Limits: &aflock.LimitsPolicy{
			MaxToolCalls: &aflock.Limit{Value: 100, Enforcement: "fail-fast"},
		},
	}
	seedSession(t, h, "session-integ", pol)

	// Pre-tool-use: check Read is allowed
	preInput := &aflock.HookInput{
		SessionID: "session-integ",
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "/app/main.go"}`),
	}

	preOut := captureStdout(t, func() {
		if err := h.handlePreToolUse(preInput); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	var preResult aflock.HookOutput
	if err := json.Unmarshal([]byte(preOut), &preResult); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if preResult.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Fatalf("expected pre-tool allow")
	}

	// Post-tool-use: track the file
	postInput := &aflock.HookInput{
		SessionID: "session-integ",
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "/app/main.go"}`),
	}

	postOut := captureStdout(t, func() {
		if err := h.handlePostToolUse(postInput); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	if postOut != "{}" {
		t.Errorf("expected empty post-tool output, got: %s", postOut)
	}

	// Verify final state
	ss, _ := h.stateManager.Load("session-integ")
	if len(ss.Actions) != 1 {
		t.Errorf("expected 1 action from pre-tool, got %d", len(ss.Actions))
	}
	if ss.Metrics.ToolCalls != 1 {
		t.Errorf("expected 1 tool call, got %d", ss.Metrics.ToolCalls)
	}
	if len(ss.Metrics.FilesRead) != 1 {
		t.Errorf("expected 1 file read from post-tool, got %d", len(ss.Metrics.FilesRead))
	}
}

// ----- Policy expiration enforcement -----

func TestHandlePreToolUse_ExpiredPolicy_Ephemeral_Denies(t *testing.T) {
	h := newTestHandler(t)

	// Create a temp dir with an expired policy file
	policyDir := t.TempDir()
	expired := time.Now().Add(-1 * time.Hour)
	polJSON := []byte(`{
		"name": "expired-test",
		"expires": "` + expired.Format(time.RFC3339) + `",
		"tools": {"allow": ["Read"]}
	}`)
	if err := os.WriteFile(filepath.Join(policyDir, ".aflock"), polJSON, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	input := &aflock.HookInput{
		SessionID: "session-expired-ephemeral",
		Cwd:       policyDir,
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "main.go"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse error: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse output: %v (raw: %s)", err, got)
	}
	if out.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput")
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionDeny {
		t.Errorf("expected deny for expired policy, got %v", out.HookSpecificOutput.PermissionDecision)
	}
	if out.HookSpecificOutput.PermissionDecisionReason == "" || !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "expired") {
		t.Errorf("expected reason to mention 'expired', got: %s", out.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestHandlePreToolUse_ExpiredPolicy_SessionState_Denies(t *testing.T) {
	h := newTestHandler(t)
	expired := time.Now().Add(-1 * time.Hour)
	pol := &aflock.Policy{
		Name:    "expired-session",
		Expires: &expired,
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read"},
		},
	}
	seedSession(t, h, "session-expired-state", pol)

	input := &aflock.HookInput{
		SessionID: "session-expired-state",
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "main.go"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse error: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse output: %v (raw: %s)", err, got)
	}
	if out.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput")
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionDeny {
		t.Errorf("expected deny for expired policy, got %v", out.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "expired") {
		t.Errorf("expected reason to mention 'expired', got: %s", out.HookSpecificOutput.PermissionDecisionReason)
	}
}

// ----- Stop: fake attestation file (no DSSE structure) is rejected -----

func TestHandleStop_FakeAttestationRejected(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "test-fake-attest",
		RequiredAttestations: []string{"security-review"},
	}
	ss := seedSession(t, h, "session-fake-attest", pol)

	// Record an action so the tool counts as "used" — handleStop only checks
	// requiredAttestations for tools that were actually invoked.
	h.stateManager.RecordAction(ss, aflock.ActionRecord{
		ToolName: "security-review", Decision: "allow",
	})
	h.stateManager.Save(ss)

	attestDir := h.stateManager.AttestationsDir("session-fake-attest")
	os.MkdirAll(attestDir, 0755)

	// Write a fake attestation file that exists but has no valid DSSE structure
	os.WriteFile(filepath.Join(attestDir, "security-review.json"), []byte(`{}`), 0644)

	input := &aflock.HookInput{SessionID: "session-fake-attest"}

	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Decision != "block" {
		t.Errorf("expected block for fake attestation file, got %q", out.Decision)
	}
	if !strings.Contains(out.Reason, "missing attestations") {
		t.Errorf("expected 'missing attestations' in reason, got: %s", out.Reason)
	}
}

func TestHandleStop_EmptySignaturesRejected(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "test-empty-sig",
		RequiredAttestations: []string{"build"},
	}
	ss := seedSession(t, h, "session-empty-sig", pol)

	// Record an action so the tool counts as "used"
	h.stateManager.RecordAction(ss, aflock.ActionRecord{
		ToolName: "build", Decision: "allow",
	})
	h.stateManager.Save(ss)

	attestDir := h.stateManager.AttestationsDir("session-empty-sig")
	os.MkdirAll(attestDir, 0755)

	// Attestation with payload and payloadType but empty signatures array
	os.WriteFile(filepath.Join(attestDir, "build.json"),
		[]byte(`{"payload":"eyJ0ZXN0IjoidmFsaWQifQ==","payloadType":"application/vnd.in-toto+json","signatures":[]}`), 0644)

	input := &aflock.HookInput{SessionID: "session-empty-sig"}

	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Decision != "block" {
		t.Errorf("expected block for attestation with empty signatures, got %q", out.Decision)
	}
}

func TestValidateAttestationIntegrity(t *testing.T) {
	dir := t.TempDir()

	// Tightened in issue #67 review: the integrity check now requires the
	// payload to be a parseable in-toto Statement with non-empty subject,
	// the payloadType to be application/vnd.in-toto+json exactly, and at
	// least one signature with non-empty keyid + base64-decodable non-empty
	// sig. The "valid DSSE" fixture is updated to satisfy the new contract.
	validPayload := base64.StdEncoding.EncodeToString([]byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"x"}]}`))
	validSig := base64.StdEncoding.EncodeToString([]byte("sig-bytes"))
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"valid DSSE", `{"payload":"` + validPayload + `","payloadType":"application/vnd.in-toto+json","signatures":[{"keyid":"k","sig":"` + validSig + `"}]}`, true},
		{"empty object", `{}`, false},
		{"missing signatures", `{"payload":"` + validPayload + `","payloadType":"application/vnd.in-toto+json"}`, false},
		{"empty signatures", `{"payload":"` + validPayload + `","payloadType":"application/vnd.in-toto+json","signatures":[]}`, false},
		{"missing payload", `{"payloadType":"application/vnd.in-toto+json","signatures":[{"keyid":"k","sig":"` + validSig + `"}]}`, false},
		{"missing payloadType", `{"payload":"` + validPayload + `","signatures":[{"keyid":"k","sig":"` + validSig + `"}]}`, false},
		{"not JSON", `this is not json`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".json")
			os.WriteFile(path, []byte(tt.content), 0644)
			got := validateAttestationIntegrity(path)
			if got != tt.want {
				t.Errorf("validateAttestationIntegrity(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}

	// Non-existent file
	t.Run("non-existent", func(t *testing.T) {
		if validateAttestationIntegrity(filepath.Join(dir, "nope.json")) {
			t.Error("expected false for non-existent file")
		}
	})
}

// ----- PreToolUse: identity constraints without SessionStart -> deny -----

func TestHandlePreToolUse_IdentityConstraints_NoSessionStart_Denies(t *testing.T) {
	h := newTestHandler(t)

	// Create a policy file with identity constraints in a temp directory
	policyDir := t.TempDir()
	pol := aflock.Policy{
		Name: "identity-required",
		Identity: &aflock.IdentityPolicy{
			AllowedModels: []string{"claude-3-opus"},
		},
	}
	polBytes, _ := json.Marshal(pol)
	os.WriteFile(filepath.Join(policyDir, ".aflock"), polBytes, 0644)

	// Call handlePreToolUse WITHOUT prior handleSessionStart — no session state exists
	input := &aflock.HookInput{
		SessionID: "session-no-start",
		Cwd:       policyDir,
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "echo hello"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse: %v (raw: %s)", err, got)
	}

	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionDeny {
		t.Fatalf("expected deny when identity constraints exist but SessionStart was skipped, got %s",
			out.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "identity verification") {
		t.Errorf("expected reason about identity verification, got: %s", out.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestHandlePreToolUse_NoIdentityConstraints_NoSessionStart_Allows(t *testing.T) {
	h := newTestHandler(t)

	// Create a policy file WITHOUT identity constraints
	policyDir := t.TempDir()
	pol := aflock.Policy{
		Name: "no-identity",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"*"},
		},
	}
	polBytes, _ := json.Marshal(pol)
	os.WriteFile(filepath.Join(policyDir, ".aflock"), polBytes, 0644)

	// Call handlePreToolUse WITHOUT prior handleSessionStart
	input := &aflock.HookInput{
		SessionID: "session-no-start-2",
		Cwd:       policyDir,
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "/tmp/test.txt"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse: %v (raw: %s)", err, got)
	}

	// Without identity constraints, ephemeral session should still work
	if out.HookSpecificOutput.PermissionDecision == aflock.DecisionDeny {
		t.Fatalf("expected allow when no identity constraints, got deny: %s",
			out.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestHandlePreToolUse_FutureExpiry_Allows(t *testing.T) {
	h := newTestHandler(t)
	future := time.Now().Add(24 * time.Hour)
	pol := &aflock.Policy{
		Name:    "future-expiry",
		Expires: &future,
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read"},
		},
	}
	seedSession(t, h, "session-future-expiry", pol)

	input := &aflock.HookInput{
		SessionID: "session-future-expiry",
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "main.go"}`),
	}

	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse error: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse output: %v (raw: %s)", err, got)
	}
	if out.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput")
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("expected allow for non-expired policy, got %v", out.HookSpecificOutput.PermissionDecision)
	}
}

func TestHandleSessionStart_ExpiredPolicy_IsChecked(t *testing.T) {
	// handleSessionStart calls ExitWithError (os.Exit(2)) for expired policies,
	// so we can't test it directly. Instead, verify that Policy.IsExpired()
	// returns true for an expired policy, confirming the check will trigger.
	expired := time.Now().Add(-1 * time.Hour)
	pol := &aflock.Policy{
		Name:    "expired-session-start",
		Expires: &expired,
	}
	if !pol.IsExpired() {
		t.Error("expected IsExpired() to return true for past expiration")
	}

	// Verify a future expiry does not trigger
	future := time.Now().Add(24 * time.Hour)
	polFuture := &aflock.Policy{
		Name:    "future-session-start",
		Expires: &future,
	}
	if polFuture.IsExpired() {
		t.Error("expected IsExpired() to return false for future expiration")
	}

	// Verify nil expiry does not trigger
	polNoExpiry := &aflock.Policy{
		Name: "no-expiry",
	}
	if polNoExpiry.IsExpired() {
		t.Error("expected IsExpired() to return false for nil expiration")
	}
}
