package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// seedSessionWithPolicyFile writes pol to <tmpdir>/.aflock and initializes a
// session bound to that real on-disk file, so the issue #100 tamper and
// self-protection checks run against realistic state.
func seedSessionWithPolicyFile(t *testing.T, h *Handler, sessionID string, pol *aflock.Policy) (policyDir, policyPath string) {
	t.Helper()
	policyDir = t.TempDir()
	policyPath = filepath.Join(policyDir, ".aflock")
	polBytes, err := json.Marshal(pol)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, polBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	ss := h.stateManager.Initialize(sessionID, pol, policyPath)
	if ss.PolicyDigest == "" {
		t.Fatal("expected Initialize to capture PolicyDigest from the on-disk policy file")
	}
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatal(err)
	}
	return policyDir, policyPath
}

func preToolUseDecision(t *testing.T, h *Handler, input *aflock.HookInput) (aflock.PermissionDecision, string) {
	t.Helper()
	got := captureStdout(t, func() {
		if err := h.handlePreToolUse(input); err != nil {
			t.Fatalf("handlePreToolUse: %v", err)
		}
	})
	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse output: %v (raw: %s)", err, got)
	}
	if out.HookSpecificOutput == nil {
		t.Fatalf("expected hookSpecificOutput, got: %s", got)
	}
	return out.HookSpecificOutput.PermissionDecision, out.HookSpecificOutput.PermissionDecisionReason
}

// TestPreToolUse_PolicyTamper proves the issue #100 fail-closed behavior:
// once the on-disk policy file diverges from the digest frozen at session
// init, every tool call is denied — even ones the (rewritten) policy allows.
func TestPreToolUse_PolicyTamper(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:  "tamper-test",
		Tools: &aflock.ToolsPolicy{Allow: []string{"Read", "Write", "Bash"}},
	}
	policyDir, policyPath := seedSessionWithPolicyFile(t, h, "sess-tamper", pol)

	input := &aflock.HookInput{
		SessionID: "sess-tamper",
		Cwd:       policyDir,
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "main.go"}`),
	}

	if decision, reason := preToolUseDecision(t, h, input); decision != aflock.DecisionAllow {
		t.Fatalf("happy path: expected allow, got %s (%s)", decision, reason)
	}

	// Agent rewrites the policy to grant itself everything.
	if err := os.WriteFile(policyPath, []byte(`{"version":"1.0","name":"tamper-test","tools":{"allow":["*"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	decision, reason := preToolUseDecision(t, h, input)
	if decision != aflock.DecisionDeny {
		t.Fatalf("expected deny after policy rewrite, got %s", decision)
	}
	if !strings.Contains(reason, "digest mismatch") || !strings.Contains(reason, "issue #100") {
		t.Errorf("unexpected deny reason: %q", reason)
	}

	// Deleting the policy file is tampering too (fail closed).
	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	if decision, _ := preToolUseDecision(t, h, input); decision != aflock.DecisionDeny {
		t.Fatalf("expected deny after policy deletion, got %s", decision)
	}
}

// TestPreToolUse_SelfProtect proves that guardrail files are off-limits even
// when the policy explicitly allows the tool (issue #100).
func TestPreToolUse_SelfProtect(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:  "selfprotect-test",
		Tools: &aflock.ToolsPolicy{Allow: []string{"Read", "Write", "Edit", "Bash"}},
	}
	policyDir, policyPath := seedSessionWithPolicyFile(t, h, "sess-selfprotect", pol)

	tests := []struct {
		name       string
		toolName   string
		toolInput  string
		wantDeny   bool
		wantReason string
	}{
		{
			name:       "bash heredoc rewrite of .aflock -> denied (#100 repro)",
			toolName:   "Bash",
			toolInput:  `{"command": "cat > ` + policyPath + ` << 'AFLOCK_EOF'\n{}\nAFLOCK_EOF"}`,
			wantDeny:   true,
			wantReason: "issue #100",
		},
		{
			name:      "bash read of .aflock -> allowed",
			toolName:  "Bash",
			toolInput: `{"command": "cat .aflock"}`,
			wantDeny:  false,
		},
		{
			name:       "write to .aflock -> denied despite Write being allowed",
			toolName:   "Write",
			toolInput:  `{"file_path": "` + policyPath + `", "content": "{}"}`,
			wantDeny:   true,
			wantReason: "guardrail",
		},
		{
			name:      "write to source file -> allowed",
			toolName:  "Write",
			toolInput: `{"file_path": "` + filepath.Join(policyDir, "src", "main.go") + `", "content": "package main"}`,
			wantDeny:  false,
		},
		{
			name:       "edit to .claude/settings.json -> denied",
			toolName:   "Edit",
			toolInput:  `{"file_path": "` + filepath.Join(policyDir, ".claude", "settings.json") + `"}`,
			wantDeny:   true,
			wantReason: "guardrail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &aflock.HookInput{
				SessionID: "sess-selfprotect",
				Cwd:       policyDir,
				ToolName:  tt.toolName,
				ToolInput: json.RawMessage(tt.toolInput),
			}
			decision, reason := preToolUseDecision(t, h, input)
			if tt.wantDeny {
				if decision != aflock.DecisionDeny {
					t.Fatalf("expected deny, got %s (%s)", decision, reason)
				}
				if !strings.Contains(reason, tt.wantReason) {
					t.Errorf("deny reason %q does not contain %q", reason, tt.wantReason)
				}
			} else if decision != aflock.DecisionAllow {
				t.Fatalf("expected allow, got %s (%s)", decision, reason)
			}
		})
	}
}
