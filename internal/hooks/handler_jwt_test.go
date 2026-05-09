package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/internal/auth"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// issueTokenForSession issues a session-bound JWT and writes the matching
// public key to the session directory. Mirrors what handleSessionStart now
// produces, but lets tests assemble it directly without going through
// stdin-based hook plumbing.
func issueTokenForSession(t *testing.T, h *Handler, sessionID string, pol *aflock.Policy) string {
	t.Helper()
	issuer, err := auth.NewTokenIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	token, err := issuer.IssueToken(sessionID, "a1", "h1", pol, time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	pubPEM, err := issuer.MarshalPublicKey()
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	dir := h.stateManager.SessionDir(sessionID)
	if mkErr := os.MkdirAll(dir, 0700); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}
	if writeErr := os.WriteFile(filepath.Join(dir, "jwt-pubkey.pem"), pubPEM, 0600); writeErr != nil {
		t.Fatalf("write pubkey: %v", writeErr)
	}
	return token
}

func decisionFromOutput(t *testing.T, raw string) (aflock.PermissionDecision, string) {
	t.Helper()
	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("parse output: %v (raw: %s)", err, raw)
	}
	if out.HookSpecificOutput == nil {
		t.Fatalf("expected hookSpecificOutput, got: %s", raw)
	}
	return out.HookSpecificOutput.PermissionDecision, out.HookSpecificOutput.PermissionDecisionReason
}

// TestPreToolUse_JWTValid_AllowedTool — the happy path. A valid JWT whose
// allowed_tools include the requested tool must allow the call.
func TestPreToolUse_JWTValid_AllowedTool(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:  "jwt-happy",
		Tools: &aflock.ToolsPolicy{Allow: []string{"Read", "Bash"}},
	}
	ss := seedSession(t, h, "session-jwt-happy", pol)
	ss.AuthToken = issueTokenForSession(t, h, "session-jwt-happy", pol)
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}

	got := captureStdout(t, func() {
		_ = h.handlePreToolUse(&aflock.HookInput{
			SessionID: "session-jwt-happy",
			ToolName:  "Read",
			ToolInput: json.RawMessage(`{"file_path":"main.go"}`),
		})
	})
	dec, _ := decisionFromOutput(t, got)
	if dec != aflock.DecisionAllow {
		t.Errorf("expected allow, got %v (raw: %s)", dec, got)
	}
}

// TestPreToolUse_JWTValid_ToolOutOfScope — the JWT is valid, but the
// requested tool is not in allowed_tools. The fix must reject this
// before the policy evaluator runs, which is the *whole point* of #48:
// the JWT scope is enforced at runtime, not just embedded.
func TestPreToolUse_JWTValid_ToolOutOfScope(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:  "jwt-scope",
		Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
	}
	ss := seedSession(t, h, "session-jwt-scope", pol)
	ss.AuthToken = issueTokenForSession(t, h, "session-jwt-scope", pol)
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}

	got := captureStdout(t, func() {
		_ = h.handlePreToolUse(&aflock.HookInput{
			SessionID: "session-jwt-scope",
			ToolName:  "Bash", // not in allowed_tools
			ToolInput: json.RawMessage(`{"command":"ls"}`),
		})
	})
	dec, reason := decisionFromOutput(t, got)
	if dec != aflock.DecisionDeny {
		t.Fatalf("expected deny, got %v (raw: %s)", dec, got)
	}
	if !strings.Contains(reason, "JWT scope") {
		t.Errorf("expected JWT scope reason, got: %s", reason)
	}
}

// TestPreToolUse_JWTTampered — flipping a single byte in the signature
// must fail validation. Uses a known invalid character to avoid producing
// another valid base64url string by accident.
func TestPreToolUse_JWTTampered(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:  "jwt-tamper",
		Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
	}
	ss := seedSession(t, h, "session-jwt-tamper", pol)
	token := issueTokenForSession(t, h, "session-jwt-tamper", pol)

	// Corrupt the signature segment (after the second dot).
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-part JWT, got %d", len(parts))
	}
	parts[2] = parts[2][:len(parts[2])-2] + "AA"
	ss.AuthToken = strings.Join(parts, ".")
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}

	got := captureStdout(t, func() {
		_ = h.handlePreToolUse(&aflock.HookInput{
			SessionID: "session-jwt-tamper",
			ToolName:  "Read",
			ToolInput: json.RawMessage(`{"file_path":"main.go"}`),
		})
	})
	dec, reason := decisionFromOutput(t, got)
	if dec != aflock.DecisionDeny {
		t.Fatalf("expected deny on tampered JWT, got %v (raw: %s)", dec, got)
	}
	if !strings.Contains(reason, "JWT validation failed") {
		t.Errorf("expected validation-failed reason, got: %s", reason)
	}
}

// TestPreToolUse_JWTPubKeyMissing — backward-compat for upgrades. A
// session with AuthToken set but no jwt-pubkey.pem on disk (because it
// was created by an older aflock) must NOT block. We log a warning and
// fall through to policy-only enforcement.
func TestPreToolUse_JWTPubKeyMissing(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:  "jwt-legacy",
		Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
	}
	ss := seedSession(t, h, "session-jwt-legacy", pol)
	// Set token but DO NOT write jwt-pubkey.pem — the legacy upgrade case.
	ss.AuthToken = "eyJsZWdhY3kiOiJ0b2tlbiJ9.x.y"
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}

	got := captureStdout(t, func() {
		_ = h.handlePreToolUse(&aflock.HookInput{
			SessionID: "session-jwt-legacy",
			ToolName:  "Read",
			ToolInput: json.RawMessage(`{"file_path":"main.go"}`),
		})
	})
	dec, _ := decisionFromOutput(t, got)
	// Falls through to policy: Read is allowed by policy → allow.
	if dec != aflock.DecisionAllow {
		t.Errorf("expected allow (legacy session, policy permits), got %v (raw: %s)", dec, got)
	}
}
