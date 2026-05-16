package hooks

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Issue #40 — hooks createAttestation must refuse to sign once SessionStart
// has issued a JWT but per-call validation fails (expired, wrong policy
// digest, missing pubkey on disk). Without this gate, a compromised agent
// could keep producing attestations after the JWT became invalid.
func TestPostToolUse_RefusesSigningWhenJWTValidationFails(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:  "issue-40-hooks",
		Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
	}
	ss := seedSession(t, h, "session-issue-40", pol)

	// Simulate the realistic broken path: AuthToken was issued but the
	// pubkey persisted alongside it is gone (e.g., deleted, corrupted, or
	// the session was migrated). buildJWTBindingForSession will return nil
	// and the new gate must skip signing.
	ss.AuthToken = "ey.bogus.token.signed-by-nobody"
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}
	_ = os.Remove(h.stateManager.SessionDir("session-issue-40") + "/jwt-pubkey.pem")

	input := &aflock.HookInput{
		SessionID: "session-issue-40",
		ToolName:  "Read",
		ToolUseID: "tu-issue-40",
		ToolInput: json.RawMessage(`{"file_path":"x"}`),
	}
	captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	attestDir := h.stateManager.AttestationsDir("session-issue-40")
	entries, _ := os.ReadDir(attestDir)
	if len(entries) != 0 {
		t.Errorf("attestation produced despite failed JWT validation (issue #40), files: %d", len(entries))
	}
}
