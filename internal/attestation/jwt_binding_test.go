package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// TestActionAttestation_NoJWTBinding — backward-compat path. Existing
// callers that omit the JWT binding still produce an attestation with no
// jwtBinding field in the predicate.
func TestActionAttestation_NoJWTBinding(t *testing.T) {
	signer := NewSigner("")
	if err := signer.InitializeEphemeral("hash-1"); err != nil {
		t.Fatalf("init signer: %v", err)
	}
	defer signer.Close() //nolint:errcheck

	rec := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Read",
		ToolUseID: "tu-1",
		Decision:  "allow",
	}
	env, err := signer.CreateActionAttestation(context.Background(), rec, "session-no-jwt", nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateActionAttestation: %v", err)
	}

	pred := decodePredicate(t, env)
	if pred.JWTBinding != nil {
		t.Errorf("expected no jwtBinding when binding arg omitted, got %+v", pred.JWTBinding)
	}
}

// TestActionAttestation_WithJWTBinding — issue #40 happy path. The
// supplied binding must round-trip into the predicate verbatim so a
// downstream verifier can prove the action was authorized by a token
// with the listed scope.
func TestActionAttestation_WithJWTBinding(t *testing.T) {
	signer := NewSigner("")
	if err := signer.InitializeEphemeral("hash-2"); err != nil {
		t.Fatalf("init signer: %v", err)
	}
	defer signer.Close() //nolint:errcheck

	binding := &JWTBinding{
		SessionID:    "session-abc",
		JTI:          "jti-1",
		KeyID:        "spiffe://aflock.local/agent/aflock",
		PolicyDigest: "deadbeef",
		TokenSHA256:  "feedface",
		AllowedTools: []string{"Read", "Bash"},
		DeniedTools:  []string{"WebFetch"},
	}
	rec := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Bash",
		ToolUseID: "tu-2",
		Decision:  "allow",
	}
	env, err := signer.CreateActionAttestation(context.Background(), rec, "session-abc", nil, nil, &AttestationContext{JWT: binding})
	if err != nil {
		t.Fatalf("CreateActionAttestation: %v", err)
	}

	pred := decodePredicate(t, env)
	if pred.JWTBinding == nil {
		t.Fatal("expected jwtBinding in predicate, got nil")
	}
	if pred.JWTBinding.JTI != "jti-1" {
		t.Errorf("jti = %q, want %q", pred.JWTBinding.JTI, "jti-1")
	}
	if pred.JWTBinding.KeyID != binding.KeyID {
		t.Errorf("kid = %q, want %q", pred.JWTBinding.KeyID, binding.KeyID)
	}
	if pred.JWTBinding.TokenSHA256 != "feedface" {
		t.Errorf("tokenSha256 = %q, want %q", pred.JWTBinding.TokenSHA256, "feedface")
	}
	if len(pred.JWTBinding.AllowedTools) != 2 || pred.JWTBinding.AllowedTools[0] != "Read" {
		t.Errorf("allowedTools mismatch: %v", pred.JWTBinding.AllowedTools)
	}
	if len(pred.JWTBinding.DeniedTools) != 1 || pred.JWTBinding.DeniedTools[0] != "WebFetch" {
		t.Errorf("deniedTools mismatch: %v", pred.JWTBinding.DeniedTools)
	}
}

// decodePredicate base64-decodes the DSSE payload and parses it as an
// ActionPredicate so tests can assert on the embedded fields.
func decodePredicate(t *testing.T, env *Envelope) *ActionPredicate {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var stmt struct {
		Predicate ActionPredicate `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}
	return &stmt.Predicate
}
