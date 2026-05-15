package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/internal/auth"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// TestBuildJWTBinding_NoClaims — graceful adoption: pre-token tool calls
// produce no binding, so the attestation has no JWT context.
func TestBuildJWTBinding_NoClaims(t *testing.T) {
	s := newTestServer(t)
	got := s.buildJWTBinding(callRequest(map[string]any{"_token": "x"}), nil)
	if got != nil {
		t.Errorf("expected nil binding when claims is nil, got %+v", got)
	}
}

// TestBuildJWTBinding_NoTokenInRequest — claims came from somewhere
// (test fixture), but the request didn't carry _token. We can't compute
// a token digest without the token itself, so we return nil.
func TestBuildJWTBinding_NoTokenInRequest(t *testing.T) {
	s := newTestServer(t)
	got := s.buildJWTBinding(callRequest(nil), &auth.AflockClaims{})
	if got != nil {
		t.Errorf("expected nil binding when _token absent, got %+v", got)
	}
}

// TestBuildJWTBinding_Happy — claims and token present: the binding
// reflects the claims and the token digest matches sha256(token). This
// is the per-call audit trail entry that the verifier matches against
// its issuance log to prove "this action used that token."
func TestBuildJWTBinding_Happy(t *testing.T) {
	s := newTestServerWithPolicy(t, &aflock.Policy{
		Name:    "happy-binding",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Bash"}, Deny: []string{"WebFetch"}},
	})
	issuer, err := auth.NewTokenIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	s.tokenIssuer = issuer

	token, err := issuer.IssueToken(s.sessionID, "agent-1", "h-1", s.policy, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := issuer.ValidateTokenForSessionAndPolicy(token, s.sessionID, s.computePolicyDigest())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	binding := s.buildJWTBinding(callRequest(map[string]any{"_token": token}), claims)
	if binding == nil {
		t.Fatal("expected binding")
	}
	if binding.SessionID != s.sessionID {
		t.Errorf("sessionID = %q, want %q", binding.SessionID, s.sessionID)
	}
	want := sha256.Sum256([]byte(token))
	if binding.TokenSHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("tokenSha256 mismatch")
	}
	if binding.KeyID != issuer.KeyID() {
		t.Errorf("kid = %q, want %q", binding.KeyID, issuer.KeyID())
	}
	if binding.PolicyDigest != claims.PolicyDigest {
		t.Errorf("policyDigest mismatch")
	}
	if !sliceContains(binding.AllowedTools, "Bash") || !sliceContains(binding.DeniedTools, "WebFetch") {
		t.Errorf("scope mismatch: allowed=%v denied=%v", binding.AllowedTools, binding.DeniedTools)
	}
}

func sliceContains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
