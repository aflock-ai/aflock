package hooks

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/internal/auth"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// TestBuildJWTBindingForSession_Happy — when a valid token + matching
// pubkey are persisted, the binding reflects the token's claims.
func TestBuildJWTBindingForSession_Happy(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:  "binding-happy",
		Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}, Deny: []string{"WebFetch"}},
	}
	ss := seedSession(t, h, "session-binding-happy", pol)

	issuer, err := auth.NewTokenIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	token, err := issuer.IssueToken("session-binding-happy", "agent-1", "h1", pol, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	pubPEM, err := issuer.MarshalPublicKey()
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	dir := h.stateManager.SessionDir("session-binding-happy")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "jwt-pubkey.pem"), pubPEM, 0600); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}
	ss.AuthToken = token

	binding := h.buildJWTBindingForSession(ss)
	if binding == nil {
		t.Fatal("expected binding, got nil")
	}
	if binding.SessionID != "session-binding-happy" {
		t.Errorf("sessionID = %q", binding.SessionID)
	}
	if binding.JTI != "session-binding-happy" {
		t.Errorf("jti = %q (claims.ID is set to sessionID)", binding.JTI)
	}
	want := sha256.Sum256([]byte(token))
	if binding.TokenSHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("tokenSha256 mismatch")
	}
	if !contains(binding.AllowedTools, "Read") {
		t.Errorf("AllowedTools missing 'Read': %v", binding.AllowedTools)
	}
	if !contains(binding.DeniedTools, "WebFetch") {
		t.Errorf("DeniedTools missing 'WebFetch': %v", binding.DeniedTools)
	}
}

// TestBuildJWTBindingForSession_NoToken — sessions without an AuthToken
// (legacy or token-issuance failed) get a nil binding, NOT a panic.
func TestBuildJWTBindingForSession_NoToken(t *testing.T) {
	h := newTestHandler(t)
	ss := seedSession(t, h, "session-no-token", &aflock.Policy{Name: "x"})
	if got := h.buildJWTBindingForSession(ss); got != nil {
		t.Errorf("expected nil binding when AuthToken is empty, got %+v", got)
	}
}

// TestBuildJWTBindingForSession_PubkeyMissing — token present but no
// jwt-pubkey.pem on disk (legacy session pre-#48). Returns nil silently
// — same graceful-fallback policy as the PreToolUse path.
func TestBuildJWTBindingForSession_PubkeyMissing(t *testing.T) {
	h := newTestHandler(t)
	ss := seedSession(t, h, "session-no-pubkey", &aflock.Policy{Name: "x"})
	ss.AuthToken = "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJ4In0.sig"
	if got := h.buildJWTBindingForSession(ss); got != nil {
		t.Errorf("expected nil binding when pubkey missing, got %+v", got)
	}
}

// TestBuildJWTBindingForSession_ForeignToken — the persisted pubkey
// belongs to a different signer than the one that issued the stored
// token. Validation must fail and the binding must be nil — preventing
// an attacker from swapping the pubkey to bind a forged token.
func TestBuildJWTBindingForSession_ForeignToken(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{Name: "binding-foreign", Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}}}
	ss := seedSession(t, h, "session-foreign", pol)

	signerA, _ := auth.NewTokenIssuer()
	signerB, _ := auth.NewTokenIssuer()

	tokenA, err := signerA.IssueToken("session-foreign", "agent-A", "hA", pol, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	pemB, err := signerB.MarshalPublicKey()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	dir := h.stateManager.SessionDir("session-foreign")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "jwt-pubkey.pem"), pemB, 0600); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}
	ss.AuthToken = tokenA

	if got := h.buildJWTBindingForSession(ss); got != nil {
		t.Errorf("expected nil binding when token doesn't match pubkey, got %+v", got)
	}
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
