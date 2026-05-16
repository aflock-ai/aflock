package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/aflock/internal/auth"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Issue #42 — HTTP transport has no kernel-attested peer identity, so
// handleGetToken must require a same-UID-readable bootstrap secret. The tests
// in this file pin that behavior against the three regressions that would
// reopen the bug:
//
//   - HTTP get_token without the secret silently issues a token
//   - HTTP get_token with the wrong secret silently issues a token
//   - HTTP get_token's secret is reusable (replay)
//
// stdio + unix transports are explicitly verified to NOT require the secret,
// so we don't add ceremony where the existing trust boundary already holds.

func httpServerWithBootstrap(t *testing.T) *Server {
	t.Helper()
	s := newTestServerWithPolicy(t, &aflock.Policy{
		Name:    "http-bootstrap",
		Version: "1.0",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Bash"}},
	})
	s.transportMode = "http"
	issuer, err := auth.NewTokenIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	s.tokenIssuer = issuer
	if err := s.initHTTPBootstrapSecret(); err != nil {
		t.Fatalf("initHTTPBootstrapSecret: %v", err)
	}
	return s
}

func TestHandleGetToken_HTTP_DeniesWithoutSecret(t *testing.T) {
	s := httpServerWithBootstrap(t)

	result, err := s.handleGetToken(context.Background(), callRequest(nil))
	if err != nil {
		t.Fatalf("handleGetToken returned Go error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("HTTP get_token without _bootstrap must return an error result, got: %+v", result)
	}
	if s.authActive.Load() {
		t.Error("authActive must stay false when bootstrap fails")
	}
}

func TestHandleGetToken_HTTP_DeniesWithWrongSecret(t *testing.T) {
	s := httpServerWithBootstrap(t)

	result, err := s.handleGetToken(context.Background(), callRequest(map[string]any{
		"_bootstrap": "deadbeef-not-the-real-secret",
	}))
	if err != nil {
		t.Fatalf("handleGetToken: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("HTTP get_token with wrong _bootstrap must return error, got: %+v", result)
	}
	// The real secret must still be present — a wrong attempt should not
	// burn the secret (otherwise an attacker can DoS the legitimate client
	// by spamming get_token with junk).
	s.httpBootstrapSecretMu.Lock()
	stillThere := s.httpBootstrapSecret != ""
	s.httpBootstrapSecretMu.Unlock()
	if !stillThere {
		t.Error("wrong-secret attempt must not burn the real secret")
	}
}

func TestHandleGetToken_HTTP_AcceptsCorrectSecretAndOneTime(t *testing.T) {
	s := httpServerWithBootstrap(t)

	// Read the secret off disk the way the legitimate client would.
	secretBytes, err := os.ReadFile(s.httpBootstrapSecretPath)
	if err != nil {
		t.Fatalf("read secret file: %v", err)
	}
	pathBeforeUse := s.httpBootstrapSecretPath

	result, err := s.handleGetToken(context.Background(), callRequest(map[string]any{
		"_bootstrap": string(secretBytes),
	}))
	if err != nil {
		t.Fatalf("handleGetToken: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("HTTP get_token with correct _bootstrap must succeed, got: %+v", result)
	}
	if !s.authActive.Load() {
		t.Error("authActive must flip true after successful bootstrap")
	}

	// One-time use: in-memory secret cleared.
	s.httpBootstrapSecretMu.Lock()
	memCleared := s.httpBootstrapSecret == ""
	s.httpBootstrapSecretMu.Unlock()
	if !memCleared {
		t.Error("in-memory secret must be cleared after consumption")
	}
	// And the on-disk file is gone.
	if _, statErr := os.Stat(pathBeforeUse); !os.IsNotExist(statErr) {
		t.Errorf("on-disk secret file must be removed after consumption, stat err=%v", statErr)
	}

	// Second use with the same secret must fail — replay defense.
	result2, err := s.handleGetToken(context.Background(), callRequest(map[string]any{
		"_bootstrap": string(secretBytes),
	}))
	if err != nil {
		t.Fatalf("handleGetToken (replay): %v", err)
	}
	if result2 == nil || !result2.IsError {
		t.Errorf("replayed bootstrap secret must be rejected, got: %+v", result2)
	}
}

func TestHandleGetToken_StdioAndUnix_DoNotRequireBootstrap(t *testing.T) {
	for _, mode := range []string{"stdio", "unix", ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			s := newTestServerWithPolicy(t, &aflock.Policy{
				Name:    "no-bootstrap-" + mode,
				Version: "1.0",
				Tools:   &aflock.ToolsPolicy{Allow: []string{"Bash"}},
			})
			s.transportMode = mode
			issuer, err := auth.NewTokenIssuer()
			if err != nil {
				t.Fatalf("issuer: %v", err)
			}
			s.tokenIssuer = issuer

			result, err := s.handleGetToken(context.Background(), callRequest(nil))
			if err != nil {
				t.Fatalf("handleGetToken: %v", err)
			}
			if result == nil || result.IsError {
				t.Fatalf("transport %q must not require _bootstrap, got: %+v", mode, result)
			}
		})
	}
}

func TestInitHTTPBootstrapSecret_FilePermissions(t *testing.T) {
	s := newTestServerWithPolicy(t, &aflock.Policy{Name: "perms", Version: "1.0"})
	if err := s.initHTTPBootstrapSecret(); err != nil {
		t.Fatalf("initHTTPBootstrapSecret: %v", err)
	}
	info, err := os.Stat(s.httpBootstrapSecretPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("bootstrap secret file perms = %v, want 0600", info.Mode().Perm())
	}
	if dir := filepath.Dir(s.httpBootstrapSecretPath); dir == "" {
		t.Error("secret path should live under a session dir")
	}
}
