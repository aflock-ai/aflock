package mcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

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

// httpBootstrapFailingSigner is a crypto.Signer that always fails at signing
// time. Used to exercise the "bootstrap secret survives a transient
// IssueToken failure" path (Copilot review on PR #109).
type httpBootstrapFailingSigner struct {
	pub *ecdsa.PublicKey
}

func (f httpBootstrapFailingSigner) Public() crypto.PublicKey { return f.pub }
func (f httpBootstrapFailingSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("simulated signing failure")
}

// TestHandleGetToken_HTTP_BootstrapSurvivesIssueTokenFailure pins the fix for
// the Copilot finding: if IssueToken fails AFTER the bootstrap secret was
// verified, the secret must NOT be burned — otherwise a transient signer
// fault permanently locks out the legitimate client.
func TestHandleGetToken_HTTP_BootstrapSurvivesIssueTokenFailure(t *testing.T) {
	s := newTestServerWithPolicy(t, &aflock.Policy{
		Name: "bootstrap-rollback", Version: "1.0",
		Tools: &aflock.ToolsPolicy{Allow: []string{"Bash"}},
	})
	s.transportMode = "http"
	if err := s.initHTTPBootstrapSecret(); err != nil {
		t.Fatalf("initHTTPBootstrapSecret: %v", err)
	}
	pathBefore := s.httpBootstrapSecretPath
	secretBytes, err := os.ReadFile(pathBefore)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}

	// Wire a TokenIssuer whose signer fails at Sign time — exercises the
	// realistic SPIRE-SVID-broken / KMS-handle-broken failure mode.
	realKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s.tokenIssuer = auth.NewTokenIssuerFromSigner(
		httpBootstrapFailingSigner{pub: &realKey.PublicKey},
		"failing-signer",
	)

	result, err := s.handleGetToken(context.Background(), callRequest(map[string]any{
		"_bootstrap": string(secretBytes),
	}))
	if err != nil {
		t.Fatalf("handleGetToken: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("expected error result on IssueToken failure, got: %+v", result)
	}

	// The secret must still be present in memory and on disk.
	s.httpBootstrapSecretMu.Lock()
	memKept := s.httpBootstrapSecret != ""
	pathKept := s.httpBootstrapSecretPath
	s.httpBootstrapSecretMu.Unlock()
	if !memKept {
		t.Error("in-memory secret was burned despite IssueToken failure — DoS not fixed")
	}
	if pathKept != pathBefore {
		t.Errorf("on-disk secret path changed: was %q, now %q", pathBefore, pathKept)
	}
	if _, statErr := os.Stat(pathBefore); statErr != nil {
		t.Errorf("on-disk secret file removed despite IssueToken failure: %v", statErr)
	}
	if s.authActive.Load() {
		t.Error("authActive flipped to true despite IssueToken failure")
	}
}

// TestHandleGetToken_HTTP_RefreshWithValidToken pins the fix for the second
// Copilot finding: after a successful bootstrap, the client must be able to
// refresh its JWT by presenting _token (not _bootstrap, which is consumed).
// Otherwise HTTP sessions become unusable after the JWT expires.
func TestHandleGetToken_HTTP_RefreshWithValidToken(t *testing.T) {
	s := newTestServerWithPolicy(t, &aflock.Policy{
		Name: "bootstrap-refresh", Version: "1.0",
		Tools: &aflock.ToolsPolicy{Allow: []string{"Bash"}},
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
	secretBytes, err := os.ReadFile(s.httpBootstrapSecretPath)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}

	// First call: bootstrap path issues an initial token.
	first, err := s.handleGetToken(context.Background(), callRequest(map[string]any{
		"_bootstrap": string(secretBytes),
	}))
	if err != nil {
		t.Fatalf("bootstrap call: %v", err)
	}
	if first == nil || first.IsError {
		t.Fatalf("bootstrap call must succeed, got: %+v", first)
	}
	firstToken := tokenFromResult(t, first)

	// Second call: the bootstrap secret is gone, but presenting the existing
	// JWT must still let the client refresh.
	second, err := s.handleGetToken(context.Background(), callRequest(map[string]any{
		"_token": firstToken,
	}))
	if err != nil {
		t.Fatalf("refresh call: %v", err)
	}
	if second == nil || second.IsError {
		t.Fatalf("refresh with valid _token must succeed after bootstrap consumed, got: %+v", second)
	}
	if tokenFromResult(t, second) == "" {
		t.Error("refresh must return a fresh token")
	}

	// Third call: no _token, no _bootstrap (already consumed) → must fail.
	bare, err := s.handleGetToken(context.Background(), callRequest(nil))
	if err != nil {
		t.Fatalf("bare call: %v", err)
	}
	if bare == nil || !bare.IsError {
		t.Errorf("call without _token or _bootstrap must fail after secret consumed, got: %+v", bare)
	}
}

// tokenFromResult pulls the "token" field out of handleGetToken's
// MarshalIndent'd result payload so tests can pass it back as _token on a
// refresh call.
func tokenFromResult(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if result == nil || len(result.Content) == 0 {
		t.Fatalf("result missing text content")
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("result content is not TextContent: %T", result.Content[0])
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(text.Text), &payload); err != nil {
		t.Fatalf("parse result JSON: %v (raw: %s)", err, text.Text)
	}
	return payload.Token
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
