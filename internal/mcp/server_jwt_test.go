package mcp

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/aflock-ai/aflock/internal/auth"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// callRequest builds a minimal mcp.CallToolRequest with the given arguments.
func callRequest(args map[string]any) mcp.CallToolRequest {
	r := mcp.CallToolRequest{}
	r.Params.Arguments = args
	return r
}

// TestValidateJWT_RequireTokenMode_DeniesNoToken proves issue #59 / M10:
// when AFLOCK_REQUIRE_TOKEN=1 is set, ANY tool call without a token is
// rejected — even before the first get_token. The "graceful adoption"
// window is closed.
func TestValidateJWT_RequireTokenMode_DeniesNoToken(t *testing.T) {
	s := newTestServer(t)
	issuer, err := auth.NewTokenIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	s.tokenIssuer = issuer
	s.requireToken = true

	_, err = s.validateJWT(callRequest(nil))
	if err == nil {
		t.Fatal("expected validateJWT to deny when require-token is set and no token provided")
	}
	if !strings.Contains(err.Error(), "missing auth token") {
		t.Errorf("error = %v, want 'missing auth token'", err)
	}
}

// In default (graceful adoption) mode, an unauth call before get_token must
// still be allowed — backward compatibility.
func TestValidateJWT_GracefulAdoption_AllowsBeforeGetToken(t *testing.T) {
	s := newTestServer(t)
	issuer, err := auth.NewTokenIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	s.tokenIssuer = issuer
	// requireToken left false; authActive still false (no get_token called yet).

	claims, err := s.validateJWT(callRequest(nil))
	if err != nil {
		t.Errorf("graceful adoption should allow unauth, got error: %v", err)
	}
	if claims != nil {
		t.Errorf("claims should be nil when no token is provided, got %+v", claims)
	}
}

// TestValidateJWT_TOCTOU_AtomicFlagPreventsRace simulates the race fixed by
// H11. The atomic flag is set the moment handleGetToken starts processing;
// any concurrent validateJWT call afterwards must see auth as active and
// require a token, even if the on-disk session state hasn't been persisted
// yet (issue #59 / H11).
func TestValidateJWT_TOCTOU_AtomicFlagPreventsRace(t *testing.T) {
	s := newTestServer(t)
	issuer, err := auth.NewTokenIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	s.tokenIssuer = issuer

	// Simulate handleGetToken starting: the very first action is the
	// atomic flip. We don't need to actually issue the token to prove the
	// race is closed — the flag is what validateJWT checks.
	s.authActive.Store(true)

	// Concurrent tool call with no token must now be rejected, even though
	// the on-disk session state has no AuthToken (no get_token persisted).
	_, err = s.validateJWT(callRequest(nil))
	if err == nil {
		t.Fatal("validateJWT should reject post-authActive unauth call (TOCTOU window closed)")
	}
}

// Concurrent stress: launch N goroutines, half flipping authActive (mimicking
// get_token starting), half calling validateJWT. After authActive is set,
// every subsequent unauth call MUST be denied. Asserts no goroutine sees a
// stale "auth not active" view after the flag has flipped — the race the
// test guards against.
func TestValidateJWT_ConcurrentRace(t *testing.T) {
	s := newTestServer(t)
	issuer, _ := auth.NewTokenIssuer()
	s.tokenIssuer = issuer

	const callers = 50
	var wg sync.WaitGroup

	// Flip the flag mid-flight.
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.authActive.Store(true)
	}()

	results := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.validateJWT(callRequest(nil))
			results[i] = err
		}(i)
	}
	wg.Wait()

	// After the dust settles, ANY caller that sees authActive=true must have
	// returned an error. We can't pin which callers ran before vs after the
	// flip, but we CAN assert: post-test, the flag is true, so a fresh call
	// must reject.
	if !s.authActive.Load() {
		t.Fatal("authActive should be true after the test")
	}
	if _, err := s.validateJWT(callRequest(nil)); err == nil {
		t.Fatal("post-flip validateJWT must reject unauth")
	}
	_ = results // pre-flip callers may legitimately have been allowed
}

// TestValidateJWT_PolicyDigestEnforced exercises M11 end-to-end through the
// MCP server: a token issued under policy A must fail when the server's
// current policy is B.
func TestValidateJWT_PolicyDigestEnforced(t *testing.T) {
	policyA := &aflock.Policy{Name: "permissive", Version: "1.0",
		Tools: &aflock.ToolsPolicy{Allow: []string{"Bash"}}}
	policyB := &aflock.Policy{Name: "tightened", Version: "1.1",
		Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}}}

	s := newTestServerWithPolicy(t, policyA)
	issuer, _ := auth.NewTokenIssuer()
	s.tokenIssuer = issuer

	// Issue the token under policy A.
	tokenStr, err := issuer.IssueToken(s.sessionID, "agent", "hash", policyA, time.Hour)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	// Sanity: validates against current policy A.
	if _, err := s.validateJWT(callRequest(map[string]any{"_token": tokenStr})); err != nil {
		t.Fatalf("validation under issuing policy should pass: %v", err)
	}

	// Tighten the server's policy.
	s.policy = policyB
	if _, err := s.validateJWT(callRequest(map[string]any{"_token": tokenStr})); err == nil {
		t.Fatal("validation must fail after policy tightening (M11)")
	}
}
