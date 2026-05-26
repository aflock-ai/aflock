package mcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/aflock-ai/aflock/internal/auth"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// policyWithLimits returns a policy with all six limit categories declared
// so handleCheckLimits has something to surface for each.
func policyWithLimits() *aflock.Policy {
	return &aflock.Policy{
		Version: "1.0",
		Name:    "check-limits-fixture",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Read", "Bash"}},
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD:        &aflock.Limit{Value: 10.0, Enforcement: "fail-fast"},
			MaxTokensIn:        &aflock.Limit{Value: 500_000, Enforcement: "fail-fast"},
			MaxTokensOut:       &aflock.Limit{Value: 200_000, Enforcement: "post-hoc"},
			MaxTurns:           &aflock.Limit{Value: 50, Enforcement: "post-hoc"},
			MaxToolCalls:       &aflock.Limit{Value: 100, Enforcement: "fail-fast"},
			MaxWallTimeSeconds: &aflock.Limit{Value: 3600, Enforcement: "fail-fast"},
		},
	}
}

// TestHandleCheckLimits_SurfacesAllDeclared confirms every declared
// limit appears in the response with the {value, used, remaining,
// enforcement} shape the paper-spec consumers will rely on.
func TestHandleCheckLimits_SurfacesAllDeclared(t *testing.T) {
	s := newTestServerWithPolicy(t, policyWithLimits())

	// Seed some consumption so used/remaining aren't both zero.
	sess, err := s.stateManager.Load(s.sessionID)
	if err != nil || sess == nil {
		t.Fatalf("load session: %v", err)
	}
	sess.Metrics.CostUSD = 2.5
	sess.Metrics.TokensIn = 12_000
	sess.Metrics.TokensOut = 3_000
	sess.Metrics.Turns = 7
	sess.Metrics.ToolCalls = 9
	if err := s.stateManager.Save(sess); err != nil {
		t.Fatalf("save session: %v", err)
	}

	result, err := s.handleCheckLimits(context.Background(), newTestRequest(nil))
	if err != nil {
		t.Fatalf("handleCheckLimits: %v", err)
	}

	var parsed struct {
		Limits map[string]map[string]any `json:"limits"`
	}
	if err := json.Unmarshal([]byte(result.Content[0].(mcp.TextContent).Text), &parsed); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	for _, name := range []string{
		"maxSpendUSD", "maxTokensIn", "maxTokensOut",
		"maxTurns", "maxToolCalls", "maxWallTimeSeconds",
	} {
		entry, ok := parsed.Limits[name]
		if !ok {
			t.Errorf("missing limit %q in response", name)
			continue
		}
		for _, field := range []string{"value", "used", "remaining", "enforcement"} {
			if _, ok := entry[field]; !ok {
				t.Errorf("limit %q missing %q field", name, field)
			}
		}
	}

	// Spot-check the numbers: cost limit 10.0, used 2.5 → remaining 7.5.
	spend := parsed.Limits["maxSpendUSD"]
	if spend["used"].(float64) != 2.5 || spend["remaining"].(float64) != 7.5 {
		t.Errorf("maxSpendUSD used/remaining wrong: %v", spend)
	}
}

// TestHandleCheckLimits_NoPolicy returns empty `limits` rather than erroring,
// so callers can poll the endpoint before policy loads.
func TestHandleCheckLimits_NoPolicy(t *testing.T) {
	s := newTestServer(t)
	result, err := s.handleCheckLimits(context.Background(), newTestRequest(nil))
	if err != nil {
		t.Fatalf("handleCheckLimits: %v", err)
	}
	var parsed struct {
		Limits map[string]any `json:"limits"`
	}
	if err := json.Unmarshal([]byte(result.Content[0].(mcp.TextContent).Text), &parsed); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(parsed.Limits) != 0 {
		t.Errorf("expected empty limits with no policy, got %v", parsed.Limits)
	}
}

// policyWithSublayout returns a policy declaring one valid sublayout
// (`research-agent`) so handleDelegate has something to match.
func policyWithSublayout() *aflock.Policy {
	return &aflock.Policy{
		Version: "1.0",
		Name:    "delegate-fixture",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Read", "Bash"}},
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD: &aflock.Limit{Value: 10.0, Enforcement: "fail-fast"},
			MaxTokensIn: &aflock.Limit{Value: 500_000, Enforcement: "fail-fast"},
		},
		Sublayouts: []aflock.Sublayout{{
			Name:   "research-agent",
			Policy: "./policies/research.aflock",
			Limits: &aflock.LimitsPolicy{
				MaxSpendUSD: &aflock.Limit{Value: 2.0, Enforcement: "fail-fast"},
			},
		}},
	}
}

// authedDelegateServer wires up a server with the sublayout fixture and
// pre-issues a parent JWT. Returns the server and the token string callers
// pass back through `_token` so handleDelegate's JWT gate is satisfied.
func authedDelegateServer(t *testing.T, pol *aflock.Policy) (*Server, string) {
	t.Helper()
	s := newTestServerWithPolicy(t, pol)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s.tokenIssuer = auth.NewTokenIssuerFromSigner(key, "test-signer")
	tok, err := s.tokenIssuer.IssueToken(s.sessionID, "test-agent", "test-hash", pol, time.Hour)
	if err != nil {
		t.Fatalf("issue parent token: %v", err)
	}
	return s, tok
}

// TestHandleDelegate_RequiresJWT — handler must refuse calls without a
// JWT regardless of authActive state, since delegate mints child tokens.
func TestHandleDelegate_RequiresJWT(t *testing.T) {
	s := newTestServerWithPolicy(t, policyWithSublayout())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s.tokenIssuer = auth.NewTokenIssuerFromSigner(key, "test-signer")
	// authActive deliberately left false — graceful adoption must NOT
	// apply to aflock_delegate.

	result, err := s.handleDelegate(context.Background(),
		newTestRequest(map[string]any{"sublayout_name": "research-agent"}))
	if err != nil {
		t.Fatalf("handleDelegate: %v", err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].(mcp.TextContent).Text, "requires a valid JWT") {
		t.Errorf("expected 'requires a valid JWT' error, got: %+v", result)
	}
}

// TestHandleDelegate_MissingSublayoutName rejects empty input clearly.
func TestHandleDelegate_MissingSublayoutName(t *testing.T) {
	s, tok := authedDelegateServer(t, policyWithSublayout())
	result, err := s.handleDelegate(context.Background(),
		newTestRequest(map[string]any{"_token": tok}))
	if err != nil {
		t.Fatalf("handleDelegate: %v", err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].(mcp.TextContent).Text, "sublayout_name is required") {
		t.Errorf("expected 'sublayout_name is required' error, got: %+v", result)
	}
}

// TestHandleDelegate_UnknownSublayout refuses names not in policy.
func TestHandleDelegate_UnknownSublayout(t *testing.T) {
	s, tok := authedDelegateServer(t, policyWithSublayout())
	result, err := s.handleDelegate(context.Background(),
		newTestRequest(map[string]any{"_token": tok, "sublayout_name": "nope"}))
	if err != nil {
		t.Fatalf("handleDelegate: %v", err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].(mcp.TextContent).Text, "not declared in policy") {
		t.Errorf("expected 'not declared' error, got: %+v", result)
	}
}

// TestHandleDelegate_AttenuationViolation rejects sublayouts whose
// limits exceed the parent's.
func TestHandleDelegate_AttenuationViolation(t *testing.T) {
	pol := policyWithSublayout()
	// Bump the sublayout above the parent.
	pol.Sublayouts[0].Limits.MaxSpendUSD = &aflock.Limit{Value: 99.0, Enforcement: "fail-fast"}
	s, tok := authedDelegateServer(t, pol)

	result, err := s.handleDelegate(context.Background(),
		newTestRequest(map[string]any{"_token": tok, "sublayout_name": "research-agent"}))
	if err != nil {
		t.Fatalf("handleDelegate: %v", err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].(mcp.TextContent).Text, "attenuation") {
		t.Errorf("expected 'attenuation' error, got: %+v", result)
	}
}

// TestHandleDelegate_RejectsBadChildSessionID — caller-supplied IDs
// with disallowed characters must be rejected before any side effect.
func TestHandleDelegate_RejectsBadChildSessionID(t *testing.T) {
	s, tok := authedDelegateServer(t, policyWithSublayout())
	result, err := s.handleDelegate(context.Background(),
		newTestRequest(map[string]any{
			"_token":           tok,
			"sublayout_name":   "research-agent",
			"child_session_id": "../../etc/passwd",
		}))
	if err != nil {
		t.Fatalf("handleDelegate: %v", err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].(mcp.TextContent).Text, "child_session_id must be") {
		t.Errorf("expected child_session_id format error, got: %+v", result)
	}
}

// TestHandleDelegate_HappyPath validates the full success flow:
// returns ok=true, includes the sublayout name, mints a child JWT, and
// the JWT's claims carry the attenuated limit.
func TestHandleDelegate_HappyPath(t *testing.T) {
	s, tok := authedDelegateServer(t, policyWithSublayout())

	result, err := s.handleDelegate(context.Background(),
		newTestRequest(map[string]any{"_token": tok, "sublayout_name": "research-agent"}))
	if err != nil {
		t.Fatalf("handleDelegate: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(mcp.TextContent).Text)
	}

	var parsed struct {
		OK             bool   `json:"ok"`
		Sublayout      string `json:"sublayout"`
		ChildSessionID string `json:"child_session_id"`
		ChildJWT       string `json:"child_jwt"`
	}
	if err := json.Unmarshal([]byte(result.Content[0].(mcp.TextContent).Text), &parsed); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if !parsed.OK || parsed.Sublayout != "research-agent" {
		t.Errorf("unexpected response shape: %+v", parsed)
	}
	if parsed.ChildSessionID == "" || parsed.ChildJWT == "" {
		t.Errorf("child_session_id / child_jwt must be populated: %+v", parsed)
	}

	// Validate the minted JWT carries the sublayout's attenuated limit.
	// Pass empty currentPolicyDigest because the child JWT is bound to the
	// attenuated child policy, not the parent's digest.
	claims, err := s.tokenIssuer.ValidateTokenForSessionAndPolicy(parsed.ChildJWT, parsed.ChildSessionID, "")
	if err != nil {
		t.Fatalf("validate child JWT: %v", err)
	}
	if claims.Limits == nil || claims.Limits.MaxSpendUSD == nil || claims.Limits.MaxSpendUSD.Value != 2.0 {
		t.Errorf("child JWT must carry sublayout MaxSpendUSD=2.0, got: %+v", claims.Limits)
	}
	// And it inherits the parent's TokensIn limit unchanged.
	if claims.Limits.MaxTokensIn == nil || claims.Limits.MaxTokensIn.Value != 500_000 {
		t.Errorf("child JWT must inherit parent MaxTokensIn=500000, got: %+v", claims.Limits.MaxTokensIn)
	}
}

// TestRegisterTools_PaperNamesPresent confirms the four paper-named
// tools are registered (alongside the legacy names) so a server probe
// won't hit `tool not found` on any of them.
func TestRegisterTools_PaperNamesPresent(t *testing.T) {
	s := NewServer()
	listed := s.mcpServer.ListTools()
	for _, name := range []string{
		"aflock_authorize", "aflock_attest",
		"aflock_check_limits", "aflock_delegate",
		// legacy names retained for backward compatibility:
		"check_tool", "sign_attestation",
	} {
		if _, ok := listed[name]; !ok {
			t.Errorf("expected tool %q registered, missing", name)
		}
	}
	// Compile-time anchor — keep the import live even if the body
	// changes shape later.
	_ = time.Second
}
