package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/aflock-ai/aflock/internal/state"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// mcpServerWithTranscript builds a Server whose projectRoot maps to a
// workspace dir, and drops a transcript at the matching
// ~/.claude/projects/<slug> path so FindTranscriptForWorkDir resolves
// it. inTok input tokens on opus-4-7 drive the cost.
func mcpServerWithTranscript(t *testing.T, inTok int, authMode string, maxSpendUSD float64) *Server {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	workDir := t.TempDir()

	slug := strings.ReplaceAll(workDir, "/", "-")
	projDir := filepath.Join(home, ".claude", "projects", slug)
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		t.Fatal(err)
	}
	line := `{"type":"assistant","sessionId":"c1","requestId":"r1","message":{"id":"m1","model":"claude-opus-4-7","usage":{"input_tokens":` +
		itoa(inTok) + `,"output_tokens":100}}}` + "\n"
	if err := os.WriteFile(filepath.Join(projDir, "sess.jsonl"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	pol := &aflock.Policy{
		Name: "mcp-cost", Version: "1.0",
		Limits: &aflock.LimitsPolicy{MaxSpendUSD: &aflock.Limit{Value: maxSpendUSD, Enforcement: "fail-fast"}},
	}
	s := &Server{
		stateManager: state.NewManager(filepath.Join(home, "sessions")),
		sessionID:    "mcp-test",
		policy:       pol,
		policyPath:   filepath.Join(workDir, ".aflock"),
	}
	ss := s.stateManager.Initialize(s.sessionID, pol, s.policyPath)
	ss.AuthMode = authMode
	if err := s.stateManager.Save(ss); err != nil {
		t.Fatal(err)
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestMCP_CostEnforcedUnderAPIKey is the #72 fix: in MCP mode aflock now
// scans the transcript and fires maxSpendUSD. 10k opus-4-7 input tokens
// ≈ $0.15, over the $0.10 cap → deny.
func TestMCP_CostEnforcedUnderAPIKey(t *testing.T) {
	s := mcpServerWithTranscript(t, 10000, "api_key", 0.10)
	denied := s.refreshAndEnforceLimits()
	if denied == nil || !denied.IsError {
		t.Fatal("expected maxSpendUSD deny in MCP api_key mode, got nil/non-error")
	}
	if !strings.Contains(denied.Content[0].(mcp.TextContent).Text, "maxSpendUSD") {
		t.Errorf("deny must name maxSpendUSD, got: %+v", denied)
	}
}

// TestMCP_CostAdvisoryUnderSubscription — same spend, subscription auth:
// cost is advisory, so no deny (this is the gap #72 must NOT over-correct).
func TestMCP_CostAdvisoryUnderSubscription(t *testing.T) {
	s := mcpServerWithTranscript(t, 10000, "subscription", 0.10)
	if denied := s.refreshAndEnforceLimits(); denied != nil {
		t.Errorf("subscription cost must be advisory (no deny), got: %+v", denied)
	}
}

// TestMCP_UnderBudgetPasses — spend below the cap must not deny.
func TestMCP_UnderBudgetPasses(t *testing.T) {
	s := mcpServerWithTranscript(t, 1000, "api_key", 0.10) // ~$0.015 < $0.10
	if denied := s.refreshAndEnforceLimits(); denied != nil {
		t.Errorf("under-budget session must pass, got: %+v", denied)
	}
}
