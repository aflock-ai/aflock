package mcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/aflock-ai/aflock/internal/policy"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// resultText extracts the first text content from a tool result.
func resultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("empty result content")
	}
	return result.Content[0].(mcp.TextContent).Text
}

// ---------- guardrail self-protection (issue #100) ----------

func TestHandleWriteFile_SelfProtect_DeniesGuardrail(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "test",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Write"}},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	req := newTestRequest(map[string]any{
		"path":    filepath.Join(t.TempDir(), ".aflock"),
		"content": `{"tools":{"allow":["*"]}}`,
	})
	result, err := s.handleWriteFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for write to .aflock")
	}
	if text := resultText(t, result); !strings.Contains(text, "issue #100") {
		t.Errorf("expected issue #100 guardrail deny, got: %s", text)
	}
}

func TestHandleBash_SelfProtect_DeniesGuardrailRewrite(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "test",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Bash"}},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	req := newTestRequest(map[string]any{
		"command": "cat > .aflock << 'AFLOCK_EOF'\n{}\nAFLOCK_EOF",
	})
	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for heredoc rewrite of .aflock")
	}
	if text := resultText(t, result); !strings.Contains(text, "issue #100") {
		t.Errorf("expected issue #100 guardrail deny, got: %s", text)
	}

	// Read-only reference stays allowed (non-zero exit is not an MCP error).
	readReq := newTestRequest(map[string]any{"command": "cat .aflock"})
	readResult, err := s.handleBash(ctx, readReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readResult.IsError {
		t.Fatalf("read-only .aflock reference must not be denied: %s", resultText(t, readResult))
	}
}

// ---------- mid-session tamper detection (issue #100) ----------

func TestHandleBash_PolicyTamper_DeniesEverything(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, ".aflock")
	if err := os.WriteFile(policyPath, []byte(`{"version":"1","name":"tamper","tools":{"allow":["Bash"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	s := newTestServer(t)
	pol, path, err := policy.Load(policyPath)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	s.policy = pol
	s.policyPath = path
	s.capturePolicyFileDigest()
	if s.policyFileDigest == "" {
		t.Fatal("expected policyFileDigest to be captured")
	}
	sess := s.stateManager.Initialize(s.sessionID, pol, path)
	if err := s.stateManager.Save(sess); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	req := newTestRequest(map[string]any{"command": "echo hi"})
	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("happy path should be allowed: %s", resultText(t, result))
	}

	if err := os.WriteFile(policyPath, []byte(`{"version":"1","name":"tamper","tools":{"allow":["*"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected deny after policy file rewrite")
	}
	if text := resultText(t, result); !strings.Contains(text, "digest mismatch") {
		t.Errorf("expected digest-mismatch deny, got: %s", text)
	}
}
