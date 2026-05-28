package mcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/aflock-ai/aflock/internal/auth"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

func expiredPolicy(name string) *aflock.Policy {
	past := time.Now().Add(-time.Hour)
	return &aflock.Policy{
		Version: "1.0",
		Name:    name,
		Expires: &past,
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Bash"}},
	}
}

// TestHandleCheckTool_ExpiredPolicyDenies — without the expiry check,
// Bash would return allowed=true because it's in the allowlist. The fix
// must turn that into a hard deny.
func TestHandleCheckTool_ExpiredPolicyDenies(t *testing.T) {
	s := newTestServerWithPolicy(t, expiredPolicy("expired"))
	result, err := s.handleCheckTool(context.Background(),
		newTestRequest(map[string]any{"tool_name": "Bash"}))
	if err != nil {
		t.Fatalf("handleCheckTool: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(result.Content[0].(mcp.TextContent).Text), &parsed); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if parsed["allowed"] != false || parsed["decision"] != "deny" {
		t.Errorf("expected allowed=false decision=deny, got %v", parsed)
	}
	if reason, _ := parsed["reason"].(string); !strings.Contains(reason, "expired") {
		t.Errorf("reason should mention expiry, got: %s", reason)
	}
}

// TestHandleGetToken_ExpiredPolicyRefusesIssuance — a long-running HTTP
// server can outlive Expires. The JWT TTL alone is not enough; minting a
// new token past expiry would extend authorization indefinitely. Also
// verifies the existing authActive invariant: a refused issuance must not
// flip the auth flag (same property covered by
// TestHandleGetToken_RollbackOnIssueTokenFailure for a different cause).
func TestHandleGetToken_ExpiredPolicyRefusesIssuance(t *testing.T) {
	s := newTestServerWithPolicy(t, expiredPolicy("expired"))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s.tokenIssuer = auth.NewTokenIssuerFromSigner(key, "test-signer")

	result, err := s.handleGetToken(context.Background(), callRequest(nil))
	if err != nil {
		t.Fatalf("handleGetToken: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("must return error result on expired policy, got: %+v", result)
	}
	if !strings.Contains(result.Content[0].(mcp.TextContent).Text, "expired") {
		t.Errorf("error must mention expiry, got: %s", result.Content[0].(mcp.TextContent).Text)
	}
	if s.authActive.Load() {
		t.Error("authActive must stay false when issuance is refused")
	}
}

// TestServe_RefusesToStartWithExpiredPolicy — startup-time check, the
// other half of issue #136. Hooks mode/verify CLI already refuse expired
// policies; this test pins MCP mode to the same behavior.
func TestServe_RefusesToStartWithExpiredPolicy(t *testing.T) {
	dir := t.TempDir()
	expiredPath := filepath.Join(dir, ".aflock")
	body := `{"version":"1.0","name":"startup-expired","expires":"2020-01-01T00:00:00Z"}`
	if err := os.WriteFile(expiredPath, []byte(body), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	s := newTestServer(t)
	err := s.Serve(expiredPath)
	if err == nil {
		t.Fatal("Serve must refuse to start with an expired policy")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error must mention expiry, got: %v", err)
	}
}
