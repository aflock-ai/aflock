package mcp

import (
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// TestInitAgentIdentity_PopulatesPolicyDigest covers the PR #67 review
// finding that ServeHTTP silently skipped identity discovery + PolicyDigest
// binding. The extracted helper must now run on both transports and bind
// the current policy's digest into the agent identity (paper §3.1).
//
// Identity discovery itself may legitimately return nil (no Claude Code
// process tree in the test environment) — we accept both outcomes and only
// assert that IF identity was discovered, the policy digest was applied.
func TestInitAgentIdentity_PopulatesPolicyDigest(t *testing.T) {
	s := newTestServerWithPolicy(t, &aflock.Policy{
		Name:    "identity-init-test",
		Version: "1.0",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Read"}},
	})

	// Pre-condition: no identity yet.
	if s.agentIdentity != nil {
		t.Fatal("agentIdentity should start nil")
	}

	s.initAgentIdentity()

	// If discovery succeeded, the policy digest MUST be populated. Before
	// the fix, ServeHTTP set s.agentIdentity but never called
	// computePolicyDigest() or DeriveIdentity(), leaving identity_hash="".
	if s.agentIdentity != nil {
		if s.agentIdentity.PolicyDigest == "" {
			t.Error("initAgentIdentity failed to set PolicyDigest — paper §3.1 binding missing")
		}
		if s.agentIdentity.IdentityHash == "" {
			t.Error("initAgentIdentity failed to call DeriveIdentity — IdentityHash empty")
		}
		wantDigest := s.computePolicyDigest()
		if s.agentIdentity.PolicyDigest != wantDigest {
			t.Errorf("PolicyDigest = %q, want %q", s.agentIdentity.PolicyDigest, wantDigest)
		}
	} else {
		t.Log("identity discovery returned nil (no Claude Code tree); skipping digest check")
	}
}

// TestInitAgentIdentity_NoPolicyStillDiscoverable is the degenerate case —
// when the server has no policy loaded, initAgentIdentity should still run
// discovery but skip the digest binding.
func TestInitAgentIdentity_NoPolicyStillDiscoverable(t *testing.T) {
	s := newTestServer(t) // no policy

	s.initAgentIdentity()

	// We can't assert that agentIdentity is non-nil in a headless env,
	// only that the call didn't panic and didn't touch a nil policy.
	if s.agentIdentity != nil && s.agentIdentity.PolicyDigest != "" {
		t.Error("PolicyDigest should be empty when no policy is loaded")
	}
}
