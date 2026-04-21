package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// TestValidateTokenForSessionAndPolicy_RejectsStaleDigest exercises the
// post-M11 contract: a token issued under policy A must NOT verify after the
// admin tightens to policy B (issue #59 / M11).
func TestValidateTokenForSessionAndPolicy_RejectsStaleDigest(t *testing.T) {
	issuer, err := NewTokenIssuer()
	require.NoError(t, err)

	policyA := &aflock.Policy{
		Name:    "permissive",
		Version: "1.0",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Bash", "Read"}},
	}
	policyB := &aflock.Policy{
		Name:    "tightened",
		Version: "1.1",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Read"}},
	}

	digestA := ComputePolicyDigest(policyA)
	digestB := ComputePolicyDigest(policyB)
	require.NotEqual(t, digestA, digestB)

	tokenA, err := issuer.IssueToken("session-1", "agent-1", "hash-1", policyA, time.Hour)
	require.NoError(t, err)

	// Verifying against the policy it was issued under: pass.
	claims, err := issuer.ValidateTokenForSessionAndPolicy(tokenA, "session-1", digestA)
	require.NoError(t, err)
	assert.Equal(t, digestA, claims.PolicyDigest)

	// Verifying against the new (tightened) policy: must fail.
	_, err = issuer.ValidateTokenForSessionAndPolicy(tokenA, "session-1", digestB)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "different policy version")
}

// Backward-compat: passing currentPolicyDigest="" must skip the policy check.
func TestValidateTokenForSessionAndPolicy_EmptyDigestSkipsCheck(t *testing.T) {
	issuer, err := NewTokenIssuer()
	require.NoError(t, err)

	pol := &aflock.Policy{Name: "p", Version: "1.0"}
	tok, err := issuer.IssueToken("session-1", "agent-1", "hash-1", pol, time.Hour)
	require.NoError(t, err)

	// "" → no policy check; only audience + signature.
	if _, err := issuer.ValidateTokenForSessionAndPolicy(tok, "session-1", ""); err != nil {
		t.Errorf("empty digest should skip policy check, got error: %v", err)
	}
}

// The deprecated wrapper must keep working: it's the "" path under the hood.
func TestValidateTokenForSession_StillWorks(t *testing.T) {
	issuer, err := NewTokenIssuer()
	require.NoError(t, err)
	tok, err := issuer.IssueToken("session-1", "agent-1", "hash-1", nil, time.Hour)
	require.NoError(t, err)
	if _, err := issuer.ValidateTokenForSession(tok, "session-1"); err != nil { //nolint:staticcheck // exercising deprecated path
		t.Errorf("deprecated wrapper should still validate: %v", err)
	}
}
