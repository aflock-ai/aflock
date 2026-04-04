package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

func testPolicy() *aflock.Policy {
	return &aflock.Policy{
		Version: "1.0",
		Name:    "test-policy",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Bash"},
			Deny:  []string{"Write"},
		},
		Limits: &aflock.LimitsPolicy{
			MaxTurns: &aflock.Limit{Value: 10, Enforcement: "fail-fast"},
		},
	}
}

func TestNewTokenIssuer(t *testing.T) {
	issuer, err := NewTokenIssuer()
	require.NoError(t, err)
	assert.NotNil(t, issuer)
	assert.Equal(t, "ephemeral-ecdsa-p256", issuer.KeyID())
	assert.NotNil(t, issuer.PublicKey())
}

func TestIssueAndValidateToken(t *testing.T) {
	issuer, err := NewTokenIssuer()
	require.NoError(t, err)

	pol := testPolicy()
	tokenStr, err := issuer.IssueToken(
		"session-123",
		"spiffe://aflock.ai/agent/claude-opus/4.5/abc123",
		"sha256:abc123",
		pol,
		1*time.Hour,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenStr)

	// Validate the token
	claims, err := issuer.ValidateToken(tokenStr)
	require.NoError(t, err)

	assert.Equal(t, "aflock", claims.Issuer)
	assert.Equal(t, "spiffe://aflock.ai/agent/claude-opus/4.5/abc123", claims.Subject)
	assert.Equal(t, jwt.ClaimStrings{"session-123"}, claims.Audience)
	assert.Equal(t, "session-123", claims.ID)

	assert.Equal(t, "spiffe://aflock.ai/agent/claude-opus/4.5/abc123", claims.AgentID)
	assert.Equal(t, "sha256:abc123", claims.IdentityHash)

	assert.Equal(t, []string{"Read", "Bash"}, claims.AllowedTools)
	assert.Equal(t, []string{"Write"}, claims.DeniedTools)
	assert.NotNil(t, claims.Limits)
	assert.NotEmpty(t, claims.PolicyDigest)

	// Expiry should be ~1 hour from now
	assert.True(t, claims.ExpiresAt.After(time.Now().Add(59*time.Minute)))
}

func TestValidateTokenForSession(t *testing.T) {
	issuer, err := NewTokenIssuer()
	require.NoError(t, err)

	tokenStr, err := issuer.IssueToken("session-A", "agent-1", "hash-1", nil, time.Hour)
	require.NoError(t, err)

	// Valid session
	claims, err := issuer.ValidateTokenForSession(tokenStr, "session-A")
	require.NoError(t, err)
	assert.Equal(t, "agent-1", claims.AgentID)

	// Wrong session — should fail
	_, err = issuer.ValidateTokenForSession(tokenStr, "session-B")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not valid for session")
}

func TestExpiredToken(t *testing.T) {
	issuer, err := NewTokenIssuer()
	require.NoError(t, err)

	// Issue token that's already expired
	tokenStr, err := issuer.IssueToken("session-1", "agent-1", "hash-1", nil, -1*time.Second)
	require.NoError(t, err)

	// Validation should fail
	_, err = issuer.ValidateToken(tokenStr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired")
}

func TestWrongSigningKey(t *testing.T) {
	issuer1, err := NewTokenIssuer()
	require.NoError(t, err)

	issuer2, err := NewTokenIssuer()
	require.NoError(t, err)

	// Issue with issuer1, validate with issuer2
	tokenStr, err := issuer1.IssueToken("session-1", "agent-1", "hash-1", nil, time.Hour)
	require.NoError(t, err)

	_, err = issuer2.ValidateToken(tokenStr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}

func TestAlgorithmConfusion(t *testing.T) {
	issuer, err := NewTokenIssuer()
	require.NoError(t, err)

	// Create a token using HMAC (not ECDSA) — this should be rejected
	hmacToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &AflockClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "aflock",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	// Sign with the public key bytes as HMAC secret (classic algorithm confusion attack)
	ecdsaPub, ok := issuer.PublicKey().(*ecdsa.PublicKey)
	require.True(t, ok)
	ecdhPub, _ := ecdsaPub.ECDH()
	pubBytes := ecdhPub.Bytes()
	tokenStr, err := hmacToken.SignedString(pubBytes)
	require.NoError(t, err)

	// Validation must reject non-ECDSA method
	_, err = issuer.ValidateToken(tokenStr)
	assert.Error(t, err)
}

func TestWrongIssuer(t *testing.T) {
	// Create a token with wrong issuer using a valid ECDSA key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer := NewTokenIssuerFromSigner(key, "test-key")

	wrongIssuerToken := jwt.NewWithClaims(jwt.SigningMethodES256, &AflockClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "not-aflock",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	tokenStr, err := wrongIssuerToken.SignedString(key)
	require.NoError(t, err)

	_, err = issuer.ValidateToken(tokenStr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}

func TestToolScopeEnforcement(t *testing.T) {
	tests := []struct {
		name     string
		tool     string
		allowed  []string
		denied   []string
		expected bool
	}{
		{
			name:     "allowed tool in allowlist",
			tool:     "Read",
			allowed:  []string{"Read", "Bash"},
			expected: true,
		},
		{
			name:     "disallowed tool not in allowlist",
			tool:     "Write",
			allowed:  []string{"Read", "Bash"},
			expected: false,
		},
		{
			name:     "tool in denylist",
			tool:     "Write",
			denied:   []string{"Write"},
			expected: false,
		},
		{
			name:     "tool not in denylist",
			tool:     "Read",
			denied:   []string{"Write"},
			expected: true,
		},
		{
			name:     "deny takes precedence over allow",
			tool:     "Bash",
			allowed:  []string{"Read", "Bash"},
			denied:   []string{"Bash"},
			expected: false,
		},
		{
			name:     "empty lists allow everything",
			tool:     "Bash",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsToolAllowed(tt.tool, tt.allowed, tt.denied)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPolicyDigestBinding(t *testing.T) {
	issuer, err := NewTokenIssuer()
	require.NoError(t, err)

	pol1 := &aflock.Policy{Name: "policy-1", Version: "1.0"}
	pol2 := &aflock.Policy{Name: "policy-2", Version: "1.0"}

	token1, err := issuer.IssueToken("s1", "a1", "h1", pol1, time.Hour)
	require.NoError(t, err)

	token2, err := issuer.IssueToken("s2", "a2", "h2", pol2, time.Hour)
	require.NoError(t, err)

	claims1, err := issuer.ValidateToken(token1)
	require.NoError(t, err)

	claims2, err := issuer.ValidateToken(token2)
	require.NoError(t, err)

	// Different policies should produce different digests
	assert.NotEqual(t, claims1.PolicyDigest, claims2.PolicyDigest)
	assert.NotEmpty(t, claims1.PolicyDigest)
	assert.NotEmpty(t, claims2.PolicyDigest)
}

func TestNilPolicy(t *testing.T) {
	issuer, err := NewTokenIssuer()
	require.NoError(t, err)

	tokenStr, err := issuer.IssueToken("session-1", "agent-1", "hash-1", nil, time.Hour)
	require.NoError(t, err)

	claims, err := issuer.ValidateToken(tokenStr)
	require.NoError(t, err)

	assert.Empty(t, claims.AllowedTools)
	assert.Empty(t, claims.DeniedTools)
	assert.Nil(t, claims.Limits)
	assert.Empty(t, claims.PolicyDigest)
}

func TestComputePolicyDigest(t *testing.T) {
	// Nil policy
	assert.Empty(t, ComputePolicyDigest(nil))

	// Same policy produces same digest
	pol := testPolicy()
	d1 := ComputePolicyDigest(pol)
	d2 := ComputePolicyDigest(pol)
	assert.Equal(t, d1, d2)
	assert.Len(t, d1, 64) // SHA-256 hex = 64 chars
}

func TestNewTokenIssuerFromSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer := NewTokenIssuerFromSigner(key, "spire-key-1")
	assert.Equal(t, "spire-key-1", issuer.KeyID())

	// Issue and validate roundtrip
	tokenStr, err := issuer.IssueToken("s1", "a1", "h1", nil, time.Hour)
	require.NoError(t, err)

	claims, err := issuer.ValidateToken(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "a1", claims.AgentID)
}
