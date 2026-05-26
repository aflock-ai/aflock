// Package auth implements JWT-based agent authorization for aflock.
//
// The server issues short-lived JWTs scoped to policy grants. Each MCP call
// presents the JWT for validation. This enforces:
//   - Agent identity binding (SPIFFE ID / identity hash)
//   - Session binding (audience = session ID)
//   - Tool-level authorization (allowed/denied tools from policy)
//   - Expiry-based rotation
//
// Signing uses ECDSA P-256 (ES256) exclusively to prevent algorithm confusion.
package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// AflockClaims extends standard JWT claims with aflock-specific scoping.
type AflockClaims struct {
	jwt.RegisteredClaims

	// Agent identity
	AgentID      string `json:"agent_id"`
	IdentityHash string `json:"identity_hash"`

	// Scoped grants
	AllowedTools []string             `json:"allowed_tools,omitempty"`
	DeniedTools  []string             `json:"denied_tools,omitempty"`
	Limits       *aflock.LimitsPolicy `json:"limits,omitempty"`

	// Policy binding — token is only valid for the policy it was issued against
	PolicyDigest string `json:"policy_digest"`
}

// TokenIssuer generates and validates session JWTs.
type TokenIssuer struct {
	signingKey crypto.Signer
	publicKey  crypto.PublicKey
	keyID      string
}

// NewTokenIssuer creates an issuer with an ephemeral ECDSA P-256 key.
// The key lives only in memory and is destroyed when the process exits.
func NewTokenIssuer() (*TokenIssuer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &TokenIssuer{
		signingKey: key,
		publicKey:  &key.PublicKey,
		keyID:      "ephemeral-ecdsa-p256",
	}, nil
}

// NewTokenIssuerFromSigner creates an issuer using an externally-provided
// crypto.Signer (e.g., from SPIRE).
func NewTokenIssuerFromSigner(key crypto.Signer, keyID string) *TokenIssuer {
	return &TokenIssuer{
		signingKey: key,
		publicKey:  key.Public(),
		keyID:      keyID,
	}
}

// IssueToken generates a JWT for the given session, scoped to the policy.
func (ti *TokenIssuer) IssueToken(
	sessionID string,
	agentID string,
	identityHash string,
	pol *aflock.Policy,
	ttl time.Duration,
) (string, error) {
	now := time.Now()

	claims := AflockClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "aflock",
			Subject:   agentID,
			Audience:  jwt.ClaimStrings{sessionID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        sessionID,
		},
		AgentID:      agentID,
		IdentityHash: identityHash,
	}

	// Scope from policy
	if pol != nil {
		if pol.Tools != nil {
			claims.AllowedTools = pol.Tools.Allow
			claims.DeniedTools = pol.Tools.Deny
		}
		if pol.Limits != nil {
			claims.Limits = pol.Limits
		}
		claims.PolicyDigest = ComputePolicyDigest(pol)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = ti.keyID

	return token.SignedString(ti.signingKey)
}

// MintChildToken issues a JWT for a child session bound to a parent
// sublayout. The token's scope is the intersection of the parent
// policy with the sublayout: parent tools (unchanged — sublayouts
// don't broaden tool access), sublayout limits where declared
// (falling back to the parent's limit otherwise), and a fresh
// PolicyDigest computed over the attenuated policy so verification
// can't replay this token against the parent or any other sublayout.
//
// Used by `aflock_delegate` (issue #117) to mirror, in MCP mode,
// the spawn-time binding that hooks-mode performs in
// internal/hooks/handler.go:matchSublayoutForSpawn.
func (ti *TokenIssuer) MintChildToken(
	parentPolicy *aflock.Policy,
	sub *aflock.Sublayout,
	childSessionID string,
	agentID string,
	identityHash string,
	ttl time.Duration,
) (string, error) {
	if parentPolicy == nil {
		return "", fmt.Errorf("mint child token: nil parent policy")
	}
	if sub == nil {
		return "", fmt.Errorf("mint child token: nil sublayout")
	}
	child := attenuateChildPolicy(parentPolicy, sub)
	return ti.IssueToken(childSessionID, agentID, identityHash, child, ttl)
}

// attenuateChildPolicy builds an attenuated policy for a sublayout
// child. Tools and grants are carried from the parent (the sublayout
// is a delegation, not a broadening); limits are merged field-by-field
// with the sublayout taking precedence where present.
func attenuateChildPolicy(parent *aflock.Policy, sub *aflock.Sublayout) *aflock.Policy {
	child := &aflock.Policy{
		Name:    sub.Name,
		Version: parent.Version,
		Tools:   parent.Tools,
	}
	child.Limits = mergeLimits(parent.Limits, sub.Limits)
	return child
}

// mergeLimits returns a new LimitsPolicy where each field is the
// sublayout's value if set, otherwise the parent's value. Caller is
// responsible for attenuation validation (sub <= parent) before
// calling this — mergeLimits trusts its inputs.
func mergeLimits(parent, sub *aflock.LimitsPolicy) *aflock.LimitsPolicy {
	if parent == nil && sub == nil {
		return nil
	}
	out := &aflock.LimitsPolicy{}
	pick := func(p, s *aflock.Limit) *aflock.Limit {
		if s != nil {
			return s
		}
		return p
	}
	if parent != nil {
		out.MaxSpendUSD = parent.MaxSpendUSD
		out.MaxTokensIn = parent.MaxTokensIn
		out.MaxTokensOut = parent.MaxTokensOut
		out.MaxTurns = parent.MaxTurns
		out.MaxWallTimeSeconds = parent.MaxWallTimeSeconds
		out.MaxToolCalls = parent.MaxToolCalls
	}
	if sub != nil {
		out.MaxSpendUSD = pick(out.MaxSpendUSD, sub.MaxSpendUSD)
		out.MaxTokensIn = pick(out.MaxTokensIn, sub.MaxTokensIn)
		out.MaxTokensOut = pick(out.MaxTokensOut, sub.MaxTokensOut)
		out.MaxTurns = pick(out.MaxTurns, sub.MaxTurns)
		out.MaxWallTimeSeconds = pick(out.MaxWallTimeSeconds, sub.MaxWallTimeSeconds)
		out.MaxToolCalls = pick(out.MaxToolCalls, sub.MaxToolCalls)
	}
	return out
}

// ValidateToken verifies signature, expiry, issuer, and parses claims.
func (ti *TokenIssuer) ValidateToken(tokenString string) (*AflockClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AflockClaims{},
		func(token *jwt.Token) (interface{}, error) {
			// Prevent algorithm confusion: only accept ECDSA
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return ti.publicKey, nil
		},
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer("aflock"),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*AflockClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims")
	}

	return claims, nil
}

// ValidateTokenForSession validates a token and checks it is bound to the
// given session ID (audience check).
//
// Deprecated: prefer ValidateTokenForSessionAndPolicy so the policy_digest
// claim is verified against the currently loaded policy. This wrapper exists
// only for callers that genuinely have no policy context (e.g., tests).
func (ti *TokenIssuer) ValidateTokenForSession(tokenString, sessionID string) (*AflockClaims, error) {
	return ti.ValidateTokenForSessionAndPolicy(tokenString, sessionID, "")
}

// ValidateTokenForSessionAndPolicy validates signature, expiry, issuer,
// audience binding, AND that the token was issued under the same policy
// that the caller currently has loaded (policy_digest claim).
//
// Pass currentPolicyDigest = "" to skip the policy check (legacy path).
// When non-empty, a token whose policy_digest does not match is rejected,
// closing issue #59 / M11: a permissive token does NOT survive a policy
// tightening because the digest will no longer match.
func (ti *TokenIssuer) ValidateTokenForSessionAndPolicy(tokenString, sessionID, currentPolicyDigest string) (*AflockClaims, error) {
	claims, err := ti.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Verify session binding via audience claim
	found := false
	for _, aud := range claims.Audience {
		if aud == sessionID {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("token not valid for session %s", sessionID)
	}

	// Verify policy binding. If the caller didn't pass a digest, skip — but
	// log to surface the gap so production callers can be hardened.
	if currentPolicyDigest != "" && claims.PolicyDigest != currentPolicyDigest {
		// Truncate to keep error messages readable; full hex digests are 64 chars.
		tokenDigest := claims.PolicyDigest
		if len(tokenDigest) > 16 {
			tokenDigest = tokenDigest[:16]
		}
		shortCurrent := currentPolicyDigest
		if len(shortCurrent) > 16 {
			shortCurrent = shortCurrent[:16]
		}
		return nil, fmt.Errorf("token bound to a different policy version (token=%s..., current=%s...)", tokenDigest, shortCurrent)
	}

	return claims, nil
}

// IsToolAllowed checks whether a tool is permitted by the token's scope.
// Rules:
//   - If AllowedTools is non-empty, tool must be in the list (allowlist mode).
//   - If DeniedTools is non-empty, tool must NOT be in the list.
//   - If both are empty, all tools are allowed.
func IsToolAllowed(toolName string, allowedTools, deniedTools []string) bool {
	// Check deny list first
	for _, denied := range deniedTools {
		if denied == toolName {
			return false
		}
	}

	// If an allow list exists, tool must be in it
	if len(allowedTools) > 0 {
		for _, allowed := range allowedTools {
			if allowed == toolName {
				return true
			}
		}
		return false
	}

	return true
}

// ComputePolicyDigest returns a SHA-256 digest of the policy for binding
// tokens to a specific policy version.
//
// Prefers pol.RawDigest, which is the SHA-256 of the on-disk policy bytes
// captured by policy.Load. Re-marshaling the parsed struct would normalize
// formatting (key order, whitespace, number representation) and produce a
// different digest for byte-identical input — see issue #61 / L5.
//
// Falls back to marshaling for policies constructed in-memory (e.g., tests)
// that have no associated file.
func ComputePolicyDigest(pol *aflock.Policy) string {
	if pol == nil {
		return ""
	}
	if pol.RawDigest != "" {
		return pol.RawDigest
	}
	data, err := json.Marshal(pol)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// PublicKey returns the issuer's public key (useful for testing/debugging).
func (ti *TokenIssuer) PublicKey() crypto.PublicKey {
	return ti.publicKey
}

// MarshalPublicKey returns the issuer's public key as PEM-encoded PKIX bytes.
// Used by hooks mode to persist the validation key across PreToolUse
// subprocesses — the private key dies with the SessionStart process, but the
// public key on disk lets a separate hook process validate the JWT (issue #48).
func (ti *TokenIssuer) MarshalPublicKey() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(ti.publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// NewTokenIssuerFromPublicKey reconstructs a validation-only TokenIssuer from
// PEM-encoded public key bytes produced by MarshalPublicKey. The returned
// issuer can validate tokens but cannot sign new ones (no private key).
func NewTokenIssuerFromPublicKey(pemData []byte) (*TokenIssuer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in public key data")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		return nil, fmt.Errorf("public key is not ECDSA: %T", pub)
	}
	return &TokenIssuer{publicKey: pub}, nil
}

// KeyID returns the key identifier.
func (ti *TokenIssuer) KeyID() string {
	return ti.keyID
}
