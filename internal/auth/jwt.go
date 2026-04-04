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
	"encoding/hex"
	"encoding/json"
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
func (ti *TokenIssuer) ValidateTokenForSession(tokenString, sessionID string) (*AflockClaims, error) {
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

// ComputePolicyDigest computes a SHA-256 digest of a policy for binding tokens
// to a specific policy version.
func ComputePolicyDigest(pol *aflock.Policy) string {
	if pol == nil {
		return ""
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

// KeyID returns the key identifier.
func (ti *TokenIssuer) KeyID() string {
	return ti.keyID
}
