package mcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/aflock-ai/aflock/internal/auth"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// failingSigner is a crypto.Signer that always fails. We attach a real
// ECDSA public key so TokenIssuer construction succeeds, and fail only at
// signing time — matching the realistic failure mode IssueToken would see
// from a broken SPIRE SVID or a corrupted KMS handle.
type failingSigner struct {
	pub *ecdsa.PublicKey
}

func (f failingSigner) Public() crypto.PublicKey { return f.pub }
func (f failingSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("simulated signing failure")
}

// TestHandleGetToken_RollbackOnIssueTokenFailure exercises the PR #67 review
// finding: the previous H11 fix set authActive=true synchronously at the top
// of handleGetToken, so if IssueToken failed afterward, authActive stayed
// true and every subsequent unauth tool call hit validateJWT → required a
// token → all calls were denied (DoS lockout).
//
// The fix moves the flip to AFTER successful issuance (inside sessionMu
// along with the Save). This test injects an IssueToken failure and
// confirms authActive remains false.
func TestHandleGetToken_RollbackOnIssueTokenFailure(t *testing.T) {
	s := newTestServerWithPolicy(t, &aflock.Policy{
		Name:    "rollback-test",
		Version: "1.0",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Bash"}},
	})

	// Wire a TokenIssuer whose underlying signer always fails.
	realKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s.tokenIssuer = auth.NewTokenIssuerFromSigner(
		failingSigner{pub: &realKey.PublicKey},
		"failing-test-signer",
	)

	// Pre-condition: authActive starts false.
	if s.authActive.Load() {
		t.Fatal("authActive should start false")
	}

	// Call get_token — it must return an error result.
	result, err := s.handleGetToken(context.Background(), callRequest(nil))
	if err != nil {
		t.Fatalf("handleGetToken returned Go error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("handleGetToken should return an error result on IssueToken failure, got: %+v", result)
	}

	// Post-condition (the fix): authActive must STILL be false. If it's
	// true, the server is now locked into require-token mode even though
	// no token was ever issued.
	if s.authActive.Load() {
		t.Error("authActive flipped to true despite IssueToken failure — DoS lockout not fixed")
	}

	// And validateJWT with no token must still fall through to graceful
	// adoption (allow). If it denies, the DoS the fix was meant to prevent
	// is still happening.
	claims, err := s.validateJWT(callRequest(nil))
	if err != nil {
		t.Errorf("validateJWT denied unauth call after failed get_token; DoS still present: %v", err)
	}
	if claims != nil {
		t.Errorf("claims should be nil when no token is present, got %+v", claims)
	}
}

// TestHandleGetToken_FlipsAuthActiveOnSuccess is the counterfactual to the
// rollback test: on a successful get_token, authActive MUST flip to true so
// subsequent unauth calls get rejected. This guards against a "fix" that
// accidentally never sets the flag.
func TestHandleGetToken_FlipsAuthActiveOnSuccess(t *testing.T) {
	s := newTestServerWithPolicy(t, &aflock.Policy{
		Name:    "success-test",
		Version: "1.0",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Bash"}},
	})
	issuer, err := auth.NewTokenIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	s.tokenIssuer = issuer

	if s.authActive.Load() {
		t.Fatal("authActive should start false")
	}

	result, err := s.handleGetToken(context.Background(), callRequest(nil))
	if err != nil {
		t.Fatalf("handleGetToken: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("handleGetToken should succeed, got: %+v", result)
	}

	if !s.authActive.Load() {
		t.Error("authActive must be true after successful get_token (H11 guarantee)")
	}

	// And a subsequent unauth call must now be rejected.
	if _, err := s.validateJWT(callRequest(nil)); err == nil {
		t.Error("validateJWT should deny unauth after successful get_token")
	}
}
