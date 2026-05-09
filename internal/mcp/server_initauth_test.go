package mcp

import (
	"strings"
	"testing"

	"github.com/aflock-ai/aflock/internal/attestation"
)

// TestInitAuth_ReusesSPIRESigner exercises issue #71: when SPIRE is the
// active signing source, the JWT signer must reuse the SPIRE SVID key
// instead of generating a fresh ephemeral key. We construct a Signer via
// InitializeEphemeral (which produces a real ECDSA P-256 identity) and
// then force signingMode="spire" to drive the reuse path.
func TestInitAuth_ReusesSPIRESigner(t *testing.T) {
	s := newTestServer(t)
	s.signer = attestation.NewSigner("")
	if err := s.signer.InitializeEphemeral("test-identity-hash"); err != nil {
		t.Fatalf("init signer: %v", err)
	}
	s.signingMode = "spire"

	if err := s.initAuth(); err != nil {
		t.Fatalf("initAuth: %v", err)
	}

	id, _ := s.signer.GetSigningIdentity()
	if id == nil {
		t.Fatal("signer returned nil identity")
	}
	wantKID := id.SPIFFEID.String()
	if got := s.tokenIssuer.KeyID(); got != wantKID {
		t.Errorf("kid = %q, want SPIFFE ID %q (JWT did not adopt SPIRE key)", got, wantKID)
	}
	if s.tokenIssuer.PublicKey() == nil {
		t.Error("tokenIssuer.PublicKey() is nil")
	}
}

// TestInitAuth_EphemeralModeDoesNotReuse confirms that when attestation
// signing fell back to ephemeral, the JWT issuer also gets its own
// ephemeral key (current behavior preserved — no key sharing).
func TestInitAuth_EphemeralModeDoesNotReuse(t *testing.T) {
	s := newTestServer(t)
	s.signer = attestation.NewSigner("")
	if err := s.signer.InitializeEphemeral("test-identity-hash"); err != nil {
		t.Fatalf("init signer: %v", err)
	}
	s.signingMode = "ephemeral"

	if err := s.initAuth(); err != nil {
		t.Fatalf("initAuth: %v", err)
	}

	if got := s.tokenIssuer.KeyID(); got != "ephemeral-ecdsa-p256" {
		t.Errorf("kid = %q, want %q (ephemeral mode must use fresh JWT key)", got, "ephemeral-ecdsa-p256")
	}
}

// TestInitAuth_FulcioModeDoesNotReuse confirms Fulcio is skipped: its
// cert TTL (~10 min) is shorter than typical JWT TTLs, so the JWT keeps
// its own ephemeral key.
func TestInitAuth_FulcioModeDoesNotReuse(t *testing.T) {
	s := newTestServer(t)
	s.signer = attestation.NewSigner("")
	if err := s.signer.InitializeEphemeral("test-identity-hash"); err != nil {
		t.Fatalf("init signer: %v", err)
	}
	s.signingMode = "fulcio"

	if err := s.initAuth(); err != nil {
		t.Fatalf("initAuth: %v", err)
	}

	if got := s.tokenIssuer.KeyID(); got != "ephemeral-ecdsa-p256" {
		t.Errorf("kid = %q, want %q (fulcio mode must keep ephemeral JWT key)", got, "ephemeral-ecdsa-p256")
	}
}

// TestInitAuth_NoSignerFallsBackToEphemeral confirms the no-signer path
// (signingMode unset, signer nil) still produces a working ephemeral
// issuer — preserves backward compatibility for callers that don't run
// initSigning at all (tests, edge cases).
func TestInitAuth_NoSignerFallsBackToEphemeral(t *testing.T) {
	s := newTestServer(t)

	if err := s.initAuth(); err != nil {
		t.Fatalf("initAuth: %v", err)
	}

	if s.tokenIssuer == nil {
		t.Fatal("tokenIssuer is nil")
	}
	if got := s.tokenIssuer.KeyID(); !strings.HasPrefix(got, "ephemeral") {
		t.Errorf("kid = %q, want ephemeral-prefixed", got)
	}
}
