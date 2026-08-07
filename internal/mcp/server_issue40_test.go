package mcp

import (
	"context"
	"testing"

	"github.com/aflock-ai/aflock/internal/attestation"
	"github.com/aflock-ai/aflock/internal/auth"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Issue #40 — attestation signing must require a JWT once auth is active.
// Before that ("graceful adoption" / pre-bootstrap window) nil is still
// accepted to preserve existing behavior.

func TestSignAndStoreAttestation_RefusesNilBindingWhenAuthActive(t *testing.T) {
	s := newTestServerWithPolicy(t, &aflock.Policy{
		Name: "issue-40-mcp-sign", Version: "1.0",
		Tools: &aflock.ToolsPolicy{Allow: []string{"Bash"}},
	})
	issuer, err := auth.NewTokenIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	s.tokenIssuer = issuer
	s.signingEnabled = true
	s.signer = attestation.NewSigner("")
	if err := s.signer.InitializeEphemeral("test"); err != nil {
		t.Fatalf("InitializeEphemeral: %v", err)
	}

	// Pre-authActive: nil binding accepted (graceful adoption window).
	if err := s.signAndStoreAttestation(context.Background(), aflock.ActionRecord{
		ToolName: "Bash", ToolUseID: "tu-1", Decision: "allow",
	}, nil); err != nil {
		t.Errorf("pre-authActive nil binding must be accepted, got: %v", err)
	}

	// Post-authActive: nil binding must be rejected.
	s.authActive.Store(true)
	if err := s.signAndStoreAttestation(context.Background(), aflock.ActionRecord{
		ToolName: "Bash", ToolUseID: "tu-2", Decision: "allow",
	}, nil); err == nil {
		t.Error("post-authActive nil binding must be rejected (issue #40)")
	}
}

func TestHandleSignAttestation_RefusesNoClaimsWhenAuthActive(t *testing.T) {
	s := newTestServerWithPolicy(t, &aflock.Policy{
		Name: "issue-40-handle-sign", Version: "1.0",
		Tools: &aflock.ToolsPolicy{Allow: []string{"sign_attestation"}},
	})
	issuer, err := auth.NewTokenIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	s.tokenIssuer = issuer
	s.signingEnabled = true
	s.signer = attestation.NewSigner("")
	if err := s.signer.InitializeEphemeral("test"); err != nil {
		t.Fatalf("InitializeEphemeral: %v", err)
	}
	s.authActive.Store(true)

	// No _token presented while authActive — validateJWT errors out, but
	// even if it returned nil claims silently, the explicit gate must
	// still reject. The error message must cite #40 so future maintainers
	// can trace the change.
	result, err := s.handleSignAttestation(context.Background(), callRequest(map[string]any{
		"predicate_type": "https://example.com/p/v1",
		"predicate":      map[string]any{"k": "v"},
	}))
	if err != nil {
		t.Fatalf("handleSignAttestation: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("authActive + no JWT must reject sign_attestation, got: %+v", result)
	}
}
