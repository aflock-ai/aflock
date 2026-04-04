package hooks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/aflock/internal/attestation"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

func TestPostToolUse_CreatesAttestation(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "attest-test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read"},
		},
	}
	seedSession(t, h, "session-attest-1", pol)

	input := &aflock.HookInput{
		SessionID: "session-attest-1",
		ToolName:  "Read",
		ToolUseID: "tu_test_123",
		ToolInput: json.RawMessage(`{"file_path": "src/main.go"}`),
	}

	captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	// Check attestation was created
	attestDir := h.stateManager.AttestationsDir("session-attest-1")
	entries, err := os.ReadDir(attestDir)
	if err != nil {
		t.Fatalf("read attestation dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one attestation file, got 0")
	}

	// Verify the attestation file has valid DSSE structure
	attestPath := filepath.Join(attestDir, entries[0].Name())
	data, err := os.ReadFile(attestPath)
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	var envelope attestation.Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	if envelope.PayloadType == "" || envelope.Payload == "" || len(envelope.Signatures) == 0 {
		t.Error("attestation has invalid DSSE structure")
	}
}

func TestPostToolUse_AttestationHasValidContent(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "attest-content-test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Bash"},
		},
	}
	seedSession(t, h, "session-attest-2", pol)

	input := &aflock.HookInput{
		SessionID: "session-attest-2",
		ToolName:  "Bash",
		ToolUseID: "tu_bash_456",
		ToolInput: json.RawMessage(`{"command": "go test ./..."}`),
	}

	captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	// Read the attestation file
	attestDir := h.stateManager.AttestationsDir("session-attest-2")
	entries, err := os.ReadDir(attestDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no attestation files found")
	}

	data, err := os.ReadFile(filepath.Join(attestDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}

	// Parse envelope
	var envelope attestation.Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("parse envelope: %v", err)
	}

	if envelope.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("expected payloadType 'application/vnd.in-toto+json', got %q", envelope.PayloadType)
	}
	if len(envelope.Signatures) == 0 {
		t.Error("expected at least one signature")
	}
	if envelope.Signatures[0].Sig == "" {
		t.Error("expected non-empty signature")
	}

	// Decode and verify payload is valid in-toto v1 statement
	payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var statement attestation.Statement
	if err := json.Unmarshal(payloadBytes, &statement); err != nil {
		t.Fatalf("parse statement: %v", err)
	}

	if statement.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("expected statement type v1, got %q", statement.Type)
	}
	if statement.PredicateType != "https://aflock.ai/attestations/action/v0.1" {
		t.Errorf("expected predicate type action/v0.1, got %q", statement.PredicateType)
	}
	if len(statement.Subject) == 0 {
		t.Error("expected at least one subject")
	}
	if statement.Subject[0].Name != "session:session-attest-2/action:tu_bash_456" {
		t.Errorf("unexpected subject name: %s", statement.Subject[0].Name)
	}

	// Check predicate contains the tool call info
	predBytes, err := json.Marshal(statement.Predicate)
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	var predicate attestation.ActionPredicate
	if err := json.Unmarshal(predBytes, &predicate); err != nil {
		t.Fatalf("parse predicate: %v", err)
	}
	if predicate.ToolName != "Bash" {
		t.Errorf("expected toolName 'Bash', got %q", predicate.ToolName)
	}
	if predicate.Decision != "allow" {
		t.Errorf("expected decision 'allow', got %q", predicate.Decision)
	}
	if predicate.SessionID != "session-attest-2" {
		t.Errorf("expected sessionId 'session-attest-2', got %q", predicate.SessionID)
	}
}

func TestPostToolUse_NoAttestationWithoutSession(t *testing.T) {
	h := newTestHandler(t)

	// PostToolUse without a valid session should not panic
	input := &aflock.HookInput{
		SessionID: "nonexistent-session",
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path": "test.go"}`),
	}

	captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	// Should not have created any attestation dir
	attestDir := h.stateManager.AttestationsDir("nonexistent-session")
	if _, err := os.Stat(attestDir); err == nil {
		t.Error("expected no attestation dir for nonexistent session")
	}
}

func TestPostToolUse_AttestationFileNaming(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name: "naming-test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read"},
		},
	}
	seedSession(t, h, "session-attest-3", pol)

	input := &aflock.HookInput{
		SessionID: "session-attest-3",
		ToolName:  "Read",
		ToolUseID: "tu_longid_abcdef1234567890",
		ToolInput: json.RawMessage(`{"file_path": "x.go"}`),
	}

	captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	attestDir := h.stateManager.AttestationsDir("session-attest-3")
	entries, err := os.ReadDir(attestDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no attestation files found")
	}

	name := entries[0].Name()
	// Should be <timestamp>-<first8chars>.intoto.json
	if filepath.Ext(name) != ".json" {
		t.Errorf("expected .json extension, got %q", name)
	}
	if len(name) < 20 {
		t.Errorf("filename too short: %q", name)
	}
}

func TestInitializeEphemeral(t *testing.T) {
	signer := attestation.NewSigner("")
	err := signer.InitializeEphemeral("abc123hash")
	if err != nil {
		t.Fatalf("InitializeEphemeral: %v", err)
	}

	// Should be able to sign
	stmt := attestation.Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []attestation.Subject{
			{Name: "test", Digest: map[string]string{"sha256": "abc"}},
		},
		PredicateType: "https://aflock.ai/attestations/action/v0.1",
		Predicate:     map[string]string{"test": "value"},
	}

	envelope, err := signer.Sign(context.Background(), stmt)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if envelope.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("unexpected payloadType: %s", envelope.PayloadType)
	}
	if len(envelope.Signatures) == 0 {
		t.Error("expected signatures")
	}
	if envelope.Signatures[0].Certificate == "" {
		t.Error("expected certificate in signature")
	}
}
