package verify

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	aflockMerkle "github.com/aflock-ai/aflock/internal/merkle"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// ---- Unit tests for verifyIdentityConstraints ----

func TestVerifyIdentityConstraints_NilPolicy(t *testing.T) {
	id := IdentityFields{Model: "claude-opus-4-5-20251101", Environment: "local"}
	errors := verifyIdentityConstraints(id, nil)
	if len(errors) != 0 {
		t.Errorf("Expected no errors for nil policy, got %v", errors)
	}
}

func TestVerifyIdentityConstraints_EmptyPolicy(t *testing.T) {
	id := IdentityFields{Model: "claude-opus-4-5-20251101", Environment: "local"}
	errors := verifyIdentityConstraints(id, &aflock.IdentityPolicy{})
	if len(errors) != 0 {
		t.Errorf("Expected no errors for empty policy, got %v", errors)
	}
}

func TestVerifyIdentityConstraints_ModelMatch(t *testing.T) {
	tests := []struct {
		name          string
		model         string
		allowedModels []string
		wantPass      bool
	}{
		{
			name:          "exact match",
			model:         "claude-opus-4-5-20251101",
			allowedModels: []string{"claude-opus-4-5-20251101"},
			wantPass:      true,
		},
		{
			name:          "glob match with trailing wildcard",
			model:         "claude-opus-4-5-20251101",
			allowedModels: []string{"claude-opus-4-5-*"},
			wantPass:      true,
		},
		{
			name:          "glob match broader wildcard",
			model:         "claude-sonnet-4-5-20251101",
			allowedModels: []string{"claude-sonnet-*"},
			wantPass:      true,
		},
		{
			name:          "wildcard matches all",
			model:         "anything",
			allowedModels: []string{"*"},
			wantPass:      true,
		},
		{
			name:          "multiple patterns one matches",
			model:         "claude-sonnet-4-5-20251101",
			allowedModels: []string{"claude-opus-*", "claude-sonnet-*"},
			wantPass:      true,
		},
		{
			name:          "no match",
			model:         "claude-haiku-4-5-20251001",
			allowedModels: []string{"claude-opus-*", "claude-sonnet-*"},
			wantPass:      false,
		},
		{
			name:          "partial prefix no match",
			model:         "claude-opus-4-5-20251101",
			allowedModels: []string{"claude-sonnet-4-5-*"},
			wantPass:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := IdentityFields{Model: tt.model}
			pol := &aflock.IdentityPolicy{AllowedModels: tt.allowedModels}
			errors := verifyIdentityConstraints(id, pol)
			if tt.wantPass && len(errors) != 0 {
				t.Errorf("Expected pass, got errors: %v", errors)
			}
			if !tt.wantPass && len(errors) == 0 {
				t.Error("Expected failure, got pass")
			}
		})
	}
}

func TestVerifyIdentityConstraints_EnvironmentMatch(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		allowed     []string
		wantPass    bool
	}{
		{
			name:        "exact match",
			environment: "local",
			allowed:     []string{"local"},
			wantPass:    true,
		},
		{
			name:        "container glob",
			environment: "container:ghcr.io/org/deploy-v2",
			allowed:     []string{"container:ghcr.io/org/*"},
			wantPass:    true,
		},
		{
			name:        "user prefix glob",
			environment: "user:deploy-prod",
			allowed:     []string{"user:deploy-*"},
			wantPass:    true,
		},
		{
			name:        "no match",
			environment: "container:docker.io/evil/image",
			allowed:     []string{"container:ghcr.io/org/*"},
			wantPass:    false,
		},
		{
			name:        "wildcard matches all",
			environment: "anything",
			allowed:     []string{"*"},
			wantPass:    true,
		},
		{
			name:        "multiple patterns",
			environment: "local",
			allowed:     []string{"container:*", "local"},
			wantPass:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := IdentityFields{Environment: tt.environment}
			pol := &aflock.IdentityPolicy{AllowedEnvironments: tt.allowed}
			errors := verifyIdentityConstraints(id, pol)
			if tt.wantPass && len(errors) != 0 {
				t.Errorf("Expected pass, got errors: %v", errors)
			}
			if !tt.wantPass && len(errors) == 0 {
				t.Error("Expected failure, got pass")
			}
		})
	}
}

func TestVerifyIdentityConstraints_RequiredTools(t *testing.T) {
	tests := []struct {
		name          string
		tools         []string
		requiredTools []string
		wantPass      bool
		wantErrCount  int
	}{
		{
			name:          "all required present",
			tools:         []string{"Read", "Edit", "Bash", "Glob"},
			requiredTools: []string{"Read", "Edit"},
			wantPass:      true,
		},
		{
			name:          "exact set",
			tools:         []string{"Read", "Edit"},
			requiredTools: []string{"Read", "Edit"},
			wantPass:      true,
		},
		{
			name:          "missing one tool",
			tools:         []string{"Read", "Bash"},
			requiredTools: []string{"Read", "Edit"},
			wantPass:      false,
			wantErrCount:  1,
		},
		{
			name:          "missing multiple tools",
			tools:         []string{"Bash"},
			requiredTools: []string{"Read", "Edit", "Glob"},
			wantPass:      false,
			wantErrCount:  3,
		},
		{
			name:          "empty tools list",
			tools:         []string{},
			requiredTools: []string{"Read"},
			wantPass:      false,
			wantErrCount:  1,
		},
		{
			name:          "nil tools skips check",
			tools:         nil,
			requiredTools: []string{"Read", "Edit"},
			wantPass:      true, // nil tools = unknown, skip check
		},
		{
			name:          "no required tools",
			tools:         []string{"Read"},
			requiredTools: nil,
			wantPass:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := IdentityFields{Tools: tt.tools}
			pol := &aflock.IdentityPolicy{RequiredTools: tt.requiredTools}
			errors := verifyIdentityConstraints(id, pol)
			if tt.wantPass && len(errors) != 0 {
				t.Errorf("Expected pass, got errors: %v", errors)
			}
			if !tt.wantPass {
				if len(errors) == 0 {
					t.Error("Expected failure, got pass")
				}
				if tt.wantErrCount > 0 && len(errors) != tt.wantErrCount {
					t.Errorf("Expected %d errors, got %d: %v", tt.wantErrCount, len(errors), errors)
				}
			}
		})
	}
}

func TestVerifyIdentityConstraints_MultipleConstraints(t *testing.T) {
	t.Run("all constraints pass", func(t *testing.T) {
		id := IdentityFields{
			Model:       "claude-opus-4-5-20251101",
			Environment: "container:ghcr.io/org/deploy-v2",
			Tools:       []string{"Read", "Edit", "Bash"},
		}
		pol := &aflock.IdentityPolicy{
			AllowedModels:       []string{"claude-opus-*"},
			AllowedEnvironments: []string{"container:ghcr.io/org/*"},
			RequiredTools:       []string{"Read", "Edit"},
		}
		errors := verifyIdentityConstraints(id, pol)
		if len(errors) != 0 {
			t.Errorf("Expected pass, got errors: %v", errors)
		}
	})

	t.Run("model fails environment passes", func(t *testing.T) {
		id := IdentityFields{
			Model:       "claude-haiku-4-5-20251001",
			Environment: "local",
		}
		pol := &aflock.IdentityPolicy{
			AllowedModels:       []string{"claude-opus-*"},
			AllowedEnvironments: []string{"local"},
		}
		errors := verifyIdentityConstraints(id, pol)
		if len(errors) != 1 {
			t.Errorf("Expected 1 error (model mismatch), got %d: %v", len(errors), errors)
		}
	})

	t.Run("all constraints fail", func(t *testing.T) {
		id := IdentityFields{
			Model:       "claude-haiku-4-5-20251001",
			Environment: "container:docker.io/evil/image",
			Tools:       []string{"Bash"},
		}
		pol := &aflock.IdentityPolicy{
			AllowedModels:       []string{"claude-opus-*"},
			AllowedEnvironments: []string{"container:ghcr.io/org/*"},
			RequiredTools:       []string{"Read", "Edit"},
		}
		errors := verifyIdentityConstraints(id, pol)
		// Should have: model mismatch + env mismatch + 2 missing tools = 4 errors
		if len(errors) != 4 {
			t.Errorf("Expected 4 errors, got %d: %v", len(errors), errors)
		}
	})
}

func TestVerifyIdentityConstraints_EmptyModel(t *testing.T) {
	// Empty model with allowedModels should not error (graceful for missing data)
	id := IdentityFields{Model: ""}
	pol := &aflock.IdentityPolicy{AllowedModels: []string{"claude-opus-*"}}
	errors := verifyIdentityConstraints(id, pol)
	if len(errors) != 0 {
		t.Errorf("Expected no errors for empty model, got %v", errors)
	}
}

// ---- Unit tests for matchIdentityGlob ----

func TestMatchIdentityGlob(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*", "anything", true},
		{"claude-opus-*", "claude-opus-4-5-20251101", true},
		{"claude-opus-*", "claude-sonnet-4-5-20251101", false},
		{"exact-match", "exact-match", true},
		{"exact-match", "not-exact", false},
		{"container:ghcr.io/org/*", "container:ghcr.io/org/deploy-v2", true},
		{"container:ghcr.io/org/*", "container:docker.io/other/image", false},
		{"local", "local", true},
		{"local", "container", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			got := matchIdentityGlob(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("matchIdentityGlob(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// ---- Integration: VerifySession with identity constraints ----

func TestVerifySession_IdentityPass(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-id-001",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "test-policy",
			Version: "1.0",
			Identity: &aflock.IdentityPolicy{
				AllowedModels:       []string{"claude-opus-*"},
				AllowedEnvironments: []string{"local"},
				RequiredTools:       []string{"Read"},
			},
		},
		AgentIdentityMeta: &aflock.AgentIdentityMeta{
			Model:       "claude-opus-4-5-20251101",
			Environment: "local",
		},
		Metrics: &aflock.SessionMetrics{
			Tools: map[string]int{"Read": 3, "Edit": 2, "Bash": 1},
		},
	}
	writeSessionState(t, tmpDir, "sess-id-001", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-id-001")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success, got errors: %v", result.Errors)
	}
	// Check that identity check is in the results
	found := false
	for _, c := range result.Checks {
		if c.Name == "identity" && c.Passed {
			found = true
		}
	}
	if !found {
		t.Error("Expected passing identity check in results")
	}
}

func TestVerifySession_IdentityModelMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-id-002",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "test-policy",
			Version: "1.0",
			Identity: &aflock.IdentityPolicy{
				AllowedModels: []string{"claude-opus-*"},
			},
		},
		AgentIdentityMeta: &aflock.AgentIdentityMeta{
			Model: "claude-haiku-4-5-20251001",
		},
		Metrics: &aflock.SessionMetrics{},
	}
	writeSessionState(t, tmpDir, "sess-id-002", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-id-002")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for model mismatch")
	}
	if len(result.Errors) == 0 {
		t.Error("Expected at least one error")
	}
}

func TestVerifySession_IdentityMissingRequiredTool(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-id-003",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "test-policy",
			Version: "1.0",
			Identity: &aflock.IdentityPolicy{
				RequiredTools: []string{"Read", "Edit", "Glob"},
			},
		},
		AgentIdentityMeta: &aflock.AgentIdentityMeta{
			Model: "claude-opus-4-5-20251101",
		},
		Metrics: &aflock.SessionMetrics{
			Tools: map[string]int{"Read": 3, "Bash": 1},
		},
	}
	writeSessionState(t, tmpDir, "sess-id-003", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-id-003")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for missing required tools")
	}
	// Should have 2 errors: Edit and Glob missing
	identityErrors := 0
	for _, c := range result.Checks {
		if c.Name == "identity" && !c.Passed {
			identityErrors++
		}
	}
	if identityErrors != 2 {
		t.Errorf("Expected 2 identity check failures, got %d", identityErrors)
	}
}

func TestVerifySession_NoIdentityPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-id-004",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "test-policy",
			Version: "1.0",
			// No Identity policy — should pass
		},
		Metrics: &aflock.SessionMetrics{},
	}
	writeSessionState(t, tmpDir, "sess-id-004", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-id-004")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success with no identity policy, got errors: %v", result.Errors)
	}
	// Should not have any identity checks
	for _, c := range result.Checks {
		if c.Name == "identity" {
			t.Error("Should not have identity check when no identity policy defined")
		}
	}
}

// ---- Integration: extractIdentityFromAttestation ----

// makeIdentityPayload builds an in-toto Statement with an action attestation containing agent identity.
func makeIdentityPayload(t *testing.T, stepName, model, environment string) []byte {
	t.Helper()

	action := map[string]any{
		"action":    "tool_call",
		"sessionId": "test-session",
		"toolName":  "Read",
		"decision":  "allow",
		"agentIdentity": map[string]any{
			"model":        model,
			"modelVersion": "4.5.20251101",
			"environment":  environment,
			"identityHash": "abc123def456",
		},
	}

	attestations := []map[string]any{
		{
			"type":        "https://aflock.ai/attestations/action/v0.1",
			"attestation": action,
		},
		{
			"type":        "https://aflock.ai/attestations/material/v0.1",
			"attestation": map[string]any{},
		},
	}

	predicate := map[string]any{
		"name":         stepName,
		"attestations": attestations,
	}
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://aflock.ai/attestations/collection/v0.1",
		"predicate":     predicate,
		"subject":       []map[string]any{},
	}

	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal identity payload: %v", err)
	}
	return data
}

func TestExtractIdentityFromAttestation(t *testing.T) {
	tmpDir := t.TempDir()

	payload := makeIdentityPayload(t, "build", "claude-opus-4-5-20251101", "local")
	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	envelope := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     payloadB64,
		"signatures":  []map[string]string{},
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	attestPath := filepath.Join(tmpDir, "test.intoto.json")
	if err := os.WriteFile(attestPath, data, 0644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}

	id, err := extractIdentityFromAttestation(attestPath)
	if err != nil {
		t.Fatalf("extractIdentityFromAttestation: %v", err)
	}
	if id == nil {
		t.Fatal("Expected identity, got nil")
	}
	if id.Model != "claude-opus-4-5-20251101" {
		t.Errorf("Model = %q, want %q", id.Model, "claude-opus-4-5-20251101")
	}
	if id.Environment != "local" {
		t.Errorf("Environment = %q, want %q", id.Environment, "local")
	}
}

func TestExtractIdentityFromAttestation_NoActionAttestation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an attestation with only material/product attestors (no action)
	payload := makeCollectionPayload(t, "build", []string{
		"https://aflock.ai/attestations/material/v0.1",
		"https://aflock.ai/attestations/product/v0.1",
	})
	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	envelope := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     payloadB64,
		"signatures":  []map[string]string{},
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	attestPath := filepath.Join(tmpDir, "test.intoto.json")
	if err := os.WriteFile(attestPath, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	id, err := extractIdentityFromAttestation(attestPath)
	if err != nil {
		t.Fatalf("extractIdentityFromAttestation: %v", err)
	}
	if id != nil {
		t.Errorf("Expected nil identity for attestation without action type, got %+v", id)
	}
}

// ---- Phase 4: Constraint Evaluation (Rego) ----

func TestVerifySession_RegoPass(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-rego-pass",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "rego-test",
			Version: "1.0",
			Evaluators: &aflock.EvaluatorsPolicy{
				Rego: []aflock.RegoEvaluator{
					{
						Name:   "spend-check",
						Policy: "package aflock\ndeny = []",
					},
				},
			},
		},
		Actions: []aflock.ActionRecord{
			{Timestamp: time.Now(), ToolName: "Read", ToolUseID: "tu_1", Decision: "allow"},
		},
		Metrics: &aflock.SessionMetrics{
			CostUSD: 1.0,
		},
	}
	writeSessionState(t, tmpDir, "sess-rego-pass", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-rego-pass")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success, got errors: %v", result.Errors)
	}
	found := false
	for _, c := range result.Checks {
		if c.Name == "rego" && c.Passed {
			found = true
		}
	}
	if !found {
		t.Error("Expected passing rego check")
	}
}

func TestVerifySession_RegoDeny(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-rego-deny",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "rego-test",
			Version: "1.0",
			Evaluators: &aflock.EvaluatorsPolicy{
				Rego: []aflock.RegoEvaluator{
					{
						Name: "spend-limit",
						Policy: `package aflock
deny[msg] {
  input.metrics.costUSD > 5.0
  msg := sprintf("Spend $%.2f exceeds $5.00", [input.metrics.costUSD])
}`,
					},
				},
			},
		},
		Actions: []aflock.ActionRecord{
			{Timestamp: time.Now(), ToolName: "Read", ToolUseID: "tu_1", Decision: "allow"},
		},
		Metrics: &aflock.SessionMetrics{
			CostUSD: 10.50,
		},
	}
	writeSessionState(t, tmpDir, "sess-rego-deny", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-rego-deny")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for rego deny")
	}
	if len(result.Errors) == 0 {
		t.Error("Expected at least one error")
	}
	foundRego := false
	for _, c := range result.Checks {
		if c.Name == "rego" && !c.Passed {
			foundRego = true
		}
	}
	if !foundRego {
		t.Error("Expected failing rego check")
	}
}

func TestVerifySession_NoRegoPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-no-rego",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "no-rego",
			Version: "1.0",
		},
		Metrics: &aflock.SessionMetrics{},
	}
	writeSessionState(t, tmpDir, "sess-no-rego", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-no-rego")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success, got errors: %v", result.Errors)
	}
	for _, c := range result.Checks {
		if c.Name == "rego" {
			t.Error("Should not have rego check when no evaluators defined")
		}
	}
}

func TestVerifySession_RegoMultiplePolicies(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-rego-multi",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "rego-multi",
			Version: "1.0",
			Evaluators: &aflock.EvaluatorsPolicy{
				Rego: []aflock.RegoEvaluator{
					{
						Name:   "cost-check",
						Policy: "package cost\ndeny[msg] {\n  input.metrics.costUSD > 100\n  msg := \"Cost too high\"\n}",
					},
					{
						Name:   "turns-check",
						Policy: "package turns\ndeny[msg] {\n  input.metrics.turns > 50\n  msg := \"Too many turns\"\n}",
					},
				},
			},
		},
		Metrics: &aflock.SessionMetrics{
			CostUSD: 200.0,
			Turns:   100,
		},
	}
	writeSessionState(t, tmpDir, "sess-rego-multi", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-rego-multi")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for multiple rego denials")
	}
	if len(result.Errors) < 2 {
		t.Errorf("Expected at least 2 errors, got %d: %v", len(result.Errors), result.Errors)
	}
}

// ---- Phase 3: Materials Binding (Merkle Tree) ----

// buildMerkleRootFromActions computes the Merkle root from action records for test setup.
func buildMerkleRootFromActions(t *testing.T, actions []aflock.ActionRecord) string {
	t.Helper()
	entries := make([][]byte, len(actions))
	for i, a := range actions {
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("marshal action %d: %v", i, err)
		}
		entries[i] = data
	}
	root, err := aflockMerkle.BuildRoot(entries)
	if err != nil {
		t.Fatalf("BuildRoot: %v", err)
	}
	return root
}

func TestVerifySession_MerklePass(t *testing.T) {
	tmpDir := t.TempDir()
	actions := []aflock.ActionRecord{
		{Timestamp: time.Now(), ToolName: "Read", ToolUseID: "tu_1", Decision: "allow"},
		{Timestamp: time.Now(), ToolName: "Edit", ToolUseID: "tu_2", Decision: "allow"},
	}
	merkleRoot := buildMerkleRootFromActions(t, actions)

	ss := &aflock.SessionState{
		SessionID: "sess-merkle-pass",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "merkle-test",
			Version: "1.0",
			MaterialsFrom: &aflock.MaterialsPolicy{
				Session: &aflock.SessionMaterial{
					MerkleRoot: merkleRoot,
				},
			},
		},
		Actions: actions,
		Metrics: &aflock.SessionMetrics{},
	}
	writeSessionState(t, tmpDir, "sess-merkle-pass", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-merkle-pass")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success, got errors: %v", result.Errors)
	}
	found := false
	for _, c := range result.Checks {
		if c.Name == "materials:merkle" && c.Passed {
			found = true
		}
	}
	if !found {
		t.Error("Expected passing materials:merkle check")
	}
}

func TestVerifySession_MerkleFail_TamperedAction(t *testing.T) {
	tmpDir := t.TempDir()
	originalActions := []aflock.ActionRecord{
		{Timestamp: time.Now(), ToolName: "Read", ToolUseID: "tu_1", Decision: "allow"},
		{Timestamp: time.Now(), ToolName: "Edit", ToolUseID: "tu_2", Decision: "allow"},
	}
	merkleRoot := buildMerkleRootFromActions(t, originalActions)

	// Tamper: change the tool name
	tamperedActions := []aflock.ActionRecord{
		{Timestamp: originalActions[0].Timestamp, ToolName: "Read", ToolUseID: "tu_1", Decision: "allow"},
		{Timestamp: originalActions[1].Timestamp, ToolName: "Bash", ToolUseID: "tu_2", Decision: "allow"}, // changed
	}

	ss := &aflock.SessionState{
		SessionID: "sess-merkle-tamper",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "merkle-test",
			Version: "1.0",
			MaterialsFrom: &aflock.MaterialsPolicy{
				Session: &aflock.SessionMaterial{
					MerkleRoot: merkleRoot,
				},
			},
		},
		Actions: tamperedActions,
		Metrics: &aflock.SessionMetrics{},
	}
	writeSessionState(t, tmpDir, "sess-merkle-tamper", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-merkle-tamper")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for tampered action")
	}
	foundMerkleError := false
	for _, e := range result.Errors {
		if len(e) > 0 {
			foundMerkleError = true
		}
	}
	if !foundMerkleError {
		t.Error("Expected merkle-related error")
	}
}

func TestVerifySession_MerkleFail_DroppedAction(t *testing.T) {
	tmpDir := t.TempDir()
	actions := []aflock.ActionRecord{
		{Timestamp: time.Now(), ToolName: "Read", ToolUseID: "tu_1", Decision: "allow"},
		{Timestamp: time.Now(), ToolName: "Bash", ToolUseID: "tu_2", Decision: "allow"},
		{Timestamp: time.Now(), ToolName: "Edit", ToolUseID: "tu_3", Decision: "allow"},
	}
	merkleRoot := buildMerkleRootFromActions(t, actions)

	// Drop the middle action (agent trying to hide Bash usage)
	droppedActions := []aflock.ActionRecord{
		actions[0],
		actions[2], // skipped actions[1]
	}

	ss := &aflock.SessionState{
		SessionID: "sess-merkle-drop",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "merkle-test",
			Version: "1.0",
			MaterialsFrom: &aflock.MaterialsPolicy{
				Session: &aflock.SessionMaterial{
					MerkleRoot: merkleRoot,
				},
			},
		},
		Actions: droppedActions,
		Metrics: &aflock.SessionMetrics{},
	}
	writeSessionState(t, tmpDir, "sess-merkle-drop", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-merkle-drop")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for dropped action")
	}
}

func TestVerifySession_NoMerklePolicy(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-no-merkle",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "no-merkle-test",
			Version: "1.0",
			// No MaterialsFrom — merkle check should be skipped
		},
		Metrics: &aflock.SessionMetrics{},
	}
	writeSessionState(t, tmpDir, "sess-no-merkle", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-no-merkle")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success, got errors: %v", result.Errors)
	}
	for _, c := range result.Checks {
		if c.Name == "materials:merkle" {
			t.Error("Should not have merkle check when no MaterialsFrom policy")
		}
	}
}

func TestVerifySession_MerkleEmptyRoot(t *testing.T) {
	tmpDir := t.TempDir()
	ss := &aflock.SessionState{
		SessionID: "sess-empty-root",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "empty-root-test",
			Version: "1.0",
			MaterialsFrom: &aflock.MaterialsPolicy{
				Session: &aflock.SessionMaterial{
					MerkleRoot: "", // Empty root — skip check
				},
			},
		},
		Metrics: &aflock.SessionMetrics{},
	}
	writeSessionState(t, tmpDir, "sess-empty-root", ss)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-empty-root")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success for empty merkle root, got errors: %v", result.Errors)
	}
}
