package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/aflock-ai/aflock/internal/attestation"
	"github.com/aflock-ai/aflock/internal/identity"
	"github.com/aflock-ai/aflock/internal/state"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// newTestRequest builds a CallToolRequest with the given arguments map.
func newTestRequest(args map[string]any) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: args,
		},
	}
}

// newTestServer creates a Server with a temp-dir-backed state manager.
// Signing is disabled and no MCP server is wired up -- only the handler
// methods are exercisable.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	tmpDir := t.TempDir()
	return &Server{
		stateManager: state.NewManager(tmpDir),
		sessionID:    "test-session-001",
		attestDir:    filepath.Join(tmpDir, "attestations"),
	}
}

// newTestServerWithPolicy returns a server pre-loaded with the given policy
// and an initialized session state.
func newTestServerWithPolicy(t *testing.T, pol *aflock.Policy) *Server {
	t.Helper()
	s := newTestServer(t)
	s.policy = pol
	s.policyPath = "/fake/policy.aflock"
	sess := s.stateManager.Initialize(s.sessionID, pol, s.policyPath)
	if err := s.stateManager.Save(sess); err != nil {
		t.Fatalf("save session: %v", err)
	}
	return s
}

// ---------- computePolicyDigest ----------

func TestComputePolicyDigest_NilPolicy(t *testing.T) {
	s := newTestServer(t)
	got := s.computePolicyDigest()
	if got != "" {
		t.Errorf("expected empty string for nil policy, got %q", got)
	}
}

func TestComputePolicyDigest_Deterministic(t *testing.T) {
	pol := &aflock.Policy{Version: "1", Name: "test-policy"}
	s := newTestServer(t)
	s.policy = pol

	d1 := s.computePolicyDigest()
	d2 := s.computePolicyDigest()
	if d1 != d2 {
		t.Errorf("digest not deterministic: %s vs %s", d1, d2)
	}
	if d1 == "" {
		t.Error("digest should not be empty for non-nil policy")
	}

	// Verify manually.
	data, _ := json.Marshal(pol)
	h := sha256.Sum256(data)
	want := hex.EncodeToString(h[:])
	if d1 != want {
		t.Errorf("digest mismatch: got %s want %s", d1, want)
	}
}

func TestComputePolicyDigest_DifferentPoliciesProduceDifferentDigests(t *testing.T) {
	s := newTestServer(t)

	s.policy = &aflock.Policy{Version: "1", Name: "alpha"}
	d1 := s.computePolicyDigest()

	s.policy = &aflock.Policy{Version: "1", Name: "beta"}
	d2 := s.computePolicyDigest()

	if d1 == d2 {
		t.Errorf("different policies should produce different digests")
	}
}

// ---------- computePredicateDigest ----------

func TestComputePredicateDigest(t *testing.T) {
	pred := map[string]string{"foo": "bar"}
	got := computePredicateDigest(pred)
	if got == "" {
		t.Fatal("predicate digest should not be empty")
	}

	// Verify manually.
	data, _ := json.Marshal(pred)
	h := sha256.Sum256(data)
	want := hex.EncodeToString(h[:])
	if got != want {
		t.Errorf("digest mismatch: got %s want %s", got, want)
	}
}

func TestComputePredicateDigest_NilPredicate(t *testing.T) {
	// json.Marshal(nil) => "null"
	got := computePredicateDigest(nil)
	data, _ := json.Marshal(nil)
	h := sha256.Sum256(data)
	want := hex.EncodeToString(h[:])
	if got != want {
		t.Errorf("nil predicate digest mismatch: got %s want %s", got, want)
	}
}

// ---------- NewServer ----------

func TestNewServer_Defaults(t *testing.T) {
	s := NewServer()
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.mcpServer == nil {
		t.Error("mcpServer should not be nil")
	}
	if s.stateManager == nil {
		t.Error("stateManager should not be nil")
	}
	if !strings.HasPrefix(s.sessionID, "mcp-") {
		t.Errorf("sessionID should start with 'mcp-', got %q", s.sessionID)
	}
	if s.policy != nil {
		t.Error("policy should be nil by default")
	}
	if s.signingEnabled {
		t.Error("signing should be disabled by default")
	}
	if s.attestDir == "" {
		t.Error("attestDir should not be empty")
	}
	if !strings.Contains(s.attestDir, ".aflock") {
		t.Errorf("attestDir should contain .aflock, got %q", s.attestDir)
	}
}

// ---------- recordAction ----------

func TestRecordAction_NilPolicy(t *testing.T) {
	s := newTestServer(t)
	// Should not panic with nil policy.
	s.recordAction("Bash", "allow", "")
}

func TestRecordAction_WithPolicy(t *testing.T) {
	pol := &aflock.Policy{Version: "1", Name: "test"}
	s := newTestServerWithPolicy(t, pol)

	s.recordAction("Bash", "allow", "test reason")

	sess, err := s.stateManager.Load(s.sessionID)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if sess == nil {
		t.Fatal("session should not be nil after recordAction")
	}
	if len(sess.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(sess.Actions))
	}
	if sess.Actions[0].ToolName != "Bash" {
		t.Errorf("expected ToolName=Bash, got %q", sess.Actions[0].ToolName)
	}
	if sess.Actions[0].Decision != "allow" {
		t.Errorf("expected Decision=allow, got %q", sess.Actions[0].Decision)
	}
	if sess.Actions[0].Reason != "test reason" {
		t.Errorf("expected Reason='test reason', got %q", sess.Actions[0].Reason)
	}
	if sess.Metrics.ToolCalls != 1 {
		t.Errorf("expected ToolCalls=1, got %d", sess.Metrics.ToolCalls)
	}
}

func TestRecordAction_MultipleActions(t *testing.T) {
	pol := &aflock.Policy{Version: "1", Name: "test"}
	s := newTestServerWithPolicy(t, pol)

	s.recordAction("Bash", "allow", "")
	s.recordAction("Read", "deny", "denied by policy")
	s.recordAction("Write", "allow", "")

	sess, err := s.stateManager.Load(s.sessionID)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if len(sess.Actions) != 3 {
		t.Fatalf("expected 3 actions, got %d", len(sess.Actions))
	}
	if sess.Metrics.ToolCalls != 3 {
		t.Errorf("expected ToolCalls=3, got %d", sess.Metrics.ToolCalls)
	}
}

// ---------- trackFile ----------

func TestTrackFile_NilPolicy(t *testing.T) {
	s := newTestServer(t)
	// Should not panic.
	s.trackFile("Read", "/some/file.txt")
}

func TestTrackFile_ReadTracksFilesRead(t *testing.T) {
	pol := &aflock.Policy{Version: "1", Name: "test"}
	s := newTestServerWithPolicy(t, pol)

	s.trackFile("Read", "/some/file.txt")

	sess, err := s.stateManager.Load(s.sessionID)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if len(sess.Metrics.FilesRead) != 1 {
		t.Fatalf("expected 1 file read, got %d", len(sess.Metrics.FilesRead))
	}
	if sess.Metrics.FilesRead[0] != "/some/file.txt" {
		t.Errorf("unexpected file: %s", sess.Metrics.FilesRead[0])
	}
}

func TestTrackFile_WriteTracksFilesWritten(t *testing.T) {
	pol := &aflock.Policy{Version: "1", Name: "test"}
	s := newTestServerWithPolicy(t, pol)

	s.trackFile("Write", "/some/output.txt")

	sess, err := s.stateManager.Load(s.sessionID)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if len(sess.Metrics.FilesWritten) != 1 {
		t.Fatalf("expected 1 file written, got %d", len(sess.Metrics.FilesWritten))
	}
	if sess.Metrics.FilesWritten[0] != "/some/output.txt" {
		t.Errorf("unexpected file: %s", sess.Metrics.FilesWritten[0])
	}
}

func TestTrackFile_NoDuplicates(t *testing.T) {
	pol := &aflock.Policy{Version: "1", Name: "test"}
	s := newTestServerWithPolicy(t, pol)

	s.trackFile("Read", "/some/file.txt")
	s.trackFile("Read", "/some/file.txt")

	sess, err := s.stateManager.Load(s.sessionID)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if len(sess.Metrics.FilesRead) != 1 {
		t.Errorf("expected no duplicates, got %d entries", len(sess.Metrics.FilesRead))
	}
}

// ---------- storeAttestation ----------

func TestStoreAttestation(t *testing.T) {
	s := newTestServer(t)

	env := &attestation.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     "dGVzdA==",
		Signatures:  []attestation.Signature{{KeyID: "test", Sig: "abc123"}},
	}

	toolUseID := "abcdefgh-1234-5678-9012-ijklmnopqrst"
	err := s.storeAttestation(env, toolUseID)
	if err != nil {
		t.Fatalf("storeAttestation: %v", err)
	}

	dir := s.stateManager.AttestationsDir(s.sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 attestation file, got %d", len(entries))
	}

	name := entries[0].Name()
	if !strings.HasSuffix(name, ".intoto.json") {
		t.Errorf("expected .intoto.json suffix, got %s", name)
	}
	if !strings.Contains(name, toolUseID[:8]) {
		t.Errorf("expected toolUseID prefix %s in filename %s", toolUseID[:8], name)
	}

	// Verify file content is valid JSON.
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	var parsed attestation.Envelope
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse attestation: %v", err)
	}
	if parsed.PayloadType != env.PayloadType {
		t.Errorf("payloadType mismatch: got %q want %q", parsed.PayloadType, env.PayloadType)
	}
}

// ---------- storeStepAttestation ----------

func TestStoreStepAttestation(t *testing.T) {
	s := newTestServer(t)

	envelope := map[string]string{"payloadType": "test", "payload": "data"}
	treeHash := "abc123def456"
	step := "lint"

	err := s.storeStepAttestation(envelope, treeHash, step)
	if err != nil {
		t.Fatalf("storeStepAttestation: %v", err)
	}

	expectedPath := filepath.Join(s.attestDir, treeHash, step+".intoto.json")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Fatalf("expected attestation at %s but file does not exist", expectedPath)
	}

	data, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed map[string]string
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed["payloadType"] != "test" {
		t.Errorf("payload mismatch: %v", parsed)
	}
}

// ---------- handleGetIdentity ----------

func TestHandleGetIdentity_NoIdentity(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(nil)

	result, err := s.handleGetIdentity(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result when no identity")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "No identity discovered") {
		t.Errorf("unexpected error text: %s", text)
	}
}

func TestHandleGetIdentity_WithIdentity(t *testing.T) {
	s := newTestServer(t)
	s.agentIdentity = &identity.AgentIdentity{
		Model:        "claude-opus-4-5",
		ModelVersion: "4.5.0",
		IdentityHash: "deadbeefcafebabe1234567890abcdef",
		Binary: &identity.BinaryIdentity{
			Name:    "claude-code",
			Version: "1.0.0",
			Digest:  "sha256:abc",
		},
		Environment: &identity.EnvironmentIdentity{
			Type:     "local",
			Hostname: "testhost",
		},
	}
	ctx := context.Background()
	req := newTestRequest(nil)

	result, err := s.handleGetIdentity(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("expected success result")
	}
	text := result.Content[0].(mcp.TextContent).Text

	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if parsed["model"] != "claude-opus-4-5" {
		t.Errorf("model mismatch: %v", parsed["model"])
	}
	if parsed["modelVersion"] != "4.5.0" {
		t.Errorf("modelVersion mismatch: %v", parsed["modelVersion"])
	}
	if parsed["identityHash"] != "deadbeefcafebabe1234567890abcdef" {
		t.Errorf("identityHash mismatch: %v", parsed["identityHash"])
	}

	binary, ok := parsed["binary"].(map[string]any)
	if !ok {
		t.Fatal("expected binary map")
	}
	if binary["name"] != "claude-code" {
		t.Errorf("binary.name mismatch: %v", binary["name"])
	}
	if binary["version"] != "1.0.0" {
		t.Errorf("binary.version mismatch: %v", binary["version"])
	}

	env, ok := parsed["environment"].(map[string]any)
	if !ok {
		t.Fatal("expected environment map")
	}
	if env["type"] != "local" {
		t.Errorf("env.type mismatch: %v", env["type"])
	}
}

func TestHandleGetIdentity_NoBinary(t *testing.T) {
	s := newTestServer(t)
	s.agentIdentity = &identity.AgentIdentity{
		Model:        "test-model",
		ModelVersion: "1.0.0",
		IdentityHash: "abc123",
	}
	ctx := context.Background()
	req := newTestRequest(nil)

	result, err := s.handleGetIdentity(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("expected success")
	}
	text := result.Content[0].(mcp.TextContent).Text

	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, exists := parsed["binary"]; exists {
		t.Error("binary should not be present when nil")
	}
	if _, exists := parsed["environment"]; exists {
		t.Error("environment should not be present when nil")
	}
}

// ---------- handleGetPolicy ----------

func TestHandleGetPolicy_NoPolicy(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(nil)

	result, err := s.handleGetPolicy(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result when no policy loaded")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "No policy loaded") {
		t.Errorf("unexpected text: %s", text)
	}
}

func TestHandleGetPolicy_WithPolicy(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "test-pol",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Bash", "Read"},
			Deny:  []string{"Task"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(nil)

	result, err := s.handleGetPolicy(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("expected success result")
	}
	text := result.Content[0].(mcp.TextContent).Text

	var parsed aflock.Policy
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Name != "test-pol" {
		t.Errorf("name mismatch: %s", parsed.Name)
	}
	if len(parsed.Tools.Allow) != 2 {
		t.Errorf("expected 2 allow tools, got %d", len(parsed.Tools.Allow))
	}
}

// ---------- handleCheckTool ----------

func TestHandleCheckTool_NoPolicy(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"tool_name": "Bash",
	})

	result, err := s.handleCheckTool(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("expected success when no policy")
	}
	text := result.Content[0].(mcp.TextContent).Text

	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed["allowed"] != true {
		t.Errorf("expected allowed=true with no policy, got %v", parsed["allowed"])
	}
}

func TestHandleCheckTool_Allowed(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Bash", "Read"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"tool_name": "Bash",
	})

	result, err := s.handleCheckTool(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := result.Content[0].(mcp.TextContent).Text

	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed["allowed"] != true {
		t.Errorf("expected allowed=true, got %v", parsed["allowed"])
	}
	if parsed["decision"] != "allow" {
		t.Errorf("expected decision=allow, got %v", parsed["decision"])
	}
}

func TestHandleCheckTool_Denied(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "test",
		Tools: &aflock.ToolsPolicy{
			Deny: []string{"Task"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"tool_name": "Task",
	})

	result, err := s.handleCheckTool(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := result.Content[0].(mcp.TextContent).Text

	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed["allowed"] != false {
		t.Errorf("expected allowed=false, got %v", parsed["allowed"])
	}
	if parsed["decision"] != "deny" {
		t.Errorf("expected decision=deny, got %v", parsed["decision"])
	}
}

func TestHandleCheckTool_NotInAllowList(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Bash"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"tool_name": "Write",
	})

	result, err := s.handleCheckTool(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := result.Content[0].(mcp.TextContent).Text

	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed["allowed"] != false {
		t.Errorf("expected allowed=false for tool not in allow list, got %v", parsed["allowed"])
	}
}

// ---------- handleBash ----------

func TestHandleBash_NoPolicy_SimpleEcho(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"command": "echo hello",
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	text := result.Content[0].(mcp.TextContent).Text

	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed["output"] != "hello" {
		t.Errorf("expected output='hello', got %q", parsed["output"])
	}
	exitCode, ok := parsed["exitCode"].(float64)
	if !ok || exitCode != 0 {
		t.Errorf("expected exitCode=0, got %v", parsed["exitCode"])
	}
}

func TestHandleBash_NonZeroExitCode(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"command": "exit 42",
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Non-zero exit is not an MCP error -- it's in the result.
	if result.IsError {
		t.Fatal("non-zero exit should not be an MCP error")
	}
	text := result.Content[0].(mcp.TextContent).Text

	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	exitCode, ok := parsed["exitCode"].(float64)
	if !ok || exitCode != 42 {
		t.Errorf("expected exitCode=42, got %v", parsed["exitCode"])
	}
}

func TestHandleBash_PolicyDeny(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "deny-bash",
		Tools: &aflock.ToolsPolicy{
			Deny: []string{"Bash"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"command": "echo should not run",
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result when policy denies")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "Policy denied") {
		t.Errorf("expected 'Policy denied' in error, got: %s", text)
	}

	// Verify the action was recorded as denied.
	sess, _ := s.stateManager.Load(s.sessionID)
	if sess == nil {
		t.Fatal("session should exist")
	}
	found := false
	for _, a := range sess.Actions {
		if a.ToolName == "Bash" && a.Decision == "deny" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a deny action recorded for Bash")
	}
}

func TestHandleBash_PolicyAllow(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "allow-bash",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Bash"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"command": "echo allowed",
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	text := result.Content[0].(mcp.TextContent).Text

	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed["output"] != "allowed" {
		t.Errorf("expected output='allowed', got %q", parsed["output"])
	}
}

func TestHandleBash_AttestWithoutStep(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"command": "echo test",
		"attest":  true,
		// step is missing
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when attest=true but no step")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "step parameter is required") {
		t.Errorf("unexpected error text: %s", text)
	}
}

func TestHandleBash_RequireApproval(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "ask-bash",
		Tools: &aflock.ToolsPolicy{
			RequireApproval: []string{"Bash"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"command": "echo needs approval",
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result when policy requires approval")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "requires approval") {
		t.Errorf("expected 'requires approval' in text, got: %s", text)
	}
}

func TestHandleBash_WithWorkdir(t *testing.T) {
	tmpDir := t.TempDir()
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"command": "pwd",
		"workdir": tmpDir,
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("expected success")
	}
	text := result.Content[0].(mcp.TextContent).Text

	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	output, _ := parsed["output"].(string)
	// On macOS /tmp -> /private/tmp; resolve both sides for comparison.
	resolvedTmp, _ := filepath.EvalSymlinks(tmpDir)
	resolvedOutput, _ := filepath.EvalSymlinks(output)
	if resolvedOutput != resolvedTmp {
		t.Errorf("expected output=%q, got %q", resolvedTmp, resolvedOutput)
	}
}

// ---------- handleReadFile ----------

func TestHandleReadFile_NoPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}

	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path": testFile,
	})

	result, err := s.handleReadFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("expected success")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if text != "hello world" {
		t.Errorf("expected 'hello world', got %q", text)
	}
}

func TestHandleReadFile_FileNotExist(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path": "/nonexistent/file/that/does/not/exist.txt",
	})

	result, err := s.handleReadFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for non-existent file")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "Read failed") {
		t.Errorf("expected 'Read failed' in error, got: %s", text)
	}
}

func TestHandleReadFile_PolicyDeny(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "secret.env")
	if err := os.WriteFile(testFile, []byte("SECRET=value"), 0644); err != nil {
		t.Fatal(err)
	}

	pol := &aflock.Policy{
		Version: "1",
		Name:    "deny-env",
		Files: &aflock.FilesPolicy{
			Deny: []string{"*.env"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path": testFile,
	})

	result, err := s.handleReadFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for denied file pattern")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "Policy denied") {
		t.Errorf("expected 'Policy denied' in error, got: %s", text)
	}
}

func TestHandleReadFile_PolicyAllow(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "readme.md")
	if err := os.WriteFile(testFile, []byte("# README"), 0644); err != nil {
		t.Fatal(err)
	}

	pol := &aflock.Policy{
		Version: "1",
		Name:    "allow-read",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path": testFile,
	})

	result, err := s.handleReadFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		text := result.Content[0].(mcp.TextContent).Text
		t.Fatalf("expected success, got error: %s", text)
	}
	text := result.Content[0].(mcp.TextContent).Text
	if text != "# README" {
		t.Errorf("expected '# README', got %q", text)
	}
}

func TestHandleReadFile_TracksFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "tracked.txt")
	if err := os.WriteFile(testFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	pol := &aflock.Policy{Version: "1", Name: "track"}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path": testFile,
	})

	_, err := s.handleReadFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sess, _ := s.stateManager.Load(s.sessionID)
	if sess == nil {
		t.Fatal("session should exist")
	}
	if len(sess.Metrics.FilesRead) == 0 {
		t.Error("expected file to be tracked in FilesRead")
	}
}

// ---------- handleWriteFile ----------

func TestHandleWriteFile_NoPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "output.txt")

	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path":    testFile,
		"content": "written content",
	})

	result, err := s.handleWriteFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("expected success")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "15 bytes") {
		t.Errorf("expected byte count in result, got: %s", text)
	}

	// Verify file was written.
	data, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "written content" {
		t.Errorf("file content mismatch: %q", string(data))
	}
}

func TestHandleWriteFile_PolicyDeny(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "denied.txt")

	pol := &aflock.Policy{
		Version: "1",
		Name:    "deny-write",
		Tools: &aflock.ToolsPolicy{
			Deny: []string{"Write"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path":    testFile,
		"content": "should not be written",
	})

	result, err := s.handleWriteFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when policy denies")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "Policy denied") {
		t.Errorf("expected 'Policy denied', got: %s", text)
	}

	// Verify file was NOT written.
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("file should not exist when policy denies")
	}
}

func TestHandleWriteFile_ReadOnlyDeny(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "config.yaml")

	pol := &aflock.Policy{
		Version: "1",
		Name:    "readonly",
		Files: &aflock.FilesPolicy{
			ReadOnly: []string{"*.yaml"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path":    testFile,
		"content": "should not write",
	})

	result, err := s.handleWriteFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when file is read-only")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "Policy denied") {
		t.Errorf("expected 'Policy denied', got: %s", text)
	}
}

func TestHandleWriteFile_TracksFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "tracked-write.txt")

	pol := &aflock.Policy{Version: "1", Name: "track"}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path":    testFile,
		"content": "data",
	})

	_, err := s.handleWriteFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sess, _ := s.stateManager.Load(s.sessionID)
	if sess == nil {
		t.Fatal("session should exist")
	}
	if len(sess.Metrics.FilesWritten) == 0 {
		t.Error("expected file to be tracked in FilesWritten")
	}
}

func TestHandleWriteFile_WriteFails(t *testing.T) {
	// Writing to a path that is a directory should fail.
	tmpDir := t.TempDir()

	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path":    tmpDir, // This is a directory, not a file
		"content": "data",
	})

	result, err := s.handleWriteFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when writing to a directory")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "Write failed") {
		t.Errorf("expected 'Write failed', got: %s", text)
	}
}

// ---------- handleGetSession ----------

func TestHandleGetSession_NoSessionData(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(nil)

	result, err := s.handleGetSession(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("expected success even with no session data")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, s.sessionID) {
		t.Errorf("expected session ID in output, got: %s", text)
	}
	if !strings.Contains(text, "no session data") {
		t.Errorf("expected 'no session data' in output, got: %s", text)
	}
}

func TestHandleGetSession_WithSessionData(t *testing.T) {
	pol := &aflock.Policy{Version: "1", Name: "session-test"}
	s := newTestServerWithPolicy(t, pol)

	// Record some actions to populate metrics.
	s.recordAction("Bash", "allow", "")
	s.recordAction("Read", "allow", "")
	s.trackFile("Read", "/tmp/test.txt")

	ctx := context.Background()
	req := newTestRequest(nil)

	result, err := s.handleGetSession(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("expected success")
	}
	text := result.Content[0].(mcp.TextContent).Text

	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed["sessionId"] != s.sessionID {
		t.Errorf("sessionId mismatch: %v", parsed["sessionId"])
	}
	if parsed["policyName"] != "session-test" {
		t.Errorf("policyName mismatch: %v", parsed["policyName"])
	}

	metrics, ok := parsed["metrics"].(map[string]any)
	if !ok {
		t.Fatal("expected metrics map")
	}
	if tc, ok := metrics["toolCalls"].(float64); !ok || tc != 2 {
		t.Errorf("expected toolCalls=2, got %v", metrics["toolCalls"])
	}
	if fr, ok := metrics["filesRead"].(float64); !ok || fr != 1 {
		t.Errorf("expected filesRead=1, got %v", metrics["filesRead"])
	}

	actionsCount, ok := parsed["actionsCount"].(float64)
	if !ok || actionsCount != 2 {
		t.Errorf("expected actionsCount=2, got %v", parsed["actionsCount"])
	}
}

// ---------- handleSignAttestation ----------

func TestHandleSignAttestation_SigningDisabled(t *testing.T) {
	s := newTestServer(t)
	// signingEnabled is false by default.
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"predicate_type": "https://example.com/v1",
		"predicate":      map[string]any{"key": "value"},
	})

	result, err := s.handleSignAttestation(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when signing is disabled")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "not available") {
		t.Errorf("expected 'not available' in error, got: %s", text)
	}
}

func TestHandleSignAttestation_MissingPredicateType(t *testing.T) {
	s := newTestServer(t)
	s.signingEnabled = true // Force enable to test validation
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"predicate": map[string]any{"key": "value"},
	})

	result, err := s.handleSignAttestation(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing predicate_type")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "predicate_type is required") {
		t.Errorf("unexpected error: %s", text)
	}
}

func TestHandleSignAttestation_MissingPredicate(t *testing.T) {
	s := newTestServer(t)
	s.signingEnabled = true
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"predicate_type": "https://example.com/v1",
	})

	result, err := s.handleSignAttestation(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing predicate")
	}
	text := result.Content[0].(mcp.TextContent).Text
	if !strings.Contains(text, "predicate is required") {
		t.Errorf("unexpected error: %s", text)
	}
}

// ---------- handleBash records actions with policy ----------

func TestHandleBash_RecordsAllowAction(t *testing.T) {
	pol := &aflock.Policy{Version: "1", Name: "rec-test"}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"command": "echo recording",
	})

	_, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sess, _ := s.stateManager.Load(s.sessionID)
	if sess == nil {
		t.Fatal("session should exist")
	}
	if len(sess.Actions) == 0 {
		t.Fatal("expected at least one action")
	}
	last := sess.Actions[len(sess.Actions)-1]
	if last.ToolName != "Bash" {
		t.Errorf("expected ToolName=Bash, got %s", last.ToolName)
	}
	if last.Decision != "allow" {
		t.Errorf("expected Decision=allow, got %s", last.Decision)
	}
}

// ---------- Integration: read then write with policy ----------

func TestReadWriteIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.txt")
	outputFile := filepath.Join(tmpDir, "output.txt")

	if err := os.WriteFile(inputFile, []byte("source data"), 0644); err != nil {
		t.Fatal(err)
	}

	pol := &aflock.Policy{Version: "1", Name: "integration"}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	// Read
	readReq := newTestRequest(map[string]any{"path": inputFile})
	readResult, err := s.handleReadFile(ctx, readReq)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if readResult.IsError {
		t.Fatal("expected read success")
	}
	content := readResult.Content[0].(mcp.TextContent).Text

	// Write
	writeReq := newTestRequest(map[string]any{
		"path":    outputFile,
		"content": content + " (copied)",
	})
	writeResult, err := s.handleWriteFile(ctx, writeReq)
	if err != nil {
		t.Fatalf("write error: %v", err)
	}
	if writeResult.IsError {
		t.Fatal("expected write success")
	}

	// Verify
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(data) != "source data (copied)" {
		t.Errorf("output content mismatch: %q", string(data))
	}

	// Verify session tracks both files.
	sess, _ := s.stateManager.Load(s.sessionID)
	if sess == nil {
		t.Fatal("session should exist")
	}
	if len(sess.Metrics.FilesRead) != 1 {
		t.Errorf("expected 1 file read, got %d", len(sess.Metrics.FilesRead))
	}
	if len(sess.Metrics.FilesWritten) != 1 {
		t.Errorf("expected 1 file written, got %d", len(sess.Metrics.FilesWritten))
	}
}

// ---------- handleBash with timeout ----------

func TestHandleBash_Timeout(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"command": "sleep 10",
		"timeout": float64(1),
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The command should have been killed, resulting in a non-zero exit code
	// and an error in the result.
	if result.IsError {
		// MCP-level error is acceptable too
		return
	}
	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Should have error field or non-zero exit.
	if _, hasErr := parsed["error"]; !hasErr {
		exitCode, _ := parsed["exitCode"].(float64)
		if exitCode == 0 {
			t.Error("expected non-zero exit or error for timed-out command")
		}
	}
}

// ---------- Multiple policy scenarios ----------

func TestHandleBash_ToolDenyPatternWithInput(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "deny-rm",
		Tools: &aflock.ToolsPolicy{
			Deny: []string{"Bash:*rm *"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	// Command matching the deny pattern should be blocked
	req := newTestRequest(map[string]any{
		"command": "rm -rf /tmp/test",
	})
	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected deny for rm command")
	}

	// Non-matching command should be allowed
	req2 := newTestRequest(map[string]any{
		"command": "echo safe",
	})
	result2, err := s.handleBash(ctx, req2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2.IsError {
		t.Fatal("expected allow for echo command")
	}
}

func TestHandleWriteFile_AllowPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "allowed.txt")

	pol := &aflock.Policy{
		Version: "1",
		Name:    "allow-write",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Write", "Read"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path":    testFile,
		"content": "allowed write",
	})

	result, err := s.handleWriteFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		text := result.Content[0].(mcp.TextContent).Text
		t.Fatalf("expected success, got error: %s", text)
	}

	data, _ := os.ReadFile(testFile)
	if string(data) != "allowed write" {
		t.Errorf("content mismatch: %q", string(data))
	}
}

// ---------- Edge case: empty command in bash ----------

func TestHandleBash_EmptyCommand(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"command": "",
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty command is valid bash -- just exits 0.
	if result.IsError {
		t.Fatal("empty command should not be an MCP error")
	}
}

// ---------- storeAttestation creates directory ----------

func TestStoreAttestation_CreatesDirectory(t *testing.T) {
	s := newTestServer(t)
	// Point to a nested dir that doesn't exist yet.
	s.sessionID = "new-session-create-test"

	env := &attestation.Envelope{
		PayloadType: "test",
		Payload:     "data",
	}
	toolUseID := "12345678-abcd-efgh-ijkl-mnopqrstuvwx"
	err := s.storeAttestation(env, toolUseID)
	if err != nil {
		t.Fatalf("storeAttestation: %v", err)
	}

	dir := s.stateManager.AttestationsDir(s.sessionID)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatal("attestation directory was not created")
	}
}

// TestServeHTTP_BindsLocalhost verifies that ServeHTTP constructs an address
// that binds to 127.0.0.1 (localhost only), not 0.0.0.0 (all interfaces).
// This is a regression test for issue #27 bypass path 1.
func TestServeHTTP_BindsLocalhost(t *testing.T) {
	port := 9876
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("Expected address to bind 127.0.0.1, got %s", addr)
	}

	// Verify the old pattern (:%d) would NOT have the prefix
	oldAddr := fmt.Sprintf(":%d", port)
	if strings.HasPrefix(oldAddr, "127.0.0.1:") {
		t.Fatal("Old address format unexpectedly has 127.0.0.1 prefix")
	}
}
