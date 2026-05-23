// Package issue_69 is an end-to-end regression test for the Stop-gate
// signer-cert forgery closed by PR #108 / issue #69.
//
// The test drives the real `aflock hook` CLI subcommands as subprocesses
// (the same way Claude Code drives them) and exercises the full lifecycle:
//
//  1. SessionStart  — establishes the per-session signer pin
//  2. PreToolUse    — authorizes a Bash call
//  3. PostToolUse   — produces a real attestation signed with the pinned key
//  4. drop-forgery  — overwrite the attestation file with an envelope signed
//     by a *foreign* keypair the attacker mints in-process
//  5. Stop          — expect BLOCK ("missing attestations for used tools")
//  6. restore-real  — put the legit attestation back
//  7. Stop          — expect ALLOW
//
// Step 5 is the exact bypass described in issue #69. If the Stop gate ever
// regresses to trusting the envelope's own cert, this test will start
// allowing the forgery and fail.
package issue_69

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aflock-ai/aflock/internal/attestation"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// hookOutput mirrors the subset of aflock.HookOutput the Stop gate emits.
type hookOutput struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

func TestE2E_StopGateRejectsForeignKeyForgery(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipping in short mode")
	}

	binary := buildAflockBinary(t)
	sessionDir, policyPath, projectCwd := setupTempEnv(t)
	t.Setenv("AFLOCK_POLICY", policyPath)

	sessionID := "e2e-issue-69"
	toolUseID := "tu-e2e-001"

	_ = sessionDir // kept by setupTempEnv via HOME

	// 1. SessionStart establishes the pin.
	runHook(t, binary, "SessionStart", aflock.HookInput{
		SessionID:     sessionID,
		Cwd:           projectCwd,
		HookEventName: aflock.HookSessionStart,
		Source:        "startup",
	})

	pubKey := filepath.Join(sessionDir, sessionID, "signer-pubkey.pem")
	if _, err := os.Stat(pubKey); err != nil {
		t.Fatalf("expected signer-pubkey.pem at %s after SessionStart, got: %v", pubKey, err)
	}

	// 2. PreToolUse — authorize Bash.
	runHook(t, binary, "PreToolUse", aflock.HookInput{
		SessionID:     sessionID,
		Cwd:           projectCwd,
		HookEventName: aflock.HookPreToolUse,
		ToolName:      "Bash",
		ToolUseID:     toolUseID,
		ToolInput:     json.RawMessage(`{"command":"echo hello"}`),
	})

	// 3. PostToolUse — produces a real attestation.
	runHook(t, binary, "PostToolUse", aflock.HookInput{
		SessionID:     sessionID,
		Cwd:           projectCwd,
		HookEventName: aflock.HookPostToolUse,
		ToolName:      "Bash",
		ToolUseID:     toolUseID,
		ToolInput:     json.RawMessage(`{"command":"echo hello"}`),
		ToolResponse:  json.RawMessage(`{"stdout":"hello"}`),
	})

	attestDir := filepath.Join(sessionDir, sessionID, "attestations")
	realAttestPath := findFirstAttestation(t, attestDir)
	realBytes, err := os.ReadFile(realAttestPath)
	if err != nil {
		t.Fatalf("read real attestation: %v", err)
	}

	// 4. Drop a forgery: same payload as the real one, but signed by a fresh
	// keypair the attacker mints locally. The Stop gate must refuse it
	// because the embedded cert's SPKI doesn't match the pinned fingerprint.
	forged := mintForgedEnvelope(t, sessionID, "Bash", toolUseID)
	forgedBytes, err := json.MarshalIndent(forged, "", "  ")
	if err != nil {
		t.Fatalf("marshal forgery: %v", err)
	}
	if err := os.WriteFile(realAttestPath, forgedBytes, 0600); err != nil {
		t.Fatalf("drop forgery: %v", err)
	}

	// 5. Stop must BLOCK.
	out := runHook(t, binary, "Stop", aflock.HookInput{
		SessionID:     sessionID,
		Cwd:           projectCwd,
		HookEventName: aflock.HookStop,
	})
	if out.Decision != "block" {
		t.Fatalf("forgery bypass — Stop must block, got decision=%q reason=%q", out.Decision, out.Reason)
	}
	if !strings.Contains(out.Reason, "missing attestations") {
		t.Fatalf("unexpected block reason: %q", out.Reason)
	}

	// 6. Restore the real attestation.
	if err := os.WriteFile(realAttestPath, realBytes, 0600); err != nil {
		t.Fatalf("restore real attestation: %v", err)
	}

	// 7. Stop must now ALLOW.
	out = runHook(t, binary, "Stop", aflock.HookInput{
		SessionID:     sessionID,
		Cwd:           projectCwd,
		HookEventName: aflock.HookStop,
	})
	if out.Decision == "block" {
		t.Fatalf("legitimate Stop blocked: %q", out.Reason)
	}
}

// TestE2E_StopGateRejectsBootstrapAttack covers the "no legit sign happened
// yet — attacker drops a self-signed attestation" scenario. Even though the
// envelope is internally valid (signature matches its own cert), the Stop
// gate fails closed because the session has no recorded pin.
func TestE2E_StopGateRejectsBootstrapAttack(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipping in short mode")
	}

	binary := buildAflockBinary(t)
	sessionDir, policyPath, projectCwd := setupTempEnv(t)
	t.Setenv("AFLOCK_POLICY", policyPath)

	sessionID := "e2e-issue-69-bootstrap"
	toolUseID := "tu-bootstrap-001"

	runHook(t, binary, "SessionStart", aflock.HookInput{
		SessionID:     sessionID,
		Cwd:           projectCwd,
		HookEventName: aflock.HookSessionStart,
		Source:        "startup",
	})

	// Strip the pin to simulate a pre-pinning session OR a state.json
	// stripped of its fingerprint. With no pin, the Stop gate must deny.
	if err := os.Remove(filepath.Join(sessionDir, sessionID, "signer-pubkey.pem")); err != nil {
		t.Fatalf("remove pin file: %v", err)
	}
	statePath := filepath.Join(sessionDir, sessionID, "state.json")
	stateRaw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var state map[string]any
	if err := json.Unmarshal(stateRaw, &state); err != nil {
		t.Fatalf("parse state: %v", err)
	}
	delete(state, "signer_pubkey_fingerprint")
	delete(state, "signing_mode")
	// Mark the Bash action as having been used so the requiredAttestations
	// gate has something to demand at Stop time.
	state["actions"] = []map[string]any{{
		"timestamp":   "2026-05-23T12:00:00Z",
		"tool_name":   "Bash",
		"tool_use_id": toolUseID,
		"decision":    "allow",
	}}
	newState, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal state: %v", err)
	}
	if err := os.WriteFile(statePath, newState, 0600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	// Attacker drops a fully-internally-valid envelope (signed with their
	// own cert) into the attestations dir.
	attestDir := filepath.Join(sessionDir, sessionID, "attestations")
	if err := os.MkdirAll(attestDir, 0700); err != nil {
		t.Fatalf("mkdir attest: %v", err)
	}
	forged := mintForgedEnvelope(t, sessionID, "Bash", toolUseID)
	forgedBytes, err := json.MarshalIndent(forged, "", "  ")
	if err != nil {
		t.Fatalf("marshal forgery: %v", err)
	}
	if err := os.WriteFile(filepath.Join(attestDir, "Bash.intoto.json"), forgedBytes, 0600); err != nil {
		t.Fatalf("drop forgery: %v", err)
	}

	out := runHook(t, binary, "Stop", aflock.HookInput{
		SessionID:     sessionID,
		Cwd:           projectCwd,
		HookEventName: aflock.HookStop,
	})
	if out.Decision != "block" {
		t.Fatalf("bootstrap attack — Stop must block, got decision=%q reason=%q", out.Decision, out.Reason)
	}
}

// mintForgedEnvelope produces a DSSE envelope signed with a fresh ephemeral
// key the attacker controls. Mirrors the in-issue reproduction sketch.
func mintForgedEnvelope(t *testing.T, sessionID, toolName, toolUseID string) *attestation.Envelope {
	t.Helper()
	signer := attestation.NewSigner("")
	if err := signer.InitializeEphemeral("attacker-identity"); err != nil {
		t.Fatalf("attacker signer init: %v", err)
	}
	t.Cleanup(func() { _ = signer.Close() })
	rec := aflock.ActionRecord{
		ToolName:  toolName,
		ToolUseID: toolUseID,
		Decision:  "allow",
	}
	env, err := signer.CreateActionAttestation(context.Background(), rec, sessionID, nil, nil, nil)
	if err != nil {
		t.Fatalf("attacker CreateActionAttestation: %v", err)
	}
	return env
}

func runHook(t *testing.T, binary, event string, input aflock.HookInput) hookOutput {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal hook input: %v", err)
	}
	cmd := exec.Command(binary, "hook", event)
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("aflock hook %s exited: %v\nstderr: %s", event, err, stderr.String())
	}
	stdoutBytes := stdout.Bytes()
	if len(stdoutBytes) == 0 {
		return hookOutput{}
	}
	var out hookOutput
	if err := json.Unmarshal(stdoutBytes, &out); err != nil {
		// Some hooks emit hook-specific output (e.g. context); not all carry
		// a decision. Treat unparsable output as no-decision rather than
		// failing — only Stop's output is asserted by the tests.
		return hookOutput{}
	}
	return out
}

func setupTempEnv(t *testing.T) (sessionDir, policyPath, projectCwd string) {
	t.Helper()
	tmp := t.TempDir()
	// state.NewManager("") expands ~/.aflock/sessions via $HOME. Redirect HOME
	// at the test boundary so the subprocess sees a private state root and
	// can't see / be seen by the real user's session dir.
	t.Setenv("HOME", tmp)
	sessionDir = filepath.Join(tmp, ".aflock", "sessions")
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	projectCwd = filepath.Join(tmp, "project")
	if err := os.MkdirAll(projectCwd, 0700); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	policy := map[string]any{
		"name":                 "issue-69-e2e",
		"version":              "1.0",
		"tools":                map[string]any{"allow": []string{"Bash"}},
		"requiredAttestations": []string{"Bash"},
	}
	policyBytes, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	policyPath = filepath.Join(projectCwd, ".aflock")
	if err := os.WriteFile(policyPath, policyBytes, 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return sessionDir, policyPath, projectCwd
}

func buildAflockBinary(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aflock")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	// Locate repo root: this test file is at <root>/test/e2e/issue_69/.
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	cmd := exec.Command("go", "build", "-mod=mod", "-o", bin, "./cmd/aflock")
	cmd.Dir = repoRoot
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build aflock binary: %v\nstderr: %s", err, stderr.String())
	}
	return bin
}

func findFirstAttestation(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read attestations dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".intoto.json") || strings.HasSuffix(name, ".json") {
			return filepath.Join(dir, name)
		}
	}
	t.Fatalf("no attestation file in %s after PostToolUse — got: %v", dir, fmt.Sprint(entries))
	return ""
}
