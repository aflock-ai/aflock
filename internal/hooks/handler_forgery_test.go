package hooks

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/internal/attestation"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Stop-gate forgery tests. The paper claims (§2.1) that a compromised agent
// cannot forge attestations of compliant behavior. These tests guard the
// Stop/SubagentStop gate against the narrower attacker who can only drop
// files into the session attestations dir — full paper-alignment against an
// agent that can ALSO drive the signer is tracked as an architectural gap
// (hooks-mode signing key lives in the agent's trust domain).

// Helper: produce a valid signed attestation using the ephemeral signer so
// the test is independent of SPIRE/Fulcio availability.
func newSignedAttestation(t *testing.T, sessionID, toolName, toolUseID, decision string) *attestation.Envelope {
	t.Helper()
	signer := attestation.NewSigner("")
	if err := signer.InitializeEphemeral("test-identity"); err != nil {
		t.Fatalf("InitializeEphemeral: %v", err)
	}
	t.Cleanup(func() { _ = signer.Close() })

	// Minimal ActionRecord — the fields the predicate binds to are what
	// the Stop-gate verifier checks.
	rec := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  toolName,
		ToolUseID: toolUseID,
		Decision:  decision,
	}
	env, err := signer.CreateActionAttestation(t.Context(), rec, sessionID, nil, nil)
	if err != nil {
		t.Fatalf("CreateActionAttestation: %v", err)
	}
	return env
}

func writeEnvelope(t *testing.T, path string, env *attestation.Envelope) {
	t.Helper()
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestHandleStop_RejectsTrivialStructuralForgery covers the L1 fix:
// a bare-minimum DSSE-shaped JSON that the old `validateAttestationIntegrity`
// accepted must now be rejected. This is the "drop one file, bypass Stop"
// attack.
func TestHandleStop_RejectsTrivialStructuralForgery(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "forgery",
		Tools:                &aflock.ToolsPolicy{Allow: []string{"Bash"}},
		RequiredAttestations: []string{"Bash"},
	}
	ss := seedSession(t, h, "session-forged-trivial", pol)
	ss.Actions = append(ss.Actions, aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Bash",
		ToolUseID: "tu-1",
		Decision:  "allow",
	})
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Drop the minimal forgery the reviewer described.
	attestDir := h.stateManager.AttestationsDir("session-forged-trivial")
	if err := os.MkdirAll(attestDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	forged := `{"payload":"` + base64.StdEncoding.EncodeToString([]byte("x")) + `","payloadType":"y","signatures":[{"sig":"z"}]}`
	if err := os.WriteFile(filepath.Join(attestDir, "Bash.intoto.json"), []byte(forged), 0600); err != nil {
		t.Fatalf("write forged: %v", err)
	}

	input := &aflock.HookInput{SessionID: "session-forged-trivial"}
	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse: %v (raw: %s)", err, got)
	}
	if out.Decision != "block" {
		t.Errorf("trivial forgery must NOT satisfy Stop gate, got decision=%q reason=%q", out.Decision, out.Reason)
	}
}

// TestHandleStop_RejectsStructurallyValidButCryptoInvalid covers the L2 fix:
// an envelope that passes all structural checks — valid base64, non-empty
// keyid/sig, parseable in-toto Statement — but whose signature does NOT
// verify against the embedded cert. This is the attacker who understands
// the format but doesn't have any signing key.
func TestHandleStop_RejectsStructurallyValidButCryptoInvalid(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "forgery-crypto",
		Tools:                &aflock.ToolsPolicy{Allow: []string{"Bash"}},
		RequiredAttestations: []string{"Bash"},
	}
	ss := seedSession(t, h, "session-forged-crypto", pol)
	ss.Actions = append(ss.Actions, aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Bash",
		ToolUseID: "tu-crypto-1",
		Decision:  "allow",
	})
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Build a real envelope, then corrupt the signature so crypto check fails.
	env := newSignedAttestation(t, "session-forged-crypto", "Bash", "tu-crypto-1", "allow")
	// Replace sig bytes with junk (still base64-valid, different length).
	env.Signatures[0].Sig = base64.StdEncoding.EncodeToString([]byte("wrong-signature-bytes"))

	attestDir := h.stateManager.AttestationsDir("session-forged-crypto")
	writeEnvelope(t, filepath.Join(attestDir, "Bash.intoto.json"), env)

	input := &aflock.HookInput{SessionID: "session-forged-crypto"}
	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse: %v (raw: %s)", err, got)
	}
	if out.Decision != "block" {
		t.Errorf("crypto-invalid envelope must NOT satisfy Stop gate, got decision=%q reason=%q", out.Decision, out.Reason)
	}
	if !strings.Contains(out.Reason, "missing attestations") {
		t.Errorf("reason should cite missing attestations, got %q", out.Reason)
	}
}

// TestHandleStop_RejectsCrossSessionReplay: a real, crypto-valid attestation
// signed for session A cannot satisfy session B's Stop gate. Guards against
// an attacker copying a neighbor session's attestations into the current
// session's dir.
func TestHandleStop_RejectsCrossSessionReplay(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "forgery-replay",
		Tools:                &aflock.ToolsPolicy{Allow: []string{"Bash"}},
		RequiredAttestations: []string{"Bash"},
	}
	// Session B is the target of the Stop gate. It used Bash but has no own
	// attestation.
	ssB := seedSession(t, h, "session-B", pol)
	ssB.Actions = append(ssB.Actions, aflock.ActionRecord{
		Timestamp: time.Now(), ToolName: "Bash", ToolUseID: "tu-B", Decision: "allow",
	})
	if err := h.stateManager.Save(ssB); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Produce a valid attestation signed under session A and drop it in B's dir.
	envA := newSignedAttestation(t, "session-A-different", "Bash", "tu-A", "allow")
	attestDirB := h.stateManager.AttestationsDir("session-B")
	writeEnvelope(t, filepath.Join(attestDirB, "Bash.intoto.json"), envA)

	input := &aflock.HookInput{SessionID: "session-B"}
	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse: %v (raw: %s)", err, got)
	}
	if out.Decision != "block" {
		t.Errorf("cross-session replay must NOT satisfy Stop gate, got decision=%q", out.Decision)
	}
}

// TestHandleStop_AcceptsLegitimateAttestation: sanity — a real, crypto-valid
// attestation signed for THIS session, THIS tool, THIS toolUseID must pass.
func TestHandleStop_AcceptsLegitimateAttestation(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:                 "legit",
		Tools:                &aflock.ToolsPolicy{Allow: []string{"Bash"}},
		RequiredAttestations: []string{"Bash"},
	}
	ss := seedSession(t, h, "session-legit", pol)
	ss.Actions = append(ss.Actions, aflock.ActionRecord{
		Timestamp: time.Now(), ToolName: "Bash", ToolUseID: "tu-legit", Decision: "allow",
	})
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}

	env := newSignedAttestation(t, "session-legit", "Bash", "tu-legit", "allow")
	attestDir := h.stateManager.AttestationsDir("session-legit")
	writeEnvelope(t, filepath.Join(attestDir, "Bash.intoto.json"), env)

	input := &aflock.HookInput{SessionID: "session-legit"}
	got := captureStdout(t, func() {
		if err := h.handleStop(input); err != nil {
			t.Fatalf("handleStop: %v", err)
		}
	})

	var out aflock.HookOutput
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("parse: %v (raw: %s)", err, got)
	}
	if out.Decision == "block" {
		t.Errorf("legitimate attestation must satisfy Stop gate, got block: %s", out.Reason)
	}
}

// TestValidateAttestationIntegrity_RejectsMinimalForgery targets the L1
// helper directly.
func TestValidateAttestationIntegrity_RejectsMinimalForgery(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		content string
	}{
		{"empty sig", `{"payload":"` + base64.StdEncoding.EncodeToString([]byte(`{"_type":"t","subject":[{"name":"s"}]}`)) + `","payloadType":"application/vnd.in-toto+json","signatures":[{"keyid":"k","sig":""}]}`},
		{"empty keyid", `{"payload":"` + base64.StdEncoding.EncodeToString([]byte(`{"_type":"t","subject":[{"name":"s"}]}`)) + `","payloadType":"application/vnd.in-toto+json","signatures":[{"keyid":"","sig":"` + base64.StdEncoding.EncodeToString([]byte("x")) + `"}]}`},
		{"unparseable sig base64", `{"payload":"` + base64.StdEncoding.EncodeToString([]byte(`{"_type":"t","subject":[{"name":"s"}]}`)) + `","payloadType":"application/vnd.in-toto+json","signatures":[{"keyid":"k","sig":"not-valid-base64!!"}]}`},
		{"wrong payloadType", `{"payload":"` + base64.StdEncoding.EncodeToString([]byte(`{"_type":"t","subject":[{"name":"s"}]}`)) + `","payloadType":"text/plain","signatures":[{"keyid":"k","sig":"` + base64.StdEncoding.EncodeToString([]byte("x")) + `"}]}`},
		{"unparseable payload base64", `{"payload":"not-valid-base64!!","payloadType":"application/vnd.in-toto+json","signatures":[{"keyid":"k","sig":"` + base64.StdEncoding.EncodeToString([]byte("x")) + `"}]}`},
		{"payload missing subject", `{"payload":"` + base64.StdEncoding.EncodeToString([]byte(`{"_type":"t","subject":[]}`)) + `","payloadType":"application/vnd.in-toto+json","signatures":[{"keyid":"k","sig":"` + base64.StdEncoding.EncodeToString([]byte("x")) + `"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".json")
			if err := os.WriteFile(p, []byte(tc.content), 0600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if validateAttestationIntegrity(p) {
				t.Error("integrity check should reject this variant")
			}
		})
	}
}
