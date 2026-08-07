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

// Issue #26 gap 1 — attestation predicates produced by a child session that
// was bound to a parent's declared sublayout must carry the matched
// SublayoutBinding (name + prefix + parent session id). Audit/verify tools
// can then group child attestations under the declared slot.

func TestPostToolUse_StampsSublayoutBindingFromSession(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:    "issue-26-prefix-child",
		Version: "1.0",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Read"}},
	}
	ss := seedSession(t, h, "child-with-sublayout", pol)
	// Simulate the propagation having bound this child to a parent's
	// declared sublayout. Real SessionStart fills these from the
	// propagation record (issue #26).
	ss.ParentSessionID = "parent-xyz"
	ss.ParentSublayoutName = "research"
	ss.AttestationPrefix = "sub/research/"
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}

	input := &aflock.HookInput{
		SessionID: "child-with-sublayout",
		ToolName:  "Read",
		ToolUseID: "tu-prefix-1",
		ToolInput: json.RawMessage(`{"file_path":"src/main.go"}`),
	}
	captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	// Read the produced attestation and check the predicate.
	attestDir := h.stateManager.AttestationsDir("child-with-sublayout")
	entries, err := os.ReadDir(attestDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("expected attestation file, err=%v entries=%d", err, len(entries))
	}

	data, err := os.ReadFile(filepath.Join(attestDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	var env attestation.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var stmt struct {
		Predicate attestation.ActionPredicate `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatalf("parse statement: %v", err)
	}

	if stmt.Predicate.SublayoutBinding == nil {
		t.Fatal("expected SublayoutBinding in predicate, got nil")
	}
	if got := stmt.Predicate.SublayoutBinding.Name; got != "research" {
		t.Errorf("SublayoutBinding.Name = %q, want %q", got, "research")
	}
	if got := stmt.Predicate.SublayoutBinding.Prefix; got != "sub/research/" {
		t.Errorf("SublayoutBinding.Prefix = %q, want %q", got, "sub/research/")
	}
	if got := stmt.Predicate.SublayoutBinding.ParentSessionID; got != "parent-xyz" {
		t.Errorf("SublayoutBinding.ParentSessionID = %q, want %q", got, "parent-xyz")
	}
}

func TestPostToolUse_NoSublayoutBindingWhenUnbound(t *testing.T) {
	h := newTestHandler(t)
	pol := &aflock.Policy{
		Name:    "issue-26-prefix-unbound",
		Version: "1.0",
		Tools:   &aflock.ToolsPolicy{Allow: []string{"Read"}},
	}
	ss := seedSession(t, h, "unbound-child", pol)
	// Deliberately do NOT set ParentSublayoutName — this is a legacy /
	// no-sublayout session and must not get a spurious binding.
	if ss.ParentSublayoutName != "" {
		t.Fatalf("test precondition broken: ParentSublayoutName already set")
	}
	if err := h.stateManager.Save(ss); err != nil {
		t.Fatalf("save: %v", err)
	}

	input := &aflock.HookInput{
		SessionID: "unbound-child",
		ToolName:  "Read",
		ToolUseID: "tu-no-prefix",
		ToolInput: json.RawMessage(`{"file_path":"x"}`),
	}
	captureStdout(t, func() {
		if err := h.handlePostToolUse(input); err != nil {
			t.Fatalf("handlePostToolUse: %v", err)
		}
	})

	attestDir := h.stateManager.AttestationsDir("unbound-child")
	entries, _ := os.ReadDir(attestDir)
	if len(entries) == 0 {
		t.Fatal("expected attestation file")
	}
	data, _ := os.ReadFile(filepath.Join(attestDir, entries[0].Name()))
	var env attestation.Envelope
	_ = json.Unmarshal(data, &env)
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	var stmt struct {
		Predicate attestation.ActionPredicate `json:"predicate"`
	}
	_ = json.Unmarshal(payload, &stmt)
	if stmt.Predicate.SublayoutBinding != nil {
		t.Errorf("expected nil SublayoutBinding for unbound session, got %+v", stmt.Predicate.SublayoutBinding)
	}
}

// TestWritePropagation_CarriesAttestationPrefix verifies the
// parent-side: WritePropagationForSublayout stores the sublayout's
// AttestationPrefix so the child can pick it up at SessionStart.
func TestWritePropagation_CarriesAttestationPrefix(t *testing.T) {
	h := newTestHandler(t)
	parent := seedSession(t, h, "parent-prefix-write", &aflock.Policy{
		Name:    "parent",
		Version: "1.0",
	})
	parent.Metrics = &aflock.SessionMetrics{}
	if err := h.stateManager.Save(parent); err != nil {
		t.Fatalf("save: %v", err)
	}

	sub := &aflock.Sublayout{
		Name:              "research",
		AttestationPrefix: "sub/research/",
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD: &aflock.Limit{Value: 2.0},
		},
	}
	if err := h.stateManager.WritePropagationForSublayout(parent, sub); err != nil {
		t.Fatalf("WritePropagationForSublayout: %v", err)
	}

	rec, err := h.stateManager.ReadPropagation(parent.PolicyPath)
	if err != nil || rec == nil {
		t.Fatalf("ReadPropagation: rec=%v err=%v", rec, err)
	}
	if rec.AttestationPrefix != "sub/research/" {
		t.Errorf("AttestationPrefix = %q, want %q", rec.AttestationPrefix, "sub/research/")
	}
	if rec.SublayoutName != "research" {
		t.Errorf("SublayoutName = %q, want %q", rec.SublayoutName, "research")
	}
	// Silence unused imports kept for parity with the rest of the file.
	_ = strings.HasPrefix
	_ = time.Now
	_ = base64.StdEncoding
	_ = attestation.ActionPredicate{}
}
