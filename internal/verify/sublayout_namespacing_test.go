package verify

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeActionEnvelope drops a DSSE-shaped envelope into dir containing
// a predicate with the given sublayoutBinding. Returns the file path.
// binding may be nil to model an attestation that omits the field
// entirely (which the namespacing check must tolerate).
func writeActionEnvelope(t *testing.T, dir, fname string, binding map[string]any) string {
	t.Helper()
	pred := map[string]any{"toolName": "Read"}
	if binding != nil {
		pred["sublayoutBinding"] = binding
	}
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://aflock.ai/attestations/action/v0.1",
		"predicate":     pred,
		"subject":       []map[string]any{},
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	env := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures":  []map[string]string{{"keyid": "k", "sig": "c2ln"}},
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal env: %v", err)
	}
	p := filepath.Join(dir, fname)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// TestVerifySublayoutNamespacing_AllMatch is the happy path: every
// attestation's sublayoutBinding names this sublayout, so the check
// returns no messages.
func TestVerifySublayoutNamespacing_AllMatch(t *testing.T) {
	dir := t.TempDir()
	writeActionEnvelope(t, dir, "a.intoto.json", map[string]any{
		"name":   "research-agent",
		"prefix": "research/",
	})
	writeActionEnvelope(t, dir, "b.intoto.json", map[string]any{
		"name":   "research-agent",
		"prefix": "research/",
	})
	msgs := verifySublayoutNamespacing(dir, "research-agent", "research/")
	if len(msgs) != 0 {
		t.Errorf("expected no violations, got %v", msgs)
	}
}

// TestVerifySublayoutNamespacing_NameMismatch — the core failure
// mode the paper's Phase 6 filter catches: an attestation whose
// binding names a different sublayout slipped into this child's
// directory.
func TestVerifySublayoutNamespacing_NameMismatch(t *testing.T) {
	dir := t.TempDir()
	writeActionEnvelope(t, dir, "a.intoto.json", map[string]any{
		"name": "research-agent",
	})
	writeActionEnvelope(t, dir, "b.intoto.json", map[string]any{
		"name": "evil-agent", // mismatched
	})
	msgs := verifySublayoutNamespacing(dir, "research-agent", "")
	if len(msgs) != 1 {
		t.Fatalf("expected 1 violation, got %d: %v", len(msgs), msgs)
	}
	if !strings.Contains(msgs[0], "evil-agent") || !strings.Contains(msgs[0], "research-agent") {
		t.Errorf("expected violation to mention both names, got: %s", msgs[0])
	}
}

// TestVerifySublayoutNamespacing_PrefixMismatch — when the sublayout
// declares an AttestationPrefix, every binding must carry it too.
// An attestation with the right name but wrong prefix still fails.
func TestVerifySublayoutNamespacing_PrefixMismatch(t *testing.T) {
	dir := t.TempDir()
	writeActionEnvelope(t, dir, "a.intoto.json", map[string]any{
		"name":   "research-agent",
		"prefix": "wrong/",
	})
	msgs := verifySublayoutNamespacing(dir, "research-agent", "research/")
	if len(msgs) != 1 {
		t.Fatalf("expected 1 violation, got %d: %v", len(msgs), msgs)
	}
	if !strings.Contains(msgs[0], "prefix") {
		t.Errorf("violation must mention prefix, got: %s", msgs[0])
	}
}

// TestVerifySublayoutNamespacing_PrefixOptional — when the sublayout
// itself declares no AttestationPrefix, the check ignores binding
// prefixes entirely (only the name is enforced). Otherwise legacy
// policies that rely on name-based grouping would suddenly fail.
func TestVerifySublayoutNamespacing_PrefixOptional(t *testing.T) {
	dir := t.TempDir()
	writeActionEnvelope(t, dir, "a.intoto.json", map[string]any{
		"name":   "research-agent",
		"prefix": "anything-goes/",
	})
	msgs := verifySublayoutNamespacing(dir, "research-agent", "")
	if len(msgs) != 0 {
		t.Errorf("expected no violations when sublayout declares no prefix, got %v", msgs)
	}
}

// TestVerifySublayoutNamespacing_NoBindingSkipped — attestation types
// that don't stamp sublayoutBinding (e.g. step attestations) must not
// trigger a violation. Only attestations that DO claim a binding are
// validated.
func TestVerifySublayoutNamespacing_NoBindingSkipped(t *testing.T) {
	dir := t.TempDir()
	writeActionEnvelope(t, dir, "no-binding.intoto.json", nil)
	writeActionEnvelope(t, dir, "with-binding.intoto.json", map[string]any{
		"name": "research-agent",
	})
	msgs := verifySublayoutNamespacing(dir, "research-agent", "")
	if len(msgs) != 0 {
		t.Errorf("expected no violations, got %v", msgs)
	}
}

// TestVerifySublayoutNamespacing_EmptyDir — verifying an empty
// directory is a no-op, not an error. Avoids spurious failures for
// children that haven't recorded attestations yet.
func TestVerifySublayoutNamespacing_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	if msgs := verifySublayoutNamespacing(dir, "research-agent", "research/"); len(msgs) != 0 {
		t.Errorf("expected no violations for empty dir, got %v", msgs)
	}
}
