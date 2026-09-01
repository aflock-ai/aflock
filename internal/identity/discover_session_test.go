package identity

import (
	"path/filepath"
	"testing"
	"time"
)

// Multi-Claude safety: DiscoverForSession must attribute the model from the
// hook's OWN transcript, never from whichever session file in the project
// was flushed most recently (the failure mode with concurrent instances).

func TestDiscoverForSession_ExactTranscriptBeatsNewerNeighbor(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // isolate any heuristic fallback
	tmp := t.TempDir()

	own := filepath.Join(tmp, "sess-own.jsonl")
	other := filepath.Join(tmp, "sess-other.jsonl")

	writeJSONLFile(t, own, []map[string]any{
		{"message": map[string]any{"model": "claude-opus-4-5-20251101"}},
	})
	// A concurrent session's transcript, flushed later — the old mtime
	// heuristic would have picked this one.
	time.Sleep(10 * time.Millisecond)
	writeJSONLFile(t, other, []map[string]any{
		{"message": map[string]any{"model": "claude-sonnet-4-20250514"}},
	})

	model, meta, err := DiscoverForSession("sess-own", own)
	if err != nil {
		t.Fatalf("DiscoverForSession: %v", err)
	}
	if model != "claude-opus-4-5-20251101" {
		t.Fatalf("model = %q, want the OWN transcript's model claude-opus-4-5-20251101", model)
	}
	if meta.SessionID != "sess-own" {
		t.Errorf("SessionID = %q, want sess-own", meta.SessionID)
	}
	if meta.SessionPath != own {
		t.Errorf("SessionPath = %q, want %q", meta.SessionPath, own)
	}
	if meta.DiscoveryMethod != DiscoveryMethodTranscript {
		t.Errorf("DiscoveryMethod = %q, want %q", meta.DiscoveryMethod, DiscoveryMethodTranscript)
	}
}

func TestDiscoverForSession_DerivesSessionIDFromFilename(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	tmp := t.TempDir()

	transcript := filepath.Join(tmp, "abc-123-def.jsonl")
	writeJSONLFile(t, transcript, []map[string]any{
		{"model": "claude-opus-4-5-20251101"},
	})

	_, meta, err := DiscoverForSession("", transcript)
	if err != nil {
		t.Fatalf("DiscoverForSession: %v", err)
	}
	if meta.SessionID != "abc-123-def" {
		t.Errorf("SessionID = %q, want abc-123-def (derived from filename)", meta.SessionID)
	}
}

func TestDiscoverForSession_NoModelYetDoesNotAdoptNeighborIdentity(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // heuristic fallback cannot find real ~/.claude
	tmp := t.TempDir()

	own := filepath.Join(tmp, "sess-own.jsonl")
	other := filepath.Join(tmp, "sess-other.jsonl")

	// Fresh session: transcript exists but has no assistant turn yet.
	writeJSONLFile(t, own, []map[string]any{
		{"type": "summary"},
	})
	time.Sleep(10 * time.Millisecond)
	writeJSONLFile(t, other, []map[string]any{
		{"message": map[string]any{"model": "claude-sonnet-4-20250514"}},
	})

	model, meta, err := DiscoverForSession("sess-own", own)

	// The fallback heuristic may or may not resolve a model depending on the
	// environment, but it must NEVER be marked exact, and it must keep the
	// hook's own session identity rather than adopting the neighbor's.
	if err == nil {
		if meta == nil {
			t.Fatal("nil meta with nil error")
		}
		if meta.DiscoveryMethod == DiscoveryMethodTranscript {
			t.Errorf("model-less transcript must not report exact transcript attribution (model=%q)", model)
		}
		if meta.SessionID != "sess-own" {
			t.Errorf("SessionID = %q, want sess-own (must not adopt neighbor's session)", meta.SessionID)
		}
		if meta.SessionPath != own {
			t.Errorf("SessionPath = %q, want %q", meta.SessionPath, own)
		}
	}
}

func TestDiscoverForSession_EmptyTranscriptPathFallsBack(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// No transcript supplied (older Claude Code, MCP mode): behaves like the
	// legacy heuristic — and must not panic or fabricate exact attribution.
	_, meta, err := DiscoverForSession("some-session", "")
	if err == nil && meta != nil && meta.DiscoveryMethod == DiscoveryMethodTranscript {
		t.Error("no transcript path must not yield transcript-exact attribution")
	}
}
