package usage

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTracker_RealFixture parses a fixture captured from a live Claude Code
// JSONL and asserts every aggregate matches what `jq` computed
// independently from the same file.
func TestTracker_RealFixture(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "session.jsonl")
	src, err := os.ReadFile("testdata/sample.jsonl")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(jsonl, src, 0o600); err != nil {
		t.Fatal(err)
	}

	tr := NewTracker(jsonl, tmp)
	delta, err := tr.ReadDelta()
	if err != nil {
		t.Fatalf("ReadDelta: %v", err)
	}

	// Values verified against the fixture via:
	//   jq -s 'map(select(.type=="assistant" and .message.usage) | .message.usage) | ...'
	want := Cumulative{
		InputTokens:              12,
		OutputTokens:             342,
		CacheReadInputTokens:     23190,
		CacheCreationInputTokens: 17582,
		AssistantTurns:           2,
		Model:                    "claude-opus-4-7",
	}
	if delta != want {
		t.Errorf("delta = %+v, want %+v", delta, want)
	}
	if cum := tr.Cumulative(); cum != want {
		t.Errorf("Cumulative() = %+v, want %+v", cum, want)
	}
}

// TestTracker_OffsetAdvance verifies that a second ReadDelta on an unchanged
// file returns zero — we should not double-count already-consumed lines.
func TestTracker_OffsetAdvance(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "s.jsonl")
	if err := os.WriteFile(jsonl, mustReadFixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := NewTracker(jsonl, tmp)

	first, _ := tr.ReadDelta()
	if first.AssistantTurns == 0 {
		t.Fatal("first read should produce non-zero delta")
	}
	second, _ := tr.ReadDelta()
	if second.AssistantTurns != 0 || second.InputTokens != 0 {
		t.Errorf("second read should be empty, got %+v", second)
	}
}

// TestTracker_PartialLineDefer ensures we don't consume bytes after the
// last \n until a newline arrives. Otherwise we'd double-count once the
// flush completes.
func TestTracker_PartialLineDefer(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "s.jsonl")

	// Write one complete assistant line + a partial line without trailing \n.
	complete := `{"type":"assistant","message":{"role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":100,"output_tokens":50,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}}` + "\n"
	partial := `{"type":"assistant","message":{"role":"assist`
	if err := os.WriteFile(jsonl, []byte(complete+partial), 0o600); err != nil {
		t.Fatal(err)
	}

	tr := NewTracker(jsonl, tmp)
	d, err := tr.ReadDelta()
	if err != nil {
		t.Fatalf("ReadDelta: %v", err)
	}
	if d.AssistantTurns != 1 || d.InputTokens != 100 {
		t.Errorf("first read should consume only the complete line, got %+v", d)
	}

	// Now finish the partial line and add another newline.
	tail := `ant","model":"claude-opus-4-7","usage":{"input_tokens":7,"output_tokens":3,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}}` + "\n"
	f, err := os.OpenFile(jsonl, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(tail); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	d2, _ := tr.ReadDelta()
	if d2.AssistantTurns != 1 || d2.InputTokens != 7 {
		t.Errorf("second read should consume previously-partial line, got %+v", d2)
	}
}

// TestTracker_MissingFile returns an empty delta with no error when claude
// hasn't started writing yet (or aflock is being run with a non-Claude MCP
// client).
func TestTracker_MissingFile(t *testing.T) {
	tr := NewTracker("/nonexistent/path/to/session.jsonl", "")
	d, err := tr.ReadDelta()
	if err != nil {
		t.Errorf("ReadDelta on missing file should be nil error, got %v", err)
	}
	if d != (Cumulative{}) {
		t.Errorf("expected zero Cumulative, got %+v", d)
	}
}

// TestTracker_SidecarPersistence verifies that creating a NEW Tracker after
// the first one persists picks up where the first left off — does not
// re-read already-consumed lines.
func TestTracker_SidecarPersistence(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "s.jsonl")
	if err := os.WriteFile(jsonl, mustReadFixture(t), 0o600); err != nil {
		t.Fatal(err)
	}

	t1 := NewTracker(jsonl, tmp)
	d1, _ := t1.ReadDelta()
	if d1.AssistantTurns == 0 {
		t.Fatal("first read should produce non-zero delta")
	}

	// Simulate restart: new Tracker, same sidecar dir.
	t2 := NewTracker(jsonl, tmp)
	d2, _ := t2.ReadDelta()
	if d2.AssistantTurns != 0 {
		t.Errorf("second tracker should pick up sidecar offset, got delta %+v", d2)
	}

	// Verify the offset file was written.
	if _, err := os.Stat(filepath.Join(tmp, "usage.offset")); err != nil {
		t.Errorf("usage.offset should exist: %v", err)
	}
}

// TestTracker_FileTruncated handles the case where the JSONL is replaced
// with a smaller file (e.g. claude restarts a session with the same id —
// rare but possible). Tracker should reset offset and re-read from start.
func TestTracker_FileTruncated(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "s.jsonl")
	big := mustReadFixture(t)
	if err := os.WriteFile(jsonl, big, 0o600); err != nil {
		t.Fatal(err)
	}

	tr := NewTracker(jsonl, tmp)
	if _, err := tr.ReadDelta(); err != nil {
		t.Fatal(err)
	}

	// Replace with a smaller file.
	short := []byte(`{"type":"assistant","message":{"role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":1,"output_tokens":1,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}}` + "\n")
	if err := os.WriteFile(jsonl, short, 0o600); err != nil {
		t.Fatal(err)
	}

	d, err := tr.ReadDelta()
	if err != nil {
		t.Fatal(err)
	}
	if d.AssistantTurns != 1 || d.InputTokens != 1 {
		t.Errorf("after truncation, expected one assistant line re-read, got %+v", d)
	}
}

// TestTracker_CorruptLine ensures malformed JSON lines are skipped without
// failing the whole read.
func TestTracker_CorruptLine(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "s.jsonl")
	content := `{"type":"assistant","message":{"role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":10,"output_tokens":5}}}` + "\n" +
		`{this is not json` + "\n" +
		`{"type":"assistant","message":{"role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":20,"output_tokens":15}}}` + "\n"
	if err := os.WriteFile(jsonl, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	tr := NewTracker(jsonl, tmp)
	d, _ := tr.ReadDelta()
	if d.AssistantTurns != 2 {
		t.Errorf("expected 2 valid assistant turns (corrupt line skipped), got %d", d.AssistantTurns)
	}
	if d.InputTokens != 30 {
		t.Errorf("expected 30 input tokens, got %d", d.InputTokens)
	}
}

// TestTracker_NonAssistantTypesIgnored verifies that user/system/etc.
// lines do not contribute to the cumulative.
func TestTracker_NonAssistantTypesIgnored(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "s.jsonl")
	content := `{"type":"user","message":{"role":"user","content":"hi"}}` + "\n" +
		`{"type":"system","subtype":"info"}` + "\n" +
		`{"type":"attachment","name":"file"}` + "\n" +
		`{"type":"assistant","message":{"role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":99,"output_tokens":1}}}` + "\n"
	if err := os.WriteFile(jsonl, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	tr := NewTracker(jsonl, tmp)
	d, _ := tr.ReadDelta()
	if d.AssistantTurns != 1 {
		t.Errorf("expected only 1 assistant turn, got %d", d.AssistantTurns)
	}
	if d.InputTokens != 99 {
		t.Errorf("expected only the assistant's tokens, got %d", d.InputTokens)
	}
}

func mustReadFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/sample.jsonl")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}
