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
	//   jq -s 'map(select(.type=="assistant" and .message.usage)) |
	//          group_by(.message.id) | map(.[0]) | ... '
	// The fixture contains 2 JSONL lines with the SAME message.id and
	// identical usage blocks (the duplicate-emission pattern claude-code
	// produces during tool-use chains). Dedup yields 1 turn, not 2 —
	// see issue #96 / Bug 1.
	want := Cumulative{
		InputTokens:              6,
		OutputTokens:             171,
		CacheReadInputTokens:     11595,
		CacheCreationInputTokens: 8791,
		CacheCreation5mTokens:    0,
		CacheCreation1hTokens:    8791,
		AssistantTurns:           1,
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

// TestTracker_DedupesByMessageIDAndRequestID verifies that when claude-code
// writes the same assistant message twice (tool-use chain re-emission), we
// only count its usage once. Dedup key is (message.id, requestId) — both
// required, mirroring CodexBar's CostUsageScanner+Claude.swift dedup.
// Closes Bug 1 documented in #96.
func TestTracker_DedupesByMessageIDAndRequestID(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "s.jsonl")
	// Same (message.id, requestId), identical usage — should count exactly once.
	dup := `{"type":"assistant","requestId":"req_X","message":{"id":"msg_dupe1","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":10,"output_tokens":20,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}}` + "\n"
	if err := os.WriteFile(jsonl, []byte(dup+dup+dup), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := NewTracker(jsonl, tmp)
	d, _ := tr.ReadDelta()
	if d.AssistantTurns != 1 {
		t.Errorf("expected 1 turn after dedup, got %d", d.AssistantTurns)
	}
	if d.InputTokens != 10 || d.OutputTokens != 20 {
		t.Errorf("expected single-message tokens, got input=%d output=%d", d.InputTokens, d.OutputTokens)
	}
}

// TestTracker_LastChunkWins is the central regression for the bug that
// caused PR #97 to be reverted: when streaming assistant chunks share
// (message.id, requestId) and each chunk's usage is CUMULATIVE (not
// incremental), summing them double/triple-counts. CodexBar handles this
// by overwriting the row with each new chunk so the final cumulative
// snapshot wins. We assert the same here.
func TestTracker_LastChunkWins(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "s.jsonl")
	// Three streamed chunks of the same turn — usage grows monotonically.
	chunk1 := `{"type":"assistant","requestId":"req_S","message":{"id":"msg_stream","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":100,"output_tokens":10,"cache_read_input_tokens":50,"cache_creation_input_tokens":200}}}` + "\n"
	chunk2 := `{"type":"assistant","requestId":"req_S","message":{"id":"msg_stream","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":100,"output_tokens":50,"cache_read_input_tokens":50,"cache_creation_input_tokens":200}}}` + "\n"
	chunk3 := `{"type":"assistant","requestId":"req_S","message":{"id":"msg_stream","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":100,"output_tokens":120,"cache_read_input_tokens":50,"cache_creation_input_tokens":200}}}` + "\n"
	if err := os.WriteFile(jsonl, []byte(chunk1+chunk2+chunk3), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := NewTracker(jsonl, tmp)
	d, _ := tr.ReadDelta()
	if d.AssistantTurns != 1 {
		t.Errorf("three chunks of one turn should resolve to 1 turn, got %d", d.AssistantTurns)
	}
	if d.OutputTokens != 120 {
		t.Errorf("last-chunk output should win (120), got %d", d.OutputTokens)
	}
	if d.InputTokens != 100 {
		t.Errorf("input should stay at the cumulative 100, got %d", d.InputTokens)
	}
}

// TestTracker_DistinctIDsCounted ensures we don't accidentally
// over-aggressively dedupe — distinct (message.id, requestId) pairs
// must each count.
func TestTracker_DistinctIDsCounted(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "s.jsonl")
	a := `{"type":"assistant","requestId":"req_A","message":{"id":"msg_A","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":1,"output_tokens":2}}}` + "\n"
	b := `{"type":"assistant","requestId":"req_B","message":{"id":"msg_B","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":3,"output_tokens":4}}}` + "\n"
	if err := os.WriteFile(jsonl, []byte(a+b+a), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := NewTracker(jsonl, tmp)
	d, _ := tr.ReadDelta()
	if d.AssistantTurns != 2 {
		t.Errorf("expected 2 turns (A and B, A's dup overwritten), got %d", d.AssistantTurns)
	}
	if d.InputTokens != 4 || d.OutputTokens != 6 {
		t.Errorf("expected sums of A+B only, got input=%d output=%d", d.InputTokens, d.OutputTokens)
	}
}

// TestTracker_SameMessageIDDifferentRequestID guards against an over-
// aggressive dedup that keys only on message.id. Two requests producing
// rows that happen to share a message.id must both be counted — the
// compound key (message.id, requestId) prevents the collision.
func TestTracker_SameMessageIDDifferentRequestID(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "s.jsonl")
	r1 := `{"type":"assistant","requestId":"req_one","message":{"id":"msg_shared","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":5,"output_tokens":7}}}` + "\n"
	r2 := `{"type":"assistant","requestId":"req_two","message":{"id":"msg_shared","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":11,"output_tokens":13}}}` + "\n"
	if err := os.WriteFile(jsonl, []byte(r1+r2), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := NewTracker(jsonl, tmp)
	d, _ := tr.ReadDelta()
	if d.AssistantTurns != 2 {
		t.Errorf("expected 2 turns (different requestId), got %d", d.AssistantTurns)
	}
	if d.InputTokens != 16 || d.OutputTokens != 20 {
		t.Errorf("expected sum of both rows, got input=%d output=%d", d.InputTokens, d.OutputTokens)
	}
}

// TestTracker_StreamingChunksAcrossReadDelta exercises the case where
// streamed cumulative chunks land across two ReadDelta calls. The delta
// returned by the second call must reflect the GROWTH of the row's
// cumulative usage, not a fresh additive contribution. Without this,
// callers folding deltas into session metrics would double-count.
func TestTracker_StreamingChunksAcrossReadDelta(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "s.jsonl")

	chunk1 := `{"type":"assistant","requestId":"req_R","message":{"id":"msg_R","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":50,"output_tokens":10}}}` + "\n"
	if err := os.WriteFile(jsonl, []byte(chunk1), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := NewTracker(jsonl, tmp)
	d1, _ := tr.ReadDelta()
	if d1.OutputTokens != 10 || d1.AssistantTurns != 1 {
		t.Fatalf("first read: expected 10 output / 1 turn, got %+v", d1)
	}

	chunk2 := `{"type":"assistant","requestId":"req_R","message":{"id":"msg_R","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":50,"output_tokens":80}}}` + "\n"
	f, err := os.OpenFile(jsonl, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(chunk2); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	d2, _ := tr.ReadDelta()
	// Delta must reflect just the growth (80 - 10 = 70 output tokens).
	if d2.OutputTokens != 70 {
		t.Errorf("second read should report growth only (70), got %d", d2.OutputTokens)
	}
	// Turn count is unchanged — same row, just an updated snapshot.
	if d2.AssistantTurns != 0 {
		t.Errorf("second read should not add a turn (same row), got %d", d2.AssistantTurns)
	}
	// Cumulative reflects the final state.
	cum := tr.Cumulative()
	if cum.OutputTokens != 80 || cum.AssistantTurns != 1 {
		t.Errorf("cumulative after streaming: expected 80/1, got %+v", cum)
	}
}

// TestTracker_CacheTiersBrokenOut verifies that cache_creation.ephemeral_5m
// and ephemeral_1h are extracted into the per-tier fields. Closes Bug 3
// documented in #96.
func TestTracker_CacheTiersBrokenOut(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "s.jsonl")
	line := `{"type":"assistant","message":{"id":"msg_T","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":0,"output_tokens":0,"cache_creation_input_tokens":1500,"cache_creation":{"ephemeral_5m_input_tokens":500,"ephemeral_1h_input_tokens":1000}}}}` + "\n"
	if err := os.WriteFile(jsonl, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := NewTracker(jsonl, tmp)
	d, _ := tr.ReadDelta()
	if d.CacheCreation5mTokens != 500 {
		t.Errorf("expected 5m tokens=500, got %d", d.CacheCreation5mTokens)
	}
	if d.CacheCreation1hTokens != 1000 {
		t.Errorf("expected 1h tokens=1000, got %d", d.CacheCreation1hTokens)
	}
	if d.CacheCreationInputTokens != 1500 {
		t.Errorf("expected scalar (back-compat) cc=1500, got %d", d.CacheCreationInputTokens)
	}
}

// TestTracker_CacheTiersFallback verifies that older JSONLs without the
// cache_creation breakdown still credit the scalar to the 5m bucket
// (Anthropic's pre-1h-tier default).
func TestTracker_CacheTiersFallback(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "s.jsonl")
	line := `{"type":"assistant","message":{"id":"msg_F","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":0,"output_tokens":0,"cache_creation_input_tokens":2500}}}` + "\n"
	if err := os.WriteFile(jsonl, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := NewTracker(jsonl, tmp)
	d, _ := tr.ReadDelta()
	if d.CacheCreation5mTokens != 2500 {
		t.Errorf("scalar fallback should credit 5m bucket, got 5m=%d", d.CacheCreation5mTokens)
	}
	if d.CacheCreation1hTokens != 0 {
		t.Errorf("expected 1h bucket=0 in fallback path, got %d", d.CacheCreation1hTokens)
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
