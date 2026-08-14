package usage

import (
	"path/filepath"
	"testing"
)

func TestScanFile_SampleDedupAndFilter(t *testing.T) {
	path := filepath.Join("testdata", "sample.jsonl")
	got, err := ScanFile(path, "sess-abc")
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}

	// req_001/msg_001 appears twice; last write wins → output_tokens 120
	// req_002/msg_002 contributes once with the 5m/1h breakdown.
	// other-sess row is filtered out.
	if got.Turns != 2 {
		t.Errorf("turns = %d, want 2", got.Turns)
	}
	wantIn := int64(100 + 40)
	if got.InputTokens != wantIn {
		t.Errorf("inputTokens = %d, want %d", got.InputTokens, wantIn)
	}
	wantOut := int64(120 + 80)
	if got.OutputTokens != wantOut {
		t.Errorf("outputTokens = %d, want %d", got.OutputTokens, wantOut)
	}
	// opus 5m = 200 (fallback), sonnet 5m = 300 (explicit)
	if got.CacheCreate5mTokens != 500 {
		t.Errorf("cache5m = %d, want 500", got.CacheCreate5mTokens)
	}
	if got.CacheCreate1hTokens != 150 {
		t.Errorf("cache1h = %d, want 150", got.CacheCreate1hTokens)
	}
	if got.CacheReadTokens != 15 {
		t.Errorf("cacheRead = %d, want 15", got.CacheReadTokens)
	}
	if _, ok := got.PerModel["claude-opus-4-7"]; !ok {
		t.Errorf("expected per-model entry for opus")
	}
	if _, ok := got.PerModel["claude-sonnet-4-6"]; !ok {
		t.Errorf("expected per-model entry for sonnet")
	}
	if _, ok := got.PerModel["claude-haiku-4-5"]; ok {
		t.Errorf("did not expect per-model entry for other-sess haiku row")
	}
}

func TestScanFile_NoSessionIDAcceptsAll(t *testing.T) {
	path := filepath.Join("testdata", "sample.jsonl")
	got, err := ScanFile(path, "")
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	// 3 unique (msg,req) pairs: req_001/msg_001 (dedup), req_002/msg_002, req_900/msg_900
	if got.Turns != 3 {
		t.Errorf("turns = %d, want 3", got.Turns)
	}
}

func TestScanFile_MissingFile(t *testing.T) {
	_, err := ScanFile("testdata/does-not-exist.jsonl", "")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
