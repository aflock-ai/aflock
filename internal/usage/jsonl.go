// Package usage parses Claude Code's session JSONL transcripts to recover
// per-session token usage and assistant-turn counts that the MCP transport
// itself does not carry. Closes issue #96.
//
// Claude Code writes a JSONL at ~/.claude/projects/<encoded-cwd>/<session-uuid>.jsonl
// with one line per session event. Assistant messages include a `message.usage`
// block with input/output/cache_* token counts taken straight from the
// underlying Anthropic API response. This package provides:
//
//   - Tracker: incremental reader with byte-offset memoization, so each
//     ReadDelta call only sees new bytes since the previous call. The offset
//     is persisted to a sidecar so aflock restarts don't double-count.
//
//   - Cumulative: the per-session running totals.
//
// Dedup follows CodexBar's approach (steipete/CodexBar — Sources/CodexBarCore/
// Vendored/CostUsage/CostUsageScanner+Claude.swift): assistant rows are keyed
// by (message.id, requestId) and stored as a map with overwrite semantics, so
// the final cumulative chunk of a streamed turn wins. Rows missing either ID
// are kept as separate entries to avoid dropping usage. This is more robust
// than the original skip-first-on-message.id-only dedup, which under-counts
// when Claude Code emits the SAME (message.id, requestId) pair with growing
// cumulative usage across a tool-use chain.
//
// Pricing/cost calculation lives in pricing.go.
package usage

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Cumulative captures per-session usage totals.
// Cache tokens are tracked separately so pricing can apply distinct
// multipliers (cache reads ~0.10x; cache writes split by tier:
// 5-minute ephemeral ~1.25x, 1-hour ephemeral ~2.00x).
type Cumulative struct {
	InputTokens              int64  `json:"input_tokens"`
	OutputTokens             int64  `json:"output_tokens"`
	CacheReadInputTokens     int64  `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64  `json:"cache_creation_input_tokens"` // sum of 5m + 1h, kept for back-compat
	CacheCreation5mTokens    int64  `json:"cache_creation_5m_input_tokens"`
	CacheCreation1hTokens    int64  `json:"cache_creation_1h_input_tokens"`
	AssistantTurns           int    `json:"assistant_turns"`
	Model                    string `json:"model"` // last seen, for pricing lookup
}

// Add accumulates other into c. Used to fold a delta into a running total.
func (c *Cumulative) Add(other Cumulative) {
	c.InputTokens += other.InputTokens
	c.OutputTokens += other.OutputTokens
	c.CacheReadInputTokens += other.CacheReadInputTokens
	c.CacheCreationInputTokens += other.CacheCreationInputTokens
	c.CacheCreation5mTokens += other.CacheCreation5mTokens
	c.CacheCreation1hTokens += other.CacheCreation1hTokens
	c.AssistantTurns += other.AssistantTurns
	if other.Model != "" {
		c.Model = other.Model
	}
}

// sub returns the per-field difference (c - other). Negative results are
// clamped to zero — cumulative usage from Anthropic is monotonic per
// (message.id, requestId) chunk in practice, but we never want to hand a
// negative delta to UpdateMetrics if a row gets overwritten with a smaller
// snapshot due to Claude Code internals or test fixtures.
func (c Cumulative) sub(other Cumulative) Cumulative {
	clamp := func(a, b int64) int64 {
		if a < b {
			return 0
		}
		return a - b
	}
	clampInt := func(a, b int) int {
		if a < b {
			return 0
		}
		return a - b
	}
	return Cumulative{
		InputTokens:              clamp(c.InputTokens, other.InputTokens),
		OutputTokens:             clamp(c.OutputTokens, other.OutputTokens),
		CacheReadInputTokens:     clamp(c.CacheReadInputTokens, other.CacheReadInputTokens),
		CacheCreationInputTokens: clamp(c.CacheCreationInputTokens, other.CacheCreationInputTokens),
		CacheCreation5mTokens:    clamp(c.CacheCreation5mTokens, other.CacheCreation5mTokens),
		CacheCreation1hTokens:    clamp(c.CacheCreation1hTokens, other.CacheCreation1hTokens),
		AssistantTurns:           clampInt(c.AssistantTurns, other.AssistantTurns),
		Model:                    c.Model,
	}
}

// assistantRow is a deduplicated record of one assistant turn. Multiple
// JSONL lines can share (messageID, requestID) — the row stores the LAST
// occurrence's usage values so cumulative-chunk streaming converges to the
// final count.
type assistantRow struct {
	messageID    string
	requestID    string
	isSidechain  bool
	inputTokens  int64
	outputTokens int64
	cacheRead    int64
	cache5m      int64
	cache1h      int64
	cacheTotal   int64 // top-level cache_creation_input_tokens (5m + 1h)
	model        string
}

func (r assistantRow) toCumulative() Cumulative {
	return Cumulative{
		InputTokens:              r.inputTokens,
		OutputTokens:             r.outputTokens,
		CacheReadInputTokens:     r.cacheRead,
		CacheCreationInputTokens: r.cacheTotal,
		CacheCreation5mTokens:    r.cache5m,
		CacheCreation1hTokens:    r.cache1h,
		AssistantTurns:           1,
		Model:                    r.model,
	}
}

// Tracker reads a Claude Code JSONL incrementally.
// Each ReadDelta processes only new bytes since the previous call.
// Safe for concurrent ReadDelta calls — internal mutex serializes them.
type Tracker struct {
	jsonlPath  string
	offsetPath string // sidecar at <sessionDir>/usage.offset
	mu         sync.Mutex
	offset     int64
	// total is the running cumulative computed across all deduped rows.
	// It's the source of truth for what ReadDelta returns: each call diffs
	// the post-merge total against this snapshot and returns the difference.
	total Cumulative
	// rowsByKey holds assistant rows keyed by "messageID:requestID". Repeat
	// occurrences of the same key overwrite the previous entry — the last
	// cumulative chunk of a streamed turn wins (CodexBar parity).
	rowsByKey map[string]assistantRow
	// unkeyedRows holds rows missing either messageID or requestID. They
	// cannot be safely deduplicated so each is kept as a separate entry.
	unkeyedRows []assistantRow
}

// NewTracker constructs a Tracker for jsonlPath. If sessionDir is non-empty,
// the offset is persisted to <sessionDir>/usage.offset so aflock restarts
// recover their position. If sessionDir is empty, the offset is in-memory
// only (acceptable for tests; production should always pass sessionDir).
//
// If a sidecar offset exists, it is loaded; missing or corrupt sidecars
// reset to offset 0 (safe — at worst we recompute cumulative from scratch).
func NewTracker(jsonlPath, sessionDir string) *Tracker {
	t := &Tracker{
		jsonlPath: jsonlPath,
		rowsByKey: make(map[string]assistantRow),
	}
	if sessionDir != "" {
		t.offsetPath = filepath.Join(sessionDir, "usage.offset")
		t.loadOffset()
	}
	return t
}

func (t *Tracker) loadOffset() {
	if t.offsetPath == "" {
		return
	}
	data, err := os.ReadFile(t.offsetPath) //nolint:gosec // G304: path is constructed from session dir
	if err != nil {
		return
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || n < 0 {
		return
	}
	t.offset = n
}

func (t *Tracker) saveOffset() {
	if t.offsetPath == "" {
		return
	}
	// Write best-effort. Failure is non-fatal — at worst we re-process
	// already-consumed lines on restart, which is correct (just wasteful).
	_ = os.WriteFile(t.offsetPath, []byte(strconv.FormatInt(t.offset, 10)), 0o600)
}

// ReadDelta opens the JSONL, seeks to the memoized offset, reads up to the
// last newline, merges new assistant rows into the deduped collection, and
// returns the cumulative-total delta covered by the merge. Updates the
// internal offset and persists it.
//
// Bytes after the last newline are NOT consumed — they may be partial
// writes from claude that have not finished flushing. They will be
// picked up on the next ReadDelta call.
//
// Returns zero Cumulative + nil error when:
//   - the JSONL doesn't exist (claude isn't active or hasn't started yet)
//   - no new content since the last call
//   - new bytes exist but contain no newline yet (whole partial line)
//   - new bytes contain only overwrites of already-seen rows with no growth
func (t *Tracker) ReadDelta() (Cumulative, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	f, err := os.Open(t.jsonlPath) //nolint:gosec // G304: path captured at construction
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Cumulative{}, nil
		}
		return Cumulative{}, fmt.Errorf("open jsonl: %w", err)
	}
	defer func() { _ = f.Close() }()

	if t.offset > 0 {
		// Validate offset is within file bounds — file may have been
		// truncated/replaced. If so, reset state and re-read from start.
		if fi, err := f.Stat(); err == nil && fi.Size() < t.offset {
			t.offset = 0
			t.total = Cumulative{}
			t.rowsByKey = make(map[string]assistantRow)
			t.unkeyedRows = nil
		}
		if t.offset > 0 {
			if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
				return Cumulative{}, fmt.Errorf("seek to offset %d: %w", t.offset, err)
			}
		}
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return Cumulative{}, fmt.Errorf("read jsonl: %w", err)
	}
	if len(data) == 0 {
		return Cumulative{}, nil
	}

	lastNL := bytes.LastIndexByte(data, '\n')
	if lastNL < 0 {
		// Whole tail is a partial line — defer until newline arrives
		return Cumulative{}, nil
	}
	consumed := data[:lastNL+1]

	before := t.total
	newRows := parseRows(consumed)
	t.mergeRows(newRows)
	t.total = t.computeTotal()
	t.offset += int64(len(consumed))
	t.saveOffset()

	return t.total.sub(before), nil
}

// mergeRows folds parsed rows into the dedup collections. Keyed rows
// (with both messageID and requestID) overwrite by composite key — the
// last occurrence wins, matching CodexBar's streaming-chunk semantics.
// Unkeyed rows are appended as distinct entries.
func (t *Tracker) mergeRows(rows []assistantRow) {
	for _, r := range rows {
		if r.messageID != "" && r.requestID != "" {
			t.rowsByKey[r.messageID+":"+r.requestID] = r
		} else {
			t.unkeyedRows = append(t.unkeyedRows, r)
		}
	}
}

// computeTotal recomputes the cumulative from scratch by summing all
// deduped rows. Cheap relative to ReadDelta's I/O — the row count grows
// linearly with assistant turns, not bytes.
func (t *Tracker) computeTotal() Cumulative {
	var c Cumulative
	for _, r := range t.rowsByKey {
		c.Add(r.toCumulative())
	}
	for _, r := range t.unkeyedRows {
		c.Add(r.toCumulative())
	}
	return c
}

// Cumulative returns the current running totals (snapshot).
func (t *Tracker) Cumulative() Cumulative {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total
}

// JSONLPath returns the underlying JSONL path. Useful for diagnostics.
func (t *Tracker) JSONLPath() string {
	return t.jsonlPath
}

// parseRows walks each newline-terminated line and emits one assistantRow
// per qualifying assistant message. Corrupt or incomplete lines are skipped
// silently (claude can write mid-flush). Non-assistant types are ignored.
func parseRows(b []byte) []assistantRow {
	var rows []assistantRow
	scanner := bufio.NewScanner(bytes.NewReader(b))
	// Claude messages can be long (full prompts + responses) — give the
	// scanner enough buffer to handle them.
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		entry := jsonlEntry{}
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if entry.Type != "assistant" {
			continue
		}
		if entry.Message == nil || entry.Message.Usage == nil {
			continue
		}
		row := assistantRow{
			messageID:    entry.Message.ID,
			requestID:    entry.RequestID,
			isSidechain:  entry.IsSidechain,
			inputTokens:  entry.Message.Usage.InputTokens,
			outputTokens: entry.Message.Usage.OutputTokens,
			cacheRead:    entry.Message.Usage.CacheReadInputTokens,
			cacheTotal:   entry.Message.Usage.CacheCreationInputTokens,
			model:        entry.Message.Model,
		}
		// Anthropic prompt caching has two write tiers with different
		// pricing. The top-level cache_creation_input_tokens equals
		// 5m + 1h combined; we read the breakdown so pricing can apply
		// the correct multiplier (5m: 1.25x, 1h: 2.0x).
		if entry.Message.Usage.CacheCreation != nil {
			row.cache5m = entry.Message.Usage.CacheCreation.Ephemeral5mInputTokens
			row.cache1h = entry.Message.Usage.CacheCreation.Ephemeral1hInputTokens
		} else {
			// Older sessions or single-tier responses fall back to the
			// scalar field, treated as 5m (Anthropic's pre-1h-tier default).
			row.cache5m = entry.Message.Usage.CacheCreationInputTokens
		}
		rows = append(rows, row)
	}
	return rows
}

// jsonlEntry models the subset of fields we read. Other fields in the
// JSONL (subagent stops, attachments, etc.) are ignored by the standard
// library JSON decoder.
type jsonlEntry struct {
	Type        string    `json:"type"`
	IsSidechain bool      `json:"isSidechain"`
	RequestID   string    `json:"requestId"`
	Message     *jsonlMsg `json:"message,omitempty"`
}

type jsonlMsg struct {
	ID    string      `json:"id"`
	Role  string      `json:"role"`
	Model string      `json:"model"`
	Usage *jsonlUsage `json:"usage,omitempty"`
}

type jsonlUsage struct {
	InputTokens              int64               `json:"input_tokens"`
	OutputTokens             int64               `json:"output_tokens"`
	CacheReadInputTokens     int64               `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64               `json:"cache_creation_input_tokens"`
	CacheCreation            *jsonlCacheCreation `json:"cache_creation,omitempty"`
}

// jsonlCacheCreation breaks the cache_creation_input_tokens scalar into
// the 5-minute and 1-hour ephemeral tiers Anthropic prices distinctly.
type jsonlCacheCreation struct {
	Ephemeral5mInputTokens int64 `json:"ephemeral_5m_input_tokens"`
	Ephemeral1hInputTokens int64 `json:"ephemeral_1h_input_tokens"`
}
