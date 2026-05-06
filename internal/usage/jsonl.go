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
//     ReadDelta call only sees new lines since the previous call. The offset
//     is persisted to a sidecar so aflock restarts don't double-count.
//
//   - Cumulative: the per-session running totals.
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

// Tracker reads a Claude Code JSONL incrementally.
// Each ReadDelta processes only new content since the previous call.
// Safe for concurrent ReadDelta calls — internal mutex serializes them.
type Tracker struct {
	jsonlPath  string
	offsetPath string // sidecar at <sessionDir>/usage.offset
	mu         sync.Mutex
	offset     int64
	cumulative Cumulative
	// seenIDs deduplicates assistant messages by message.id. Claude Code
	// emits the same assistant turn as multiple JSONL lines (different
	// parentUuid, identical message.id and identical usage block) when
	// the message participates in a tool-use chain. Counting both copies
	// double-counts tokens. Per-tracker in-memory only — duplicate IDs
	// are always co-located in the JSONL so a single tracker instance
	// catches them; we don't need cross-restart persistence.
	seenIDs map[string]struct{}
}

// NewTracker constructs a Tracker for jsonlPath. If sessionDir is non-empty,
// the offset is persisted to <sessionDir>/usage.offset so aflock restarts
// recover their position. If sessionDir is empty, the offset is in-memory
// only (acceptable for tests; production should always pass sessionDir).
//
// If a sidecar offset exists, it is loaded; missing or corrupt sidecars
// reset to offset 0 (safe — at worst we recompute cumulative from scratch).
func NewTracker(jsonlPath, sessionDir string) *Tracker {
	t := &Tracker{jsonlPath: jsonlPath, seenIDs: make(map[string]struct{})}
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
// last newline, and returns a Cumulative covering only the new content.
// Updates internal offset and cumulative, and persists the offset.
//
// Bytes after the last newline are NOT consumed — they may be partial
// writes from claude that have not finished flushing. They will be
// picked up on the next ReadDelta call.
//
// Returns zero Cumulative + nil error when:
//   - the JSONL doesn't exist (claude isn't active or hasn't started yet)
//   - no new content since the last call
//   - new bytes exist but contain no newline yet (whole partial line)
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
		// truncated/replaced. If so, reset and re-read from start.
		if fi, err := f.Stat(); err == nil && fi.Size() < t.offset {
			t.offset = 0
			t.cumulative = Cumulative{}
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

	delta := parseLines(consumed, t.seenIDs)

	t.offset += int64(len(consumed))
	t.saveOffset()
	t.cumulative.Add(delta)

	return delta, nil
}

// Cumulative returns the current running totals (snapshot).
func (t *Tracker) Cumulative() Cumulative {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cumulative
}

// JSONLPath returns the underlying JSONL path. Useful for diagnostics.
func (t *Tracker) JSONLPath() string {
	return t.jsonlPath
}

// parseLines walks each newline-terminated line and accumulates usage from
// assistant messages. Lines whose message.id is already in seen are
// skipped — Claude Code emits the same assistant turn multiple times
// when it participates in a tool-use chain, with identical usage blocks
// (see issue #96). Corrupt or incomplete lines are skipped silently
// (claude can write mid-flush, partial parses happen). Non-assistant
// types are ignored.
func parseLines(b []byte, seen map[string]struct{}) Cumulative {
	var c Cumulative
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
		// Dedupe by message.id. Empty IDs are treated as always-unique
		// (defensive — every real Anthropic API response has an id).
		if entry.Message.ID != "" {
			if _, dup := seen[entry.Message.ID]; dup {
				continue
			}
			seen[entry.Message.ID] = struct{}{}
		}
		c.InputTokens += entry.Message.Usage.InputTokens
		c.OutputTokens += entry.Message.Usage.OutputTokens
		c.CacheReadInputTokens += entry.Message.Usage.CacheReadInputTokens
		// Anthropic prompt caching has two write tiers with different
		// pricing. The top-level cache_creation_input_tokens equals
		// 5m + 1h combined; we read the breakdown so pricing can apply
		// the correct multiplier (5m: 1.25x, 1h: 2.0x).
		if entry.Message.Usage.CacheCreation != nil {
			c.CacheCreation5mTokens += entry.Message.Usage.CacheCreation.Ephemeral5mInputTokens
			c.CacheCreation1hTokens += entry.Message.Usage.CacheCreation.Ephemeral1hInputTokens
		} else {
			// Older sessions or single-tier responses fall back to the
			// scalar field, treated as 5m (Anthropic's pre-1h-tier default).
			c.CacheCreation5mTokens += entry.Message.Usage.CacheCreationInputTokens
		}
		c.CacheCreationInputTokens += entry.Message.Usage.CacheCreationInputTokens
		c.AssistantTurns++
		if entry.Message.Model != "" {
			c.Model = entry.Message.Model
		}
	}
	return c
}

// jsonlEntry models the subset of fields we read. Other fields in the
// JSONL (subagent stops, attachments, etc.) are ignored by the standard
// library JSON decoder.
type jsonlEntry struct {
	Type    string    `json:"type"`
	Message *jsonlMsg `json:"message,omitempty"`
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
