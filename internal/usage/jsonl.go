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
// multipliers (cache writes ~1.25x input, cache reads ~0.10x).
type Cumulative struct {
	InputTokens              int64  `json:"input_tokens"`
	OutputTokens             int64  `json:"output_tokens"`
	CacheReadInputTokens     int64  `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64  `json:"cache_creation_input_tokens"`
	AssistantTurns           int    `json:"assistant_turns"`
	Model                    string `json:"model"` // last seen, for pricing lookup
}

// Add accumulates other into c. Used to fold a delta into a running total.
func (c *Cumulative) Add(other Cumulative) {
	c.InputTokens += other.InputTokens
	c.OutputTokens += other.OutputTokens
	c.CacheReadInputTokens += other.CacheReadInputTokens
	c.CacheCreationInputTokens += other.CacheCreationInputTokens
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
}

// NewTracker constructs a Tracker for jsonlPath. If sessionDir is non-empty,
// the offset is persisted to <sessionDir>/usage.offset so aflock restarts
// recover their position. If sessionDir is empty, the offset is in-memory
// only (acceptable for tests; production should always pass sessionDir).
//
// If a sidecar offset exists, it is loaded; missing or corrupt sidecars
// reset to offset 0 (safe — at worst we recompute cumulative from scratch).
func NewTracker(jsonlPath, sessionDir string) *Tracker {
	t := &Tracker{jsonlPath: jsonlPath}
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

	delta := parseLines(consumed)

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
// assistant messages. Corrupt or incomplete lines are skipped (not fatal —
// claude can mid-write, partial parses happen). Non-assistant types are
// silently ignored.
func parseLines(b []byte) Cumulative {
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
		c.InputTokens += entry.Message.Usage.InputTokens
		c.OutputTokens += entry.Message.Usage.OutputTokens
		c.CacheReadInputTokens += entry.Message.Usage.CacheReadInputTokens
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
	Role  string      `json:"role"`
	Model string      `json:"model"`
	Usage *jsonlUsage `json:"usage,omitempty"`
}

type jsonlUsage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
}
