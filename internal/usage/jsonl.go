// Package usage parses Claude Code session JSONL transcripts to extract
// per-session token usage (input/output/cache) and computes cost from
// published per-token rates. Dollar cost is meaningful only when the
// claude-code session was authenticated with an API key — see the
// internal/auth/claudeauth package for the auth-mode probe and the
// gating wired into the policy evaluator.
//
// JSONL shape (claude-code, as of 2026): one JSON object per line, with
// assistant turns carrying a `message.usage` block:
//
//	{
//	  "type": "assistant",
//	  "sessionId": "...",
//	  "timestamp": "2026-05-19T12:34:56.789Z",
//	  "requestId": "req_01ABC...",
//	  "message": {
//	    "id": "msg_01XYZ...",
//	    "model": "claude-opus-4-7",
//	    "usage": {
//	      "input_tokens": 100,
//	      "output_tokens": 150,
//	      "cache_creation_input_tokens": 300,
//	      "cache_read_input_tokens": 50,
//	      "cache_creation": {
//	        "ephemeral_5m_input_tokens": 200,
//	        "ephemeral_1h_input_tokens": 100
//	      }
//	    }
//	  }
//	}
//
// Streaming surfaces the same (id, requestId) multiple times with
// incrementing usage totals. We dedup by (message.id, requestId) with
// overwrite-last semantics so cumulative chunks converge on the final
// snapshot instead of pinning the first (smaller) chunk's numbers. Rows
// missing either ID stay as separate entries — losing them entirely
// would under-count more than letting them double-count.
package usage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// SessionUsage is the aggregated transcript usage for a session.
//
// All token counts are summed across every assistant turn for the
// session, after dedup. Per-model breakdowns let pricing apply the
// correct rate to each model's tokens; PerModel keys are the raw model
// strings as they appear in the JSONL (e.g., "claude-opus-4-7").
type SessionUsage struct {
	InputTokens         int64                `json:"inputTokens"`
	OutputTokens        int64                `json:"outputTokens"`
	CacheCreate5mTokens int64                `json:"cacheCreate5mTokens"`
	CacheCreate1hTokens int64                `json:"cacheCreate1hTokens"`
	CacheReadTokens     int64                `json:"cacheReadTokens"`
	Turns               int                  `json:"turns"`
	PerModel            map[string]ModelRoll `json:"perModel,omitempty"`
}

// ModelRoll is the per-model rollup used by the pricing layer.
type ModelRoll struct {
	InputTokens         int64 `json:"inputTokens"`
	OutputTokens        int64 `json:"outputTokens"`
	CacheCreate5mTokens int64 `json:"cacheCreate5mTokens"`
	CacheCreate1hTokens int64 `json:"cacheCreate1hTokens"`
	CacheReadTokens     int64 `json:"cacheReadTokens"`
}

// transcriptLine is the subset of the JSONL row we care about. Fields
// outside this struct (content, role, etc.) are intentionally ignored.
type transcriptLine struct {
	Type      string  `json:"type"`
	SessionID string  `json:"sessionId"`
	RequestID string  `json:"requestId"`
	Message   message `json:"message"`
}

type message struct {
	ID    string     `json:"id"`
	Model string     `json:"model"`
	Usage usageBlock `json:"usage"`
}

type usageBlock struct {
	InputTokens              int64          `json:"input_tokens"`
	OutputTokens             int64          `json:"output_tokens"`
	CacheCreationInputTokens int64          `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64          `json:"cache_read_input_tokens"`
	CacheCreation            *cacheBreakout `json:"cache_creation,omitempty"`
}

type cacheBreakout struct {
	Ephemeral5m int64 `json:"ephemeral_5m_input_tokens"`
	Ephemeral1h int64 `json:"ephemeral_1h_input_tokens"`
}

// dedupKey identifies one logical assistant turn. Streaming emits the
// same turn N times with growing usage totals; the last write wins.
type dedupKey struct {
	MessageID string
	RequestID string
}

// ScanFile parses one JSONL transcript file and returns its aggregated
// usage. When sessionID is non-empty, lines whose sessionId field
// doesn't match are skipped — useful when a transcript file contains
// multiple session boundaries (rare but observed). An empty sessionID
// means "accept every assistant row".
//
// Streaming chunks for the same (message.id, requestId) overwrite
// earlier numbers (overwrite-last). Rows lacking either ID fall through
// and are summed verbatim, on the theory that under-counting unknown
// rows is worse than potentially double-counting them.
func ScanFile(path, sessionID string) (*SessionUsage, error) {
	f, err := os.Open(path) //nolint:gosec // G304: transcript path comes from claude-code hook input
	if err != nil {
		return nil, fmt.Errorf("open transcript: %w", err)
	}
	defer f.Close() //nolint:errcheck // best-effort close on read path

	return parseReader(f, sessionID)
}

func parseReader(r io.Reader, sessionID string) (*SessionUsage, error) {
	scanner := bufio.NewScanner(r)
	// Some assistant turns embed very large content. Bump the per-line
	// buffer so we don't truncate before reaching the usage block.
	const maxLine = 8 * 1024 * 1024
	scanner.Buffer(make([]byte, 64*1024), maxLine)

	dedup := make(map[dedupKey]ModelRoll)
	dedupModel := make(map[dedupKey]string)
	var anon []anonRow

	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 || raw[0] != '{' {
			continue
		}
		var line transcriptLine
		if err := json.Unmarshal(raw, &line); err != nil {
			continue
		}
		if line.Type != "assistant" {
			continue
		}
		if sessionID != "" && line.SessionID != "" && line.SessionID != sessionID {
			continue
		}
		roll := rollFromUsage(line.Message.Usage)
		if isZero(roll) {
			continue
		}
		if line.Message.ID == "" || line.RequestID == "" {
			anon = append(anon, anonRow{model: line.Message.Model, roll: roll})
			continue
		}
		key := dedupKey{MessageID: line.Message.ID, RequestID: line.RequestID}
		dedup[key] = roll
		dedupModel[key] = line.Message.Model
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan transcript: %w", err)
	}

	out := &SessionUsage{PerModel: make(map[string]ModelRoll)}
	for key, roll := range dedup {
		add(out, dedupModel[key], roll)
	}
	for _, a := range anon {
		add(out, a.model, a.roll)
	}
	out.Turns = len(dedup) + len(anon)
	if len(out.PerModel) == 0 {
		out.PerModel = nil
	}
	return out, nil
}

type anonRow struct {
	model string
	roll  ModelRoll
}

func rollFromUsage(u usageBlock) ModelRoll {
	r := ModelRoll{
		InputTokens:     u.InputTokens,
		OutputTokens:    u.OutputTokens,
		CacheReadTokens: u.CacheReadInputTokens,
	}
	// Prefer the explicit 5m/1h breakdown when the API supplied it; fall
	// back to dumping the whole cache_creation_input_tokens count into
	// the 5m bucket (the historical default tier and what claude-code
	// uses when it doesn't request a longer TTL).
	if u.CacheCreation != nil && (u.CacheCreation.Ephemeral5m > 0 || u.CacheCreation.Ephemeral1h > 0) {
		r.CacheCreate5mTokens = u.CacheCreation.Ephemeral5m
		r.CacheCreate1hTokens = u.CacheCreation.Ephemeral1h
	} else {
		r.CacheCreate5mTokens = u.CacheCreationInputTokens
	}
	return r
}

func isZero(r ModelRoll) bool {
	return r.InputTokens == 0 && r.OutputTokens == 0 &&
		r.CacheCreate5mTokens == 0 && r.CacheCreate1hTokens == 0 && r.CacheReadTokens == 0
}

func add(out *SessionUsage, model string, r ModelRoll) {
	out.InputTokens += r.InputTokens
	out.OutputTokens += r.OutputTokens
	out.CacheCreate5mTokens += r.CacheCreate5mTokens
	out.CacheCreate1hTokens += r.CacheCreate1hTokens
	out.CacheReadTokens += r.CacheReadTokens
	if model == "" {
		return
	}
	if out.PerModel == nil {
		out.PerModel = make(map[string]ModelRoll)
	}
	cur := out.PerModel[model]
	cur.InputTokens += r.InputTokens
	cur.OutputTokens += r.OutputTokens
	cur.CacheCreate5mTokens += r.CacheCreate5mTokens
	cur.CacheCreate1hTokens += r.CacheCreate1hTokens
	cur.CacheReadTokens += r.CacheReadTokens
	out.PerModel[model] = cur
}
