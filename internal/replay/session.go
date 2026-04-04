// Package replay implements session replay for validating recorded Claude Code
// sessions against aflock policies.
package replay

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// Session holds parsed metadata from a Claude Code .jsonl session file.
type Session struct {
	Path      string
	Model     string
	Turns     int
	TokensIn  int64
	TokensOut int64
	Actions   []Action
}

// Action is a single tool call extracted from a session.
type Action struct {
	Index    int
	Tool     string
	ID       string
	Input    map[string]any
	RawInput json.RawMessage
}

// ParseSession parses a Claude Code .jsonl session file and extracts all tool calls.
func ParseSession(path string) (*Session, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open session file: %w", err)
	}
	defer f.Close()

	session := &Session{Path: path}
	scanner := bufio.NewScanner(f)
	// Claude session lines can be large (tool results with file contents)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	idx := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		msg, ok := entry["message"].(map[string]any)
		if !ok {
			continue
		}

		role, _ := msg["role"].(string)

		if role == "user" {
			session.Turns++
		}

		if role != "assistant" {
			continue
		}

		// Extract model
		if m, ok := msg["model"].(string); ok && m != "" && m != "<synthetic>" {
			session.Model = m
		}

		// Extract token usage
		if usage, ok := msg["usage"].(map[string]any); ok {
			if v, ok := usage["input_tokens"].(float64); ok {
				session.TokensIn += int64(v)
			}
			if v, ok := usage["output_tokens"].(float64); ok {
				session.TokensOut += int64(v)
			}
		}

		// Extract tool calls from content blocks
		content, ok := msg["content"].([]any)
		if !ok {
			continue
		}
		for _, block := range content {
			b, ok := block.(map[string]any)
			if !ok || b["type"] != "tool_use" {
				continue
			}

			toolName, _ := b["name"].(string)
			toolID, _ := b["id"].(string)
			input, _ := b["input"].(map[string]any)
			rawInput, _ := json.Marshal(input)

			idx++
			session.Actions = append(session.Actions, Action{
				Index:    idx,
				Tool:     toolName,
				ID:       toolID,
				Input:    input,
				RawInput: rawInput,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read session file: %w", err)
	}

	return session, nil
}

// InputDetail returns a human-readable summary of a tool call's input.
func (a *Action) InputDetail() string {
	switch a.Tool {
	case "Read", "Write", "Edit":
		if fp, ok := a.Input["file_path"].(string); ok {
			return fp
		}
	case "Bash":
		if cmd, ok := a.Input["command"].(string); ok {
			if len(cmd) > 80 {
				return cmd[:80] + "..."
			}
			return cmd
		}
	case "Glob":
		if p, ok := a.Input["pattern"].(string); ok {
			return p
		}
	case "Grep":
		if p, ok := a.Input["pattern"].(string); ok {
			return p
		}
	case "Agent":
		if p, ok := a.Input["prompt"].(string); ok {
			if len(p) > 60 {
				return p[:60] + "..."
			}
			return p
		}
	}

	data, _ := json.Marshal(a.Input)
	s := string(data)
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}
