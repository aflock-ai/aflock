//go:build js && wasm

// Package main provides a WebAssembly build target that exposes aflock's
// replay evaluator to JavaScript.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"syscall/js"

	"github.com/aflock-ai/aflock/internal/policy"
	"github.com/aflock-ai/aflock/internal/replay"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

func main() {
	js.Global().Set("aflockReplay", js.FuncOf(aflockReplay))
	js.Global().Set("aflockParseSession", js.FuncOf(aflockParseSession))
	js.Global().Set("aflockEvaluateAction", js.FuncOf(aflockEvaluateAction))
	js.Global().Set("aflockVersion", js.FuncOf(aflockVersion))

	fmt.Println("aflock WASM module loaded")

	// Block forever — standard WASM pattern.
	select {}
}

// aflockReplay takes raw session JSONL and raw policy JSON, runs the replay
// evaluator, and returns the JSON report.
//
// JS signature: aflockReplay(sessionJSONL: string, policyJSON: string) -> string
func aflockReplay(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return errJSON("aflockReplay requires 2 arguments: sessionJSONL, policyJSON")
	}

	sessionJSONL := args[0].String()
	policyJSON := args[1].String()

	session, err := parseSessionFromString(sessionJSONL)
	if err != nil {
		return errJSON(fmt.Sprintf("parse session: %v", err))
	}

	var pol aflock.Policy
	if err := json.Unmarshal([]byte(policyJSON), &pol); err != nil {
		return errJSON(fmt.Sprintf("parse policy: %v", err))
	}

	// Infer project root from file paths in the session.
	// The evaluator needs this to relativize absolute paths against policy globs.
	// When called from CLI, the policy file's directory is used. In the browser,
	// we infer it from the common prefix of all absolute file paths.
	projectRoot := inferProjectRoot(session)
	// replay.Run uses filepath.Dir(policyPath) as project root,
	// so we pass projectRoot + "/policy.aflock" to make Dir() return projectRoot.
	fakePolicyPath := projectRoot + "/policy.aflock"
	if projectRoot == "" {
		fakePolicyPath = "browser"
	}

	report := replay.Run(session, &pol, fakePolicyPath)

	out, err := report.FormatJSON()
	if err != nil {
		return errJSON(fmt.Sprintf("format report: %v", err))
	}

	return out
}

// aflockParseSession parses session metadata from JSONL content.
//
// JS signature: aflockParseSession(sessionJSONL: string) -> string
func aflockParseSession(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errJSON("aflockParseSession requires 1 argument: sessionJSONL")
	}

	session, err := parseSessionFromString(args[0].String())
	if err != nil {
		return errJSON(fmt.Sprintf("parse session: %v", err))
	}

	toolNames := make([]string, 0, len(session.Actions))
	for _, a := range session.Actions {
		toolNames = append(toolNames, a.Tool)
	}

	type sessionInfo struct {
		Model     string   `json:"model"`
		Turns     int      `json:"turns"`
		TokensIn  int64    `json:"tokensIn"`
		TokensOut int64    `json:"tokensOut"`
		ToolCalls int      `json:"toolCalls"`
		Actions   []string `json:"actions"`
	}

	data, err := json.Marshal(sessionInfo{
		Model:     session.Model,
		Turns:     session.Turns,
		TokensIn:  session.TokensIn,
		TokensOut: session.TokensOut,
		ToolCalls: len(session.Actions),
		Actions:   toolNames,
	})
	if err != nil {
		return errJSON(fmt.Sprintf("marshal session info: %v", err))
	}

	return string(data)
}

// aflockEvaluateAction evaluates a single tool action against a policy.
//
// JS signature: aflockEvaluateAction(toolName: string, toolInputJSON: string, policyJSON: string, projectRoot: string) -> string
func aflockEvaluateAction(_ js.Value, args []js.Value) any {
	if len(args) < 4 {
		return errJSON("aflockEvaluateAction requires 4 arguments: toolName, toolInputJSON, policyJSON, projectRoot")
	}

	toolName := args[0].String()
	toolInputJSON := args[1].String()
	policyJSON := args[2].String()
	projectRoot := args[3].String()

	var pol aflock.Policy
	if err := json.Unmarshal([]byte(policyJSON), &pol); err != nil {
		return errJSON(fmt.Sprintf("parse policy: %v", err))
	}

	evaluator := policy.NewEvaluator(&pol, projectRoot)
	decision, reason := evaluator.EvaluatePreToolUse(toolName, json.RawMessage(toolInputJSON))

	type decisionResult struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}

	data, err := json.Marshal(decisionResult{
		Decision: string(decision),
		Reason:   reason,
	})
	if err != nil {
		return errJSON(fmt.Sprintf("marshal decision: %v", err))
	}

	return string(data)
}

// aflockVersion returns the WASM module version string.
//
// JS signature: aflockVersion() -> string
func aflockVersion(_ js.Value, _ []js.Value) any {
	return "aflock-wasm v0.1.0"
}

// parseSessionFromString parses a Claude Code JSONL session from an in-memory
// string, mirroring the logic in replay.ParseSession but without file I/O.
func parseSessionFromString(jsonl string) (*replay.Session, error) {
	session := &replay.Session{}
	scanner := bufio.NewScanner(strings.NewReader(jsonl))
	// Claude session lines can be large (tool results with file contents).
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

		// Extract model.
		if m, ok := msg["model"].(string); ok && m != "" && m != "<synthetic>" {
			session.Model = m
		}

		// Extract token usage.
		if usage, ok := msg["usage"].(map[string]any); ok {
			if v, ok := usage["input_tokens"].(float64); ok {
				session.TokensIn += int64(v)
			}
			if v, ok := usage["output_tokens"].(float64); ok {
				session.TokensOut += int64(v)
			}
		}

		// Extract tool calls from content blocks.
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
			session.Actions = append(session.Actions, replay.Action{
				Index:    idx,
				Tool:     toolName,
				ID:       toolID,
				Input:    input,
				RawInput: rawInput,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read session data: %w", err)
	}

	return session, nil
}

// inferProjectRoot finds the longest common directory prefix across all
// absolute file paths in the session. This mirrors what the CLI does using
// the policy file's directory.
func inferProjectRoot(session *replay.Session) string {
	var absPaths []string
	for _, a := range session.Actions {
		if fp, ok := a.Input["file_path"].(string); ok && len(fp) > 0 && fp[0] == '/' {
			absPaths = append(absPaths, fp)
		}
	}
	if len(absPaths) == 0 {
		return ""
	}

	// Split first path into parts as the starting common prefix.
	parts := strings.Split(absPaths[0], "/")
	commonLen := len(parts)

	for _, p := range absPaths[1:] {
		segs := strings.Split(p, "/")
		j := 0
		for j < commonLen && j < len(segs) && segs[j] == parts[j] {
			j++
		}
		commonLen = j
	}

	prefix := strings.Join(parts[:commonLen], "/")
	return prefix
}

// errJSON returns a JSON-encoded error string.
func errJSON(msg string) string {
	data, _ := json.Marshal(map[string]string{"error": msg})
	return string(data)
}
