package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// hookEventSpec describes one aflock hook entry for .claude/settings.json.
// Mirrors plugin/hooks/hooks.json, but invokes the installed binary via PATH
// ("aflock hook <event>", the form the docs use for non-plugin setups).
type hookEventSpec struct {
	event   string
	matcher string
	timeout int
}

// aflockHookEvents is the full event set aflock enforces. Installing all of
// them via settings.json is the enforcement floor: settings-level hooks fire
// for subagent native tool calls too, which MCP-only integration cannot
// intercept (issue #100).
var aflockHookEvents = []hookEventSpec{
	{event: "SessionStart", matcher: "", timeout: 10},
	{event: "PreToolUse", matcher: "*", timeout: 5},
	{event: "PostToolUse", matcher: "*", timeout: 5},
	{event: "PermissionRequest", matcher: "*", timeout: 5},
	{event: "UserPromptSubmit", matcher: "", timeout: 5},
	{event: "Stop", matcher: "", timeout: 5},
	{event: "SubagentStop", matcher: "", timeout: 5},
	{event: "SessionEnd", matcher: "", timeout: 30},
}

// mergeAflockHooks merges aflock's hook entries into existing Claude Code
// settings JSON (may be empty), preserving every unrelated key and any
// non-aflock hook entries. Idempotent: an event that already has an aflock
// hook command is left untouched, so running `aflock init` twice does not
// duplicate entries. Returns the merged JSON and the list of events added.
func mergeAflockHooks(existing []byte) ([]byte, []string, error) {
	settings := map[string]interface{}{}
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &settings); err != nil {
			return nil, nil, fmt.Errorf("parse existing settings: %w", err)
		}
	}

	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		if _, exists := settings["hooks"]; exists {
			return nil, nil, fmt.Errorf("existing settings has non-object \"hooks\" key; refusing to overwrite")
		}
		hooks = map[string]interface{}{}
	}

	var added []string
	for _, spec := range aflockHookEvents {
		entries, _ := hooks[spec.event].([]interface{})
		if hasAflockHook(entries, spec.event) {
			continue
		}
		entry := map[string]interface{}{
			"matcher": spec.matcher,
			"hooks": []interface{}{
				map[string]interface{}{
					"type":    "command",
					"command": "aflock hook " + spec.event,
					"timeout": spec.timeout,
				},
			},
		}
		hooks[spec.event] = append(entries, entry)
		added = append(added, spec.event)
	}
	settings["hooks"] = hooks

	merged, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshal settings: %w", err)
	}
	return append(merged, '\n'), added, nil
}

// hasAflockHook reports whether any entry for the event already invokes
// aflock, in either the PATH form ("aflock hook <event>") or the plugin form
// ("aflock --hook <event>").
func hasAflockHook(entries []interface{}, event string) bool {
	for _, e := range entries {
		entry, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		cmds, _ := entry["hooks"].([]interface{})
		for _, c := range cmds {
			cmd, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			command, _ := cmd["command"].(string)
			if command == "aflock hook "+event || command == "aflock --hook "+event {
				return true
			}
		}
	}
	return false
}

// installAflockHooks merges aflock's hook entries into .claude/settings.json
// under dir, creating the directory and file if absent. Returns the events
// that were added (empty when everything was already wired).
func installAflockHooks(dir string) (settingsPath string, added []string, err error) {
	settingsPath = filepath.Join(dir, ".claude", "settings.json")

	existing, err := os.ReadFile(settingsPath) //nolint:gosec // G304: fixed path under cwd
	if err != nil && !os.IsNotExist(err) {
		return settingsPath, nil, fmt.Errorf("read %s: %w", settingsPath, err)
	}

	merged, added, err := mergeAflockHooks(existing)
	if err != nil {
		return settingsPath, nil, err
	}
	if len(added) == 0 {
		return settingsPath, nil, nil
	}

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		return settingsPath, nil, fmt.Errorf("create .claude dir: %w", err)
	}
	if err := os.WriteFile(settingsPath, merged, 0o644); err != nil { //nolint:gosec // G306: settings file must stay readable by Claude Code
		return settingsPath, nil, fmt.Errorf("write %s: %w", settingsPath, err)
	}
	return settingsPath, added, nil
}
