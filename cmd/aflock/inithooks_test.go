package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMergeAflockHooks(t *testing.T) {
	tests := []struct {
		name       string
		existing   string
		wantAdded  int
		wantErr    bool
		checkAfter func(t *testing.T, settings map[string]interface{})
	}{
		{
			name:      "empty settings -> all events added",
			existing:  "",
			wantAdded: len(aflockHookEvents),
			checkAfter: func(t *testing.T, settings map[string]interface{}) {
				hooks := settings["hooks"].(map[string]interface{})
				for _, spec := range aflockHookEvents {
					if _, ok := hooks[spec.event]; !ok {
						t.Errorf("missing hook event %s", spec.event)
					}
				}
			},
		},
		{
			name:      "unrelated keys and non-aflock hooks preserved",
			existing:  `{"model":"opus","permissions":{"allow":["Bash(ls:*)"]},"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"my-linter check"}]}]}}`,
			wantAdded: len(aflockHookEvents),
			checkAfter: func(t *testing.T, settings map[string]interface{}) {
				if settings["model"] != "opus" {
					t.Error("unrelated key 'model' was clobbered")
				}
				if _, ok := settings["permissions"].(map[string]interface{}); !ok {
					t.Error("unrelated key 'permissions' was clobbered")
				}
				pre := settings["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})
				if len(pre) != 2 {
					t.Fatalf("expected 2 PreToolUse entries (existing + aflock), got %d", len(pre))
				}
				first := pre[0].(map[string]interface{})
				cmd := first["hooks"].([]interface{})[0].(map[string]interface{})["command"]
				if cmd != "my-linter check" {
					t.Errorf("pre-existing non-aflock hook was not preserved: %v", cmd)
				}
			},
		},
		{
			name:      "plugin-form aflock hook counts as present",
			existing:  `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"aflock --hook PreToolUse"}]}]}}`,
			wantAdded: len(aflockHookEvents) - 1,
		},
		{
			name:     "malformed settings -> error, never clobber",
			existing: `{not json`,
			wantErr:  true,
		},
		{
			name:     "non-object hooks key -> error, never clobber",
			existing: `{"hooks": "surprise"}`,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merged, added, err := mergeAflockHooks([]byte(tt.existing))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("mergeAflockHooks: %v", err)
			}
			if len(added) != tt.wantAdded {
				t.Fatalf("added %d events, want %d: %v", len(added), tt.wantAdded, added)
			}
			var settings map[string]interface{}
			if err := json.Unmarshal(merged, &settings); err != nil {
				t.Fatalf("merged output is not valid JSON: %v", err)
			}
			if tt.checkAfter != nil {
				tt.checkAfter(t, settings)
			}

			// Idempotent: a second merge adds nothing and is byte-stable.
			again, addedAgain, err := mergeAflockHooks(merged)
			if err != nil {
				t.Fatalf("second merge: %v", err)
			}
			if len(addedAgain) != 0 {
				t.Errorf("second merge added entries: %v", addedAgain)
			}
			if string(again) != string(merged) {
				t.Error("second merge changed the settings bytes")
			}
		})
	}
}

func TestInstallAflockHooks(t *testing.T) {
	dir := t.TempDir()

	settingsPath, added, err := installAflockHooks(dir)
	if err != nil {
		t.Fatalf("installAflockHooks: %v", err)
	}
	if settingsPath != filepath.Join(dir, ".claude", "settings.json") {
		t.Errorf("unexpected settings path: %s", settingsPath)
	}
	if len(added) != len(aflockHookEvents) {
		t.Fatalf("added %d events, want %d", len(added), len(aflockHookEvents))
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("settings not valid JSON: %v", err)
	}

	// Second install is a no-op (init run twice must not duplicate).
	_, addedAgain, err := installAflockHooks(dir)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if len(addedAgain) != 0 {
		t.Errorf("second install added entries: %v", addedAgain)
	}
	after, _ := os.ReadFile(settingsPath)
	if string(after) != string(data) {
		t.Error("second install modified settings.json")
	}
}
