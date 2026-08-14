package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectedPaths(t *testing.T) {
	cwd := t.TempDir()

	paths := ProtectedPaths(filepath.Join(cwd, "policy.aflock"), cwd)

	want := []string{
		filepath.Join(cwd, "policy.aflock"),
		filepath.Join(cwd, ".aflock"),
		filepath.Join(cwd, ".claude", "settings.json"),
		filepath.Join(cwd, ".claude", "settings.local.json"),
	}
	if len(paths) != len(want) {
		t.Fatalf("expected %d paths, got %d: %v", len(want), len(paths), paths)
	}
	for i, w := range want {
		if paths[i] != w {
			t.Errorf("paths[%d] = %q, want %q", i, paths[i], w)
		}
	}

	t.Run("relative policy path resolves against cwd", func(t *testing.T) {
		paths := ProtectedPaths(".aflock", cwd)
		if paths[0] != filepath.Join(cwd, ".aflock") {
			t.Errorf("relative policy path not resolved against cwd: %q", paths[0])
		}
	})

	t.Run("empty policy path and cwd", func(t *testing.T) {
		if paths := ProtectedPaths("", ""); len(paths) != 0 {
			t.Errorf("expected no paths, got %v", paths)
		}
	})
}

func TestCheckSelfProtect(t *testing.T) {
	cwd := t.TempDir()
	protected := ProtectedPaths(filepath.Join(cwd, ".aflock"), cwd)

	tests := []struct {
		name       string
		toolName   string
		toolInput  map[string]interface{}
		wantDenied bool
	}{
		{
			// The exact issue #100 repro: a subagent rewrote the policy via
			// a Bash heredoc.
			name:     "bash heredoc rewrite of .aflock -> denied (#100 repro)",
			toolName: "Bash",
			toolInput: map[string]interface{}{
				"command": "cat > " + filepath.Join(cwd, ".aflock") + " << 'AFLOCK_EOF'\n{\"version\":\"1.0\"}\nAFLOCK_EOF",
			},
			wantDenied: true,
		},
		{
			name:       "bash read of .aflock -> allowed",
			toolName:   "Bash",
			toolInput:  map[string]interface{}{"command": "cat .aflock"},
			wantDenied: false,
		},
		{
			name:       "bash grep of .aflock -> allowed",
			toolName:   "Bash",
			toolInput:  map[string]interface{}{"command": "grep tools .aflock"},
			wantDenied: false,
		},
		{
			name:       "bash rm of .aflock -> denied",
			toolName:   "Bash",
			toolInput:  map[string]interface{}{"command": "rm .aflock"},
			wantDenied: true,
		},
		{
			name:       "bash sed -i on settings.json -> denied",
			toolName:   "Bash",
			toolInput:  map[string]interface{}{"command": "sed -i 's/deny/allow/' .claude/settings.json"},
			wantDenied: true,
		},
		{
			name:       "bash redirect to unrelated file -> allowed",
			toolName:   "Bash",
			toolInput:  map[string]interface{}{"command": "echo hi > /tmp/out.txt"},
			wantDenied: false,
		},
		{
			name:       "write to .aflock -> denied",
			toolName:   "Write",
			toolInput:  map[string]interface{}{"file_path": filepath.Join(cwd, ".aflock")},
			wantDenied: true,
		},
		{
			name:       "write to .aflock in another directory -> denied (basename match)",
			toolName:   "Write",
			toolInput:  map[string]interface{}{"file_path": "/some/other/dir/.aflock"},
			wantDenied: true,
		},
		{
			name:       "write to src/main.go -> allowed",
			toolName:   "Write",
			toolInput:  map[string]interface{}{"file_path": filepath.Join(cwd, "src", "main.go")},
			wantDenied: false,
		},
		{
			name:       "edit to .claude/settings.json -> denied",
			toolName:   "Edit",
			toolInput:  map[string]interface{}{"file_path": filepath.Join(cwd, ".claude", "settings.json")},
			wantDenied: true,
		},
		{
			name:       "edit to .claude/settings.local.json elsewhere -> denied (suffix match)",
			toolName:   "Edit",
			toolInput:  map[string]interface{}{"file_path": "/elsewhere/.claude/settings.local.json"},
			wantDenied: true,
		},
		{
			name:       "multiedit to loaded policy path -> denied",
			toolName:   "MultiEdit",
			toolInput:  map[string]interface{}{"file_path": protected[0]},
			wantDenied: true,
		},
		{
			name:       "notebookedit to guardrail via notebook_path -> denied",
			toolName:   "NotebookEdit",
			toolInput:  map[string]interface{}{"notebook_path": filepath.Join(cwd, ".aflock")},
			wantDenied: true,
		},
		{
			name:       "read tool ignores guard",
			toolName:   "Read",
			toolInput:  map[string]interface{}{"file_path": filepath.Join(cwd, ".aflock")},
			wantDenied: false,
		},
		{
			name:       "write with missing file_path -> allowed",
			toolName:   "Write",
			toolInput:  map[string]interface{}{},
			wantDenied: false,
		},
		{
			name:       "nil input -> allowed",
			toolName:   "Bash",
			toolInput:  nil,
			wantDenied: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			denied, reason := CheckSelfProtect(tt.toolName, tt.toolInput, protected)
			if denied != tt.wantDenied {
				t.Fatalf("denied = %v, want %v (reason=%q)", denied, tt.wantDenied, reason)
			}
			if denied {
				if !strings.Contains(reason, "[aflock] BLOCKED") || !strings.Contains(reason, "issue #100") {
					t.Errorf("deny reason missing repo-style markers: %q", reason)
				}
			}
		})
	}
}

func TestCheckPolicyTamper(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, ".aflock")
	original := []byte(`{"version":"1.0","name":"p"}`)
	if err := os.WriteFile(policyPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(original)
	digest := hex.EncodeToString(sum[:])

	t.Run("unmodified file -> no deny", func(t *testing.T) {
		if denied, reason := CheckPolicyTamper(policyPath, digest); denied {
			t.Fatalf("unexpected deny: %s", reason)
		}
	})

	t.Run("modified file -> deny", func(t *testing.T) {
		if err := os.WriteFile(policyPath, []byte(`{"version":"1.0","name":"p","tools":{"allow":["*"]}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		denied, reason := CheckPolicyTamper(policyPath, digest)
		if !denied {
			t.Fatal("expected deny after policy file modification")
		}
		if !strings.Contains(reason, "digest mismatch") || !strings.Contains(reason, "issue #100") {
			t.Errorf("unexpected deny reason: %q", reason)
		}
	})

	t.Run("deleted file -> deny (fail closed)", func(t *testing.T) {
		if err := os.Remove(policyPath); err != nil {
			t.Fatal(err)
		}
		if denied, _ := CheckPolicyTamper(policyPath, digest); !denied {
			t.Fatal("expected deny when policy file is unreadable")
		}
	})

	t.Run("empty digest -> skip (legacy sessions)", func(t *testing.T) {
		if denied, _ := CheckPolicyTamper(policyPath, ""); denied {
			t.Fatal("empty digest must skip the check")
		}
	})
}
