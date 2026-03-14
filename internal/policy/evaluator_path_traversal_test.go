package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// ---------------------------------------------------------------------------
// Path traversal via symlinks (fail-05, Vector 1)
//
// A symlink src/config.json → ../../restricted/credentials.json passes the
// deny check because filePathVariants only examines the symlink path, never
// the resolved target. After the fix, EvalSymlinks adds the real target to
// the variant list so deny patterns match.
// ---------------------------------------------------------------------------

func pathTraversalPolicy() *aflock.Policy {
	return &aflock.Policy{
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Write", "Edit", "Bash", "Glob", "Grep"},
		},
		Files: &aflock.FilesPolicy{
			Allow: []string{"src/**", "*.md"},
			Deny:  []string{"restricted/**", "**/credentials*"},
		},
	}
}

func TestSymlink_ToDeniedPath_Denied(t *testing.T) {
	// Setup: create a temp dir with restricted/credentials.json and a symlink
	tmpDir := t.TempDir()
	restricted := filepath.Join(tmpDir, "restricted")
	src := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(restricted, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	credFile := filepath.Join(restricted, "credentials.json")
	if err := os.WriteFile(credFile, []byte(`{"key":"secret"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create symlink: src/config.json → ../restricted/credentials.json
	symlink := filepath.Join(src, "config.json")
	if err := os.Symlink(filepath.Join("..", "restricted", "credentials.json"), symlink); err != nil {
		t.Fatal(err)
	}

	pol := pathTraversalPolicy()
	evaluator := NewEvaluator(pol, tmpDir)

	toolInput, _ := json.Marshal(aflock.FileToolInput{FilePath: symlink})
	decision, reason := evaluator.EvaluatePreToolUse("Read", toolInput)
	if decision != aflock.DecisionDeny {
		t.Errorf("symlink to denied file should be DENIED, got %s (reason: %s)", decision, reason)
	}
}

func TestSymlink_ToAllowedPath_Allowed(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create a real file in allowed path
	realFile := filepath.Join(src, "utils.go")
	if err := os.WriteFile(realFile, []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create symlink: src/helper.go → src/utils.go (both in allowed area)
	symlink := filepath.Join(src, "helper.go")
	if err := os.Symlink("utils.go", symlink); err != nil {
		t.Fatal(err)
	}

	pol := pathTraversalPolicy()
	evaluator := NewEvaluator(pol, tmpDir)

	toolInput, _ := json.Marshal(aflock.FileToolInput{FilePath: symlink})
	decision, reason := evaluator.EvaluatePreToolUse("Read", toolInput)
	if decision != aflock.DecisionAllow {
		t.Errorf("symlink to allowed file should be ALLOWED, got %s (reason: %s)", decision, reason)
	}
}

func TestSymlink_RegularFileInAllowedPath_Allowed(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(src, "main.go")
	if err := os.WriteFile(realFile, []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}

	pol := pathTraversalPolicy()
	evaluator := NewEvaluator(pol, tmpDir)

	toolInput, _ := json.Marshal(aflock.FileToolInput{FilePath: realFile})
	decision, reason := evaluator.EvaluatePreToolUse("Read", toolInput)
	if decision != aflock.DecisionAllow {
		t.Errorf("regular file in allowed path should be ALLOWED, got %s (reason: %s)", decision, reason)
	}
}

func TestSymlink_NonExistentFile_NoCrash(t *testing.T) {
	tmpDir := t.TempDir()
	pol := pathTraversalPolicy()
	evaluator := NewEvaluator(pol, tmpDir)

	// Non-existent file — EvalSymlinks will error, should not crash
	toolInput, _ := json.Marshal(aflock.FileToolInput{FilePath: filepath.Join(tmpDir, "src", "nonexistent.go")})
	// Should not panic — decision doesn't matter as long as it doesn't crash
	evaluator.EvaluatePreToolUse("Read", toolInput)
}

// ---------------------------------------------------------------------------
// Path traversal via Bash file-reading commands (fail-05, Vector 2)
//
// "cat restricted/credentials.json" via Bash bypasses file deny because
// isFileOperation("Bash") returns false. After the fix, file arguments are
// extracted from Bash commands and checked against files.deny.
// ---------------------------------------------------------------------------

func TestBashFileRead_DeniedFile_Denied(t *testing.T) {
	pol := pathTraversalPolicy()
	evaluator := NewEvaluator(pol, "/project")

	tests := []struct {
		name    string
		command string
	}{
		{"cat denied file", "cat restricted/credentials.json"},
		{"head denied file", "head restricted/credentials.json"},
		{"tail denied file", "tail -20 restricted/credentials.json"},
		{"cat credentials by name", "cat src/credentials.bak"},
		{"less denied file", "less restricted/secrets.txt"},
		{"base64 denied file", "base64 restricted/credentials.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toolInput, _ := json.Marshal(aflock.BashToolInput{Command: tt.command})
			decision, reason := evaluator.EvaluatePreToolUse("Bash", toolInput)
			if decision != aflock.DecisionDeny {
				t.Errorf("bash %q should be DENIED, got %s (reason: %s)", tt.command, decision, reason)
			}
		})
	}
}

func TestBashFileRead_AllowedFile_Allowed(t *testing.T) {
	pol := pathTraversalPolicy()
	evaluator := NewEvaluator(pol, "/project")

	tests := []struct {
		name    string
		command string
	}{
		{"cat readme", "cat README.md"},
		{"head src file", "head -20 src/app.py"},
		{"ls directory", "ls -la"},
		{"grep in src", "grep -r 'pattern' src/"},
		{"git status", "git status"},
		{"piping to sort", "cat data.csv | sort | head -10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toolInput, _ := json.Marshal(aflock.BashToolInput{Command: tt.command})
			decision, reason := evaluator.EvaluatePreToolUse("Bash", toolInput)
			if decision != aflock.DecisionAllow {
				t.Errorf("bash %q should be ALLOWED, got %s (reason: %s)", tt.command, decision, reason)
			}
		})
	}
}

func TestBashFileRead_NoDenyList_NotChecked(t *testing.T) {
	// When there are no files.deny patterns, bash file reading should not be blocked
	pol := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Bash"},
		},
		Files: &aflock.FilesPolicy{
			Allow: []string{"src/**"},
			// No Deny patterns
		},
	}
	evaluator := NewEvaluator(pol, "/project")

	toolInput, _ := json.Marshal(aflock.BashToolInput{Command: "cat restricted/credentials.json"})
	decision, reason := evaluator.EvaluatePreToolUse("Bash", toolInput)
	if decision != aflock.DecisionAllow {
		t.Errorf("should be allowed when no deny list, got %s (reason: %s)", decision, reason)
	}
}

// ---------------------------------------------------------------------------
// ExtractFileArgs unit tests
// ---------------------------------------------------------------------------

func TestExtractFileArgs_SingleFile(t *testing.T) {
	a := NewBashAnalyzer()
	args := a.ExtractFileArgs("cat file.txt")
	if len(args) != 1 || args[0] != "file.txt" {
		t.Errorf("expected [file.txt], got %v", args)
	}
}

func TestExtractFileArgs_WithFlags(t *testing.T) {
	a := NewBashAnalyzer()
	args := a.ExtractFileArgs("head -20 src/app.py")
	if len(args) != 1 || args[0] != "src/app.py" {
		t.Errorf("expected [src/app.py], got %v", args)
	}
}

func TestExtractFileArgs_Pipeline(t *testing.T) {
	a := NewBashAnalyzer()
	args := a.ExtractFileArgs("cat secrets.txt | grep password")
	// Both cat and grep are file-reading commands; grep's "password" is
	// extracted as a non-flag arg (which is fine for deny-list purposes).
	if len(args) != 2 {
		t.Errorf("expected [secrets.txt password], got %v", args)
	}
}

func TestExtractFileArgs_Chaining(t *testing.T) {
	a := NewBashAnalyzer()
	args := a.ExtractFileArgs("echo done; cat restricted/creds.json && head other.txt")
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %v", args)
	}
	expected := map[string]bool{"restricted/creds.json": true, "other.txt": true}
	for _, a := range args {
		if !expected[a] {
			t.Errorf("unexpected arg %q", a)
		}
	}
}

func TestExtractFileArgs_Dedup(t *testing.T) {
	a := NewBashAnalyzer()
	args := a.ExtractFileArgs("cat file.txt; cat file.txt")
	if len(args) != 1 {
		t.Errorf("expected dedup to 1 arg, got %v", args)
	}
}

func TestExtractFileArgs_NonFileCommand(t *testing.T) {
	a := NewBashAnalyzer()
	args := a.ExtractFileArgs("ls -la")
	if len(args) != 0 {
		t.Errorf("ls should not extract file args, got %v", args)
	}
}

func TestExtractFileArgs_GrepIsFileCommand(t *testing.T) {
	a := NewBashAnalyzer()
	args := a.ExtractFileArgs("grep -r pattern src/")
	// grep is now a file-reading command; non-flag args are extracted.
	if len(args) != 2 {
		t.Errorf("grep should extract file args [pattern src/], got %v", args)
	}
}

func TestExtractFileArgs_EmptyCommand(t *testing.T) {
	a := NewBashAnalyzer()
	args := a.ExtractFileArgs("")
	if len(args) != 0 {
		t.Errorf("empty command should return no args, got %v", args)
	}
}
