package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// TestExpandPlaceholders_PaperExample loads the policy shape lifted directly
// from paper §4.4 (the original #134 motivating case) and confirms both
// placeholders resolve to the env values a real session would have set.
func TestExpandPlaceholders_PaperExample(t *testing.T) {
	env := map[string]string{
		"CLAUDE_SESSION_PATH": "/home/me/.claude/projects/p/abc.jsonl",
		"GIT_TREE_HASH":       "a1b2c3d4e5",
	}
	p := &aflock.Policy{
		MaterialsFrom: &aflock.MaterialsPolicy{
			Session: &aflock.SessionMaterial{Path: "${CLAUDE_SESSION_PATH}"},
			Git:     &aflock.GitMaterial{TreeHash: "${GIT_TREE_HASH}"},
		},
	}

	if err := expandPlaceholders(p, mapGetenv(env)); err != nil {
		t.Fatalf("expandPlaceholders: %v", err)
	}
	if got, want := p.MaterialsFrom.Session.Path, env["CLAUDE_SESSION_PATH"]; got != want {
		t.Errorf("Session.Path = %q, want %q", got, want)
	}
	if got, want := p.MaterialsFrom.Git.TreeHash, env["GIT_TREE_HASH"]; got != want {
		t.Errorf("Git.TreeHash = %q, want %q", got, want)
	}
}

// TestExpandPlaceholders_UnknownPlaceholder_HardFails — strict mode is the
// whole point. A typo like ${CLAUDE_SESSION_PTH} silently resolving to
// empty string is the bug #134 closes; an explicit error is what we want.
func TestExpandPlaceholders_UnknownPlaceholder_HardFails(t *testing.T) {
	p := &aflock.Policy{
		MaterialsFrom: &aflock.MaterialsPolicy{
			Session: &aflock.SessionMaterial{Path: "${CLAUDE_SESSION_PTH}"}, // typo
		},
	}
	err := expandPlaceholders(p, mapGetenv(map[string]string{}))
	if err == nil {
		t.Fatal("typo'd placeholder must fail Load")
	}
	if !errors.Is(err, ErrUnknownPlaceholder) {
		t.Errorf("wrong error: %v (want ErrUnknownPlaceholder)", err)
	}
}

// TestExpandPlaceholders_UnsetKnown_HardFails — known placeholder with an
// unset env var is also strict. Leaving the literal in place was the
// original bug: the verifier compared literal "${X}" against real values
// and never matched.
func TestExpandPlaceholders_UnsetKnown_HardFails(t *testing.T) {
	p := &aflock.Policy{
		MaterialsFrom: &aflock.MaterialsPolicy{
			Session: &aflock.SessionMaterial{Path: "${CLAUDE_SESSION_PATH}"},
		},
	}
	err := expandPlaceholders(p, mapGetenv(map[string]string{})) // empty env
	if err == nil {
		t.Fatal("unset known placeholder must fail Load")
	}
	if !errors.Is(err, ErrUnsetPlaceholder) {
		t.Errorf("wrong error: %v (want ErrUnsetPlaceholder)", err)
	}
}

// TestExpandPlaceholders_NoPlaceholder_PassesThrough — policies without any
// ${...} must keep working unchanged. Regression guard against ever turning
// the placeholder check into a required-field check.
func TestExpandPlaceholders_NoPlaceholder_PassesThrough(t *testing.T) {
	p := &aflock.Policy{
		MaterialsFrom: &aflock.MaterialsPolicy{
			Session: &aflock.SessionMaterial{Path: "/literal/path.jsonl"},
			Git:     &aflock.GitMaterial{TreeHash: "deadbeef"},
		},
	}
	if err := expandPlaceholders(p, mapGetenv(map[string]string{})); err != nil {
		t.Fatalf("literal-only policy must not error: %v", err)
	}
	if p.MaterialsFrom.Session.Path != "/literal/path.jsonl" {
		t.Errorf("literal mutated: %q", p.MaterialsFrom.Session.Path)
	}
}

// TestLoad_ExpandsPlaceholders is the end-to-end Load wiring test. Drives
// the real policy.Load entry point with a synthetic env, confirming the
// loaded *Policy has expanded values — what every downstream consumer
// (verifier, hooks, MCP) sees.
func TestLoad_ExpandsPlaceholders(t *testing.T) {
	t.Setenv("CLAUDE_SESSION_PATH", "/synthetic/session.jsonl")
	t.Setenv("GIT_TREE_HASH", "feedface")

	dir := t.TempDir()
	body := `{
	  "version": "1.0",
	  "name": "paper-example",
	  "materialsFrom": {
	    "session": { "path": "${CLAUDE_SESSION_PATH}" },
	    "git":     { "treeHash": "${GIT_TREE_HASH}" }
	  }
	}`
	policyPath := filepath.Join(dir, ".aflock")
	if err := os.WriteFile(policyPath, []byte(body), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	pol, _, err := Load(policyPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := pol.MaterialsFrom.Session.Path, "/synthetic/session.jsonl"; got != want {
		t.Errorf("Session.Path = %q, want %q (placeholder didn't expand at Load)", got, want)
	}
	if got, want := pol.MaterialsFrom.Git.TreeHash, "feedface"; got != want {
		t.Errorf("Git.TreeHash = %q, want %q", got, want)
	}
}

// mapGetenv returns a getenv func backed by an explicit map — lets tests
// avoid os.Setenv / t.Setenv when they just want to drive the helper.
func mapGetenv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}
