package policy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// ErrUnknownPlaceholder is returned when a policy references a placeholder
// not in allowedPlaceholders. Strict by design: typos in placeholder names
// previously silenced into "literal string never matches anything" bugs at
// verify time.
var ErrUnknownPlaceholder = errors.New("unknown placeholder in policy")

// ErrUnsetPlaceholder is returned when a known placeholder references an
// environment variable that isn't set at Load time. Leaving the literal in
// place is the original #134 bug — the verifier would compare a literal
// "${CLAUDE_SESSION_PATH}" against real paths and never match. Better to
// fail loudly so the operator wires the env var than to silently degrade.
var ErrUnsetPlaceholder = errors.New("placeholder env var not set")

// allowedPlaceholders maps the placeholder name (without ${} or $) to the
// environment variable that should resolve it. Keeping this list explicit
// (rather than letting any env var leak in via os.ExpandEnv) means a typo
// in a policy fails Load instead of silently becoming an empty string.
//
// Document new entries in docs/reference/policy-schema.md so users learn
// what's available before they paste paper examples and wonder why verify
// is returning "Materials binding failed".
var allowedPlaceholders = map[string]string{
	"CLAUDE_SESSION_PATH": "CLAUDE_SESSION_PATH",
	"GIT_TREE_HASH":       "GIT_TREE_HASH",
}

// expandPlaceholders walks the policy's placeholder-bearing fields and
// substitutes shell-style ${NAME} references with values from the
// environment. Called from Load after JSON unmarshal so every consumer
// (verifier, hooks, MCP server) sees fully-resolved values without each
// having to call os.Expand on its own — paper §4.4 / issue #134.
//
// Currently expands only MaterialsFrom.Session.Path and
// MaterialsFrom.Git.TreeHash, which are the two slots the paper example
// uses. Other policy fields (Grants.Storage globs, ArtifactMaterial URIs)
// are not yet enforced at runtime and don't need expansion until they are.
func expandPlaceholders(p *aflock.Policy, getenv func(string) string) error {
	if p == nil || p.MaterialsFrom == nil {
		return nil
	}

	if p.MaterialsFrom.Session != nil {
		expanded, err := expandString(p.MaterialsFrom.Session.Path, getenv)
		if err != nil {
			return fmt.Errorf("materialsFrom.session.path: %w", err)
		}
		p.MaterialsFrom.Session.Path = expanded
	}

	if p.MaterialsFrom.Git != nil {
		expanded, err := expandString(p.MaterialsFrom.Git.TreeHash, getenv)
		if err != nil {
			return fmt.Errorf("materialsFrom.git.treeHash: %w", err)
		}
		p.MaterialsFrom.Git.TreeHash = expanded
	}

	return nil
}

// expandString substitutes ${NAME} references against allowedPlaceholders.
// Unknown names return ErrUnknownPlaceholder; known names with an unset env
// var return ErrUnsetPlaceholder. Plain literals (no ${} markers) pass
// through unchanged so policies without placeholders keep working.
//
// We hand-roll instead of using os.Expand because os.Expand silently
// resolves unset vars to "" — the exact silent-degrade behavior #134 is
// closing.
func expandString(s string, getenv func(string) string) (string, error) {
	if !strings.Contains(s, "${") {
		return s, nil
	}

	var out strings.Builder
	i := 0
	for i < len(s) {
		if i+1 < len(s) && s[i] == '$' && s[i+1] == '{' {
			end := strings.Index(s[i+2:], "}")
			if end < 0 {
				// Unterminated ${... — treat as literal so we don't change
				// behavior on accidental dollar-sign content.
				out.WriteString(s[i:])
				break
			}
			name := s[i+2 : i+2+end]
			envName, ok := allowedPlaceholders[name]
			if !ok {
				return "", fmt.Errorf("%w: ${%s} (allowed: %v)",
					ErrUnknownPlaceholder, name, allowedNames())
			}
			val := getenv(envName)
			if val == "" {
				return "", fmt.Errorf("%w: $%s referenced via ${%s}",
					ErrUnsetPlaceholder, envName, name)
			}
			out.WriteString(val)
			i += 2 + end + 1
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String(), nil
}

// allowedNames returns the sorted list of placeholder names for error
// messages. Sorted output keeps error strings deterministic across Go
// versions / map-iter randomization.
func allowedNames() []string {
	names := make([]string, 0, len(allowedPlaceholders))
	for k := range allowedPlaceholders {
		names = append(names, k)
	}
	// Tiny list — insertion sort beats importing sort.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j-1] > names[j]; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
	return names
}
