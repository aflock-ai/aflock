// Package policy provides pattern matching for policy evaluation.
package policy

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/gobwas/glob"
)

// safeGlobMatch wraps glob.Match with panic recovery. The gobwas/glob library
// can panic on certain patterns that compile successfully but trigger out-of-bounds
// access during matching. We treat panics as non-matches.
func safeGlobMatch(g glob.Glob, s string) (matched bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			matched = false
			err = fmt.Errorf("glob match panicked: %v", r)
		}
	}()
	return g.Match(s), nil
}

// Matcher handles pattern matching for policy rules.
type Matcher struct {
	globs   map[string]glob.Glob
	regexes map[string]*regexp.Regexp
}

// NewMatcher creates a new matcher.
func NewMatcher() *Matcher {
	return &Matcher{
		globs:   make(map[string]glob.Glob),
		regexes: make(map[string]*regexp.Regexp),
	}
}

// MatchGlob checks if value matches the glob pattern.
// Handles **/*.ext patterns to also match root-level files like foo.ext
func (m *Matcher) MatchGlob(pattern, value string) bool {
	g, ok := m.globs[pattern]
	if !ok {
		var err error
		g, err = glob.Compile(pattern)
		if err != nil {
			// Cache nil so we don't retry on every call, and log the error.
			// A malformed deny pattern must not silently disappear — that turns
			// a security rule into a no-op (issue #60 / L8).
			m.globs[pattern] = nil
			fmt.Fprintf(os.Stderr, "[aflock] Warning: invalid glob deny pattern %q (compile error: %v) — rule will be skipped\n", pattern, err)
			return false
		}
		m.globs[pattern] = g
	}
	if g == nil {
		return false
	}
	if matched, matchErr := safeGlobMatch(g, value); matchErr != nil {
		// Glob panicked during match — treat as non-match
		return false
	} else if matched {
		return true
	}

	// Handle **/*.ext patterns - gobwas/glob's ** requires at least one path segment,
	// so **/*.go doesn't match root-level main.go. We check with the equivalent *.ext pattern.
	if strings.HasPrefix(pattern, "**/") { //nolint:nestif
		// Convert **/*.go to *.go and try again
		rootPattern := pattern[3:] // Remove **/ prefix
		if rootG, ok := m.globs[rootPattern]; ok {
			if matched, matchErr := safeGlobMatch(rootG, value); matchErr == nil && matched {
				return true
			}
			return false
		}
		rootG, err := glob.Compile(rootPattern)
		if err == nil {
			m.globs[rootPattern] = rootG
			if matched, matchErr := safeGlobMatch(rootG, value); matchErr == nil && matched {
				return true
			}
		}
	}

	return false
}

// MatchRegex checks if value matches the regex pattern.
// If the pattern has no leading ^ anchor or trailing $ anchor, it is
// automatically wrapped with ^(...)$ to enforce full-string matching and
// prevent unintended substring matches (R3-127).
//
// Security (R3-242): Anchor detection uses HasPrefix/HasSuffix instead of
// Contains. Previously, ^ or $ anywhere in the pattern (including inside
// character classes like [^x] or [$]) would suppress auto-anchoring,
// turning the regex into an unintended substring match.
func (m *Matcher) MatchRegex(pattern, value string) bool {
	re, ok := m.regexes[pattern]
	if !ok {
		anchored := pattern
		// Auto-anchor patterns that lack leading ^ or trailing $ anchors.
		// We check prefix/suffix specifically to avoid false positives from
		// ^ inside character classes (e.g., [^x]) or $ inside classes ([$]).
		if !strings.HasPrefix(pattern, "^") && !strings.HasSuffix(pattern, "$") {
			anchored = "^(" + pattern + ")$"
		}
		var err error
		re, err = regexp.Compile(anchored)
		if err != nil {
			return false
		}
		m.regexes[pattern] = re
	}
	return re.MatchString(value)
}

// MatchAny checks if value matches any of the patterns (glob).
func (m *Matcher) MatchAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if m.MatchGlob(pattern, value) {
			return true
		}
	}
	return false
}

// ParseToolPattern parses a pattern like "Bash:rm -rf *" into tool name and command pattern.
// Returns (toolName, commandPattern, hasPattern).
func ParseToolPattern(pattern string) (string, string, bool) {
	idx := strings.Index(pattern, ":")
	if idx == -1 {
		return pattern, "", false
	}
	return pattern[:idx], pattern[idx+1:], true
}

// MatchToolPattern checks if a tool call matches a pattern.
// Patterns can be:
// - "ToolName" - matches tool name exactly
// - "ToolName:pattern" - matches tool name and command/path pattern (glob only)
//
// Security (R3-241): Command patterns are matched using glob ONLY, not regex.
// Previously, patterns that didn't match as glob were retried as regex. This
// caused characters with different semantics between glob and regex (|, ., +,
// etc.) to widen matches. For example, "Bash:git log|rm -rf /" intended as
// a literal glob would match "rm -rf /" through regex alternation. Glob-only
// matching eliminates this class of bypass.
func (m *Matcher) MatchToolPattern(pattern string, toolName string, input string) bool {
	patternTool, patternCmd, hasCmd := ParseToolPattern(pattern)

	// Check if tool name matches
	if !m.MatchGlob(patternTool, toolName) {
		return false
	}

	// If no command pattern, tool name match is sufficient
	if !hasCmd {
		return true
	}

	// Match command/path against glob pattern only.
	return m.MatchGlob(patternCmd, input)
}
