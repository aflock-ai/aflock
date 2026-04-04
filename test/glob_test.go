package test

import (
	"fmt"
	"os"
	"testing"

	"github.com/gobwas/glob"
)

func TestGlobMatching(t *testing.T) {
	testCases := []struct {
		pattern string
		value   string
		match   bool
	}{
		// ** should match zero or more path segments
		{"**/*.go", "main.go", false}, // This is the actual behavior - ** requires at least one segment
		{"**/*.go", "internal/policy/main.go", true},
		{"*.go", "main.go", true},
		{"**/*", "main.go", false}, // Same - ** requires at least one segment

		// For top-level files, use *.go or combine patterns
		{"*.go", "evaluator.go", true},
		{"**/*.go", "evaluator.go", false},

		// Combined - need to check both
	}

	for _, tc := range testCases {
		g, err := glob.Compile(tc.pattern)
		if err != nil {
			t.Errorf("Error compiling %s: %v", tc.pattern, err)
			continue
		}
		match := g.Match(tc.value)
		if match != tc.match {
			t.Errorf("Pattern '%s' matches '%s': got %v, want %v", tc.pattern, tc.value, match, tc.match)
		}
	}
}

func TestMain(m *testing.M) {
	// Debug output for glob pattern behavior
	patterns := []string{"**/*.go", "*.go", "**/*"}
	values := []string{"main.go", "internal/policy/evaluator.go", "evaluator.go"}

	for _, pattern := range patterns {
		g, err := glob.Compile(pattern)
		if err != nil {
			fmt.Printf("Error compiling %s: %v\n", pattern, err)
			continue
		}
		for _, value := range values {
			match := g.Match(value)
			fmt.Printf("Pattern '%s' matches '%s': %v\n", pattern, value, match)
		}
		fmt.Println()
	}

	// Run all tests — without this call, no Test* functions execute.
	os.Exit(m.Run())
}
