package sandbox

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

func TestBuildPlan_ProtectsPolicySpellings(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, ".aflock")

	plan, err := BuildPlan(&aflock.Policy{Version: "1.0"}, policyPath)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		filepath.Join(dir, ".aflock"):           false,
		filepath.Join(dir, ".aflock.signed"):    false,
		filepath.Join(dir, "aflock-trust.json"): false,
	}
	for _, p := range plan.ProtectedFiles {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for p, found := range want {
		if !found {
			t.Errorf("protected files missing %s (got %v)", p, plan.ProtectedFiles)
		}
	}
}

func TestBuildPlan_SignedPolicyProtectsUnsignedSpelling(t *testing.T) {
	dir := t.TempDir()
	plan, err := BuildPlan(&aflock.Policy{}, filepath.Join(dir, ".aflock.signed"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range plan.ProtectedFiles {
		if p == filepath.Join(dir, ".aflock") {
			found = true
		}
	}
	if !found {
		t.Errorf("loading .aflock.signed must also protect the unsigned .aflock spelling: %v", plan.ProtectedFiles)
	}
}

func TestBuildPlan_DenyGlobsAndAllowPrefixes(t *testing.T) {
	dir := t.TempDir()
	pol := &aflock.Policy{
		Files: &aflock.FilesPolicy{
			Allow: []string{"src/**", "docs/api/*.md", "**/*.go"},
			Deny:  []string{"**/.env", "secrets/**"},
		},
	}
	plan, err := BuildPlan(pol, filepath.Join(dir, ".aflock"))
	if err != nil {
		t.Fatal(err)
	}

	assertContains(t, plan.DenyReadGlobs, dir+"/**/.env")
	assertContains(t, plan.DenyReadGlobs, dir+"/secrets/**")
	assertContains(t, plan.AllowWriteDirs, filepath.Join(dir, "src"))
	assertContains(t, plan.AllowWriteDirs, filepath.Join(dir, "docs/api"))
	// "**/*.go" has no static prefix — must not grant a write dir.
	if len(plan.AllowWriteDirs) != 2 {
		t.Errorf("AllowWriteDirs = %v, want exactly src and docs/api", plan.AllowWriteDirs)
	}
}

func assertContains(t *testing.T, list []string, want string) {
	t.Helper()
	if !slices.Contains(list, want) {
		t.Errorf("%q not found in %v", want, list)
	}
}

func TestStaticPrefix(t *testing.T) {
	cases := map[string]string{
		"src/**":        "src",
		"docs/api/*.md": "docs/api",
		"**/*.go":       "",
		"*.md":          "",
		"a/b/c":         "a/b/c",
		"a/b?/c":        "a",
	}
	for pattern, want := range cases {
		if got := staticPrefix(pattern); got != want {
			t.Errorf("staticPrefix(%q) = %q, want %q", pattern, got, want)
		}
	}
}

func TestGlobToRegex(t *testing.T) {
	cases := map[string]string{
		"/p/**/.env":    `^/p/(.*/)?\.env$`,
		"/p/secrets/**": `^/p/secrets/.*$`,
		"/p/*.md":       `^/p/[^/]*\.md$`,
		"/p/file?.txt":  `^/p/file[^/]\.txt$`,
		"/p/a+b(c).d":   `^/p/a\+b\(c\)\.d$`,
	}
	for pattern, want := range cases {
		if got := globToRegex(pattern); got != want {
			t.Errorf("globToRegex(%q) = %q, want %q", pattern, got, want)
		}
	}
}

func TestSBPLEscape(t *testing.T) {
	if got := sbplEscape(`/path/with"quote and \slash`); got != `/path/with\"quote and \\slash` {
		t.Errorf("sbplEscape = %q", got)
	}
}
