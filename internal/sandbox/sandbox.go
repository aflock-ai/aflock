// Package sandbox launches an agent under a kernel-enforced sandbox derived
// from the .aflock policy — `aflock exec -- claude ...`.
//
// Motivation (issue #100): aflock's hook/MCP enforcement is an application-
// layer plane. A subagent spawned N levels deep — or any process the agent
// starts — can use native tools that never traverse aflock, and can even
// rewrite the .aflock policy file itself. Kernel sandboxes close exactly
// that gap: both macOS Seatbelt profiles and Linux Landlock rulesets are
// inherited by every descendant process and can never be dropped or widened
// by a child, so process depth stops mattering.
//
// What the sandbox enforces (per platform):
//
//	darwin (Seatbelt / sandbox-exec): deny-rule semantics.
//	  - the policy file(s), trust config, and file-based trust roots are
//	    write-protected for the whole process tree;
//	  - files.deny globs are unreadable AND unwritable at any depth.
//
//	linux (Landlock LSM, kernel 5.13+): allowlist semantics — Landlock has
//	  no deny rules, so write access is granted ONLY to the files.allow
//	  prefixes plus the runtime dirs aflock/Claude need; the policy file is
//	  protected by never being write-granted. Requires a files.allow
//	  allowlist in the policy.
//
// This is enforcement, not evidence: it complements — never replaces — the
// hook-layer receipts. Hooks still see, decide, and attest every tool call;
// the kernel guarantees that what the hooks never saw also couldn't touch
// the protected surface.
package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Plan is the platform-independent sandbox specification derived from a
// policy. Platform files translate it into a Seatbelt profile or a Landlock
// ruleset.
type Plan struct {
	// ProjectRoot is the absolute project directory (where the policy lives).
	ProjectRoot string
	// ProtectedFiles are absolute paths that must be unwritable for the
	// whole process tree: the policy file and its signed variants, the trust
	// config, and file-based trust roots. The agent must never be able to
	// rewrite the rules it runs under.
	ProtectedFiles []string
	// DenyReadGlobs are the policy's files.deny patterns, resolved to
	// absolute glob form. On darwin they become deny file-read*/file-write*
	// regex rules; on linux they cannot be expressed (no deny rules) and are
	// reported as a documented gap.
	DenyReadGlobs []string
	// AllowWriteDirs are the absolute directory prefixes derived from
	// files.allow static prefixes — the only write-granted paths on linux.
	AllowWriteDirs []string
	// Strict makes sandbox unavailability a hard error instead of a warning.
	Strict bool
}

// BuildPlan derives the sandbox plan from a loaded policy.
func BuildPlan(pol *aflock.Policy, policyPath string) (*Plan, error) {
	absPolicy, err := filepath.Abs(policyPath)
	if err != nil {
		return nil, fmt.Errorf("resolve policy path: %w", err)
	}
	root := filepath.Dir(absPolicy)

	plan := &Plan{ProjectRoot: root}

	// Protect every on-disk spelling of the policy, present or future:
	// overwriting .aflock.signed with a fresh unsigned .aflock must fail
	// just as hard as editing the loaded file.
	// Seatbelt matches the kernel's resolved view of a path, so a literal
	// through a symlinked prefix (/var → /private/var, /tmp → /private/tmp)
	// silently fails to match. Protect BOTH spellings of every path.
	seen := map[string]bool{}
	addProtected := func(p string) {
		for _, spelling := range bothSpellings(p) {
			if spelling != "" && !seen[spelling] {
				seen[spelling] = true
				plan.ProtectedFiles = append(plan.ProtectedFiles, spelling)
			}
		}
	}
	addProtected(absPolicy)
	base := strings.TrimSuffix(filepath.Base(absPolicy), ".signed")
	addProtected(filepath.Join(root, base))
	addProtected(filepath.Join(root, base+".signed"))
	addProtected(filepath.Join(root, "aflock-trust.json"))

	if pol != nil {
		for _, r := range pol.Roots {
			// Only file-path roots (not inline PEM / base64) are on disk —
			// an existence check distinguishes them.
			if r.Certificate != "" && !strings.Contains(r.Certificate, "-----BEGIN") {
				if p := absolutize(r.Certificate, root); fileExists(p) {
					addProtected(p)
				}
			}
		}
	}

	if pol != nil && pol.Files != nil {
		for _, deny := range pol.Files.Deny {
			globSeen := map[string]bool{}
			for _, rootSpelling := range bothSpellings(root) {
				g := absolutizeGlob(deny, rootSpelling)
				if !globSeen[g] {
					globSeen[g] = true
					plan.DenyReadGlobs = append(plan.DenyReadGlobs, g)
				}
			}
		}
		for _, allow := range pol.Files.Allow {
			if prefix := staticPrefix(allow); prefix != "" {
				plan.AllowWriteDirs = append(plan.AllowWriteDirs, absolutize(prefix, root))
			}
		}
	}

	return plan, nil
}

// RuntimeWriteDirs are the directories the agent and aflock's own hooks need
// writable regardless of policy: session state, Claude's transcripts and
// config, and the system temp dirs.
func RuntimeWriteDirs() []string {
	dirs := []string{os.TempDir(), "/tmp", "/dev"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs,
			filepath.Join(home, ".aflock"),
			filepath.Join(home, ".claude"),
			filepath.Join(home, ".cache"),
		)
	}
	return dirs
}

// bothSpellings returns p as given and with its directory's symlinks
// resolved (the file itself may not exist yet — e.g. the .signed sibling of
// an unsigned policy — so only the parent directory is resolved).
func bothSpellings(p string) []string {
	if p == "" {
		return nil
	}
	out := []string{p}
	if resolvedDir, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		if resolved := filepath.Join(resolvedDir, filepath.Base(p)); resolved != p {
			out = append(out, resolved)
		}
	}
	return out
}

// fileExists reports whether a regular file exists at p.
func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// absolutize resolves p against root when relative.
func absolutize(p, root string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(root, p)
}

// absolutizeGlob resolves a glob pattern against root when relative,
// preserving glob metacharacters.
func absolutizeGlob(pattern, root string) string {
	if strings.HasPrefix(pattern, "/") {
		return pattern
	}
	return root + "/" + pattern
}

// staticPrefix returns the leading path segments of a glob that contain no
// metacharacters — "src/**" → "src", "docs/api/*.md" → "docs/api",
// "**/*.go" → "" (no static prefix).
func staticPrefix(pattern string) string {
	var parts []string
	for seg := range strings.SplitSeq(pattern, "/") {
		if strings.ContainsAny(seg, "*?[{") {
			break
		}
		parts = append(parts, seg)
	}
	return strings.Join(parts, "/")
}

// globToRegex translates an absolute glob into an anchored POSIX regex for
// Seatbelt (regex #"...") rules. `**/` matches any number of directories
// (including none), `**` matches across separators, `*` within a segment,
// `?` a single non-separator character.
func globToRegex(pattern string) string {
	var b strings.Builder
	b.WriteString("^")
	i := 0
	for i < len(pattern) {
		switch {
		case strings.HasPrefix(pattern[i:], "**/"):
			b.WriteString("(.*/)?")
			i += 3
		case strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(".*")
			i += 2
		case pattern[i] == '*':
			b.WriteString("[^/]*")
			i++
		case pattern[i] == '?':
			b.WriteString("[^/]")
			i++
		default:
			c := pattern[i]
			if strings.ContainsRune(`.+()|[]{}^$\`, rune(c)) {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
			i++
		}
	}
	b.WriteString("$")
	return b.String()
}

// sbplEscape escapes a literal string for inclusion in an SBPL profile.
func sbplEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}
