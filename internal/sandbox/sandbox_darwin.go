//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const sandboxExecPath = "/usr/bin/sandbox-exec"

// Available reports whether the platform sandbox can be applied.
func Available() bool {
	_, err := os.Stat(sandboxExecPath)
	return err == nil
}

// Profile renders the Seatbelt (SBPL) profile for the plan. Deny-rule
// semantics: everything is allowed except the protected surface, so normal
// agent work is unaffected while the policy file and files.deny globs are
// enforced for every descendant process.
func Profile(plan *Plan) string {
	var b strings.Builder
	b.WriteString("(version 1)\n(allow default)\n")

	if len(plan.ProtectedFiles) > 0 {
		b.WriteString("(deny file-write*")
		for _, p := range plan.ProtectedFiles {
			fmt.Fprintf(&b, "\n  (literal \"%s\")", sbplEscape(p))
		}
		b.WriteString(")\n")
	}

	if len(plan.DenyReadGlobs) > 0 {
		b.WriteString("(deny file-read* file-write*")
		for _, g := range plan.DenyReadGlobs {
			fmt.Fprintf(&b, "\n  (regex #\"%s\")", globToRegex(g))
		}
		b.WriteString(")\n")
	}

	return b.String()
}

// Command returns the argv that runs `argv` under the sandbox.
func Command(plan *Plan, argv []string) ([]string, error) {
	if !Available() {
		return nil, fmt.Errorf("%s not found — Seatbelt sandbox unavailable", sandboxExecPath)
	}
	out := append([]string{sandboxExecPath, "-p", Profile(plan)}, argv...)
	return out, nil
}

// Exec replaces the current process with argv running under the sandbox.
// The Seatbelt profile is inherited by every descendant and cannot be
// dropped or widened by any of them.
func Exec(plan *Plan, argv []string) error {
	cmdline, err := Command(plan, argv)
	if err != nil {
		return err
	}
	target, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("resolve %q: %w", argv[0], err)
	}
	cmdline[3] = target
	return syscall.Exec(sandboxExecPath, cmdline, os.Environ())
}

// GapNotes describes what this platform's sandbox cannot express.
func GapNotes(plan *Plan) []string {
	return nil
}
