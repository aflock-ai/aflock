//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
)

// Available reports whether the platform sandbox can be applied. Landlock
// needs kernel 5.13+ with the LSM enabled; BestEffort mode degrades
// gracefully, so this only reports the mechanism's presence in the binary.
func Available() bool { return true }

// Exec restricts the current process with a Landlock ruleset derived from
// the plan, then replaces it with argv. Landlock rulesets are inherited by
// every descendant process and can only ever be tightened, never dropped.
//
// Landlock has allowlist semantics (no deny rules), so write access is
// granted ONLY to the plan's AllowWriteDirs plus the runtime dirs; the
// policy file is protected by never being write-granted. A policy without
// files.allow cannot be meaningfully sandboxed on linux — Exec refuses.
func Exec(plan *Plan, argv []string) error {
	if len(plan.AllowWriteDirs) == 0 {
		return fmt.Errorf("linux sandbox needs a files.allow allowlist in the policy: " +
			"Landlock grants write access only to listed paths (it has no deny rules), " +
			"so an empty allowlist would leave the agent unable to write anything")
	}

	rwDirs := append([]string{}, plan.AllowWriteDirs...)
	rwDirs = append(rwDirs, RuntimeWriteDirs()...)
	var rw []string
	for _, d := range rwDirs {
		if _, err := os.Stat(d); err == nil {
			rw = append(rw, d)
		}
	}

	cfg := landlock.V5
	if !plan.Strict {
		cfg = cfg.BestEffort()
	}
	if err := cfg.RestrictPaths(
		landlock.RODirs("/"),
		landlock.RWDirs(rw...),
	); err != nil {
		return fmt.Errorf("apply Landlock ruleset: %w", err)
	}

	target, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("resolve %q: %w", argv[0], err)
	}
	return syscall.Exec(target, argv, os.Environ())
}

// GapNotes describes what this platform's sandbox cannot express.
func GapNotes(plan *Plan) []string {
	var notes []string
	if len(plan.DenyReadGlobs) > 0 {
		notes = append(notes, fmt.Sprintf(
			"files.deny read-blocking (%d patterns) is not kernel-enforced on linux — Landlock has no deny rules; hook-layer enforcement still applies",
			len(plan.DenyReadGlobs)))
	}
	return notes
}
