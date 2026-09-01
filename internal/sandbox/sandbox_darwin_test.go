//go:build darwin

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// End-to-end: run real commands under sandbox-exec with a profile derived
// from a real policy, and prove the enforcement holds at process depth 4.
func TestSeatbelt_EndToEnd(t *testing.T) {
	if !Available() {
		t.Skip("sandbox-exec not available")
	}
	// t.TempDir is under /var/folders — a symlinked prefix (/var →
	// /private/var). Deliberately NOT resolved here: BuildPlan must protect
	// both spellings itself, or seatbelt literals silently fail to match
	// the kernel's resolved view (regression caught in live testing).
	dir := t.TempDir()
	policyPath := filepath.Join(dir, ".aflock")
	if err := os.WriteFile(policyPath, []byte(`{"version":"1.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "secrets", "key.txt")
	if err := os.WriteFile(secret, []byte("topsecret"), 0o600); err != nil {
		t.Fatal(err)
	}

	pol := &aflock.Policy{
		Files: &aflock.FilesPolicy{Deny: []string{"secrets/**"}},
	}
	plan, err := BuildPlan(pol, policyPath)
	if err != nil {
		t.Fatal(err)
	}

	run := func(script string) (string, error) {
		cmdline, cmdErr := Command(plan, []string{"/bin/sh", "-c", script})
		if cmdErr != nil {
			t.Fatal(cmdErr)
		}
		out, runErr := exec.Command(cmdline[0], cmdline[1:]...).CombinedOutput() //nolint:gosec // test fixture
		return string(out), runErr
	}

	// 1 — writing the policy file must fail…
	if _, err := run("echo pwned > " + policyPath); err == nil {
		t.Error("direct policy write succeeded under sandbox")
	}
	// …even at process depth 4 (the issue #100 scenario).
	deep := `/bin/sh -c '/bin/sh -c "/bin/sh -c \"echo pwned > ` + policyPath + `\""'`
	if _, err := run(deep); err == nil {
		t.Error("depth-4 policy write succeeded under sandbox")
	}
	if data, _ := os.ReadFile(policyPath); strings.Contains(string(data), "pwned") {
		t.Fatal("policy file was mutated under sandbox")
	}

	// 2 — files.deny is unreadable at any depth.
	if out, err := run("cat " + secret); err == nil && strings.Contains(out, "topsecret") {
		t.Error("files.deny path was readable under sandbox")
	}

	// 3 — ordinary work is unaffected.
	if out, err := run("echo ok > " + filepath.Join(dir, "normal.txt") + " && cat " + filepath.Join(dir, "normal.txt")); err != nil || !strings.Contains(out, "ok") {
		t.Errorf("normal write/read failed under sandbox: %v %s", err, out)
	}
}
