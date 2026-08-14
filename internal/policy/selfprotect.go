package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Self-protection guard (issue #100): an agent rewrote the .aflock policy
// file itself via a subagent's native tools — nothing hard-protected aflock's
// own guardrail files. This file makes the loaded policy, the .aflock in cwd,
// and the .claude/settings.json hook wiring off-limits to the agent,
// regardless of what the policy's files rules say.

// guardrailSuffixes are matched against the tail of an absolute cleaned path
// so writes to the hook wiring are denied wherever the file lives.
var guardrailSuffixes = []string{
	string(filepath.Separator) + filepath.Join(".claude", "settings.json"),
	string(filepath.Separator) + filepath.Join(".claude", "settings.local.json"),
}

// bashWriteIndicators are substrings that suggest a Bash command mutates a
// file (redirection, in-place editors, file managers).
var bashWriteIndicators = []string{
	">", "tee", "mv ", "cp ", "rm ", "sed -i", "truncate", "dd ", "chmod", "ln ", "install ",
}

// ProtectedPaths returns the absolute, cleaned paths of aflock's own
// guardrail files: the loaded policy file plus the cwd-relative .aflock and
// Claude Code settings files that wire aflock's hooks (issue #100).
func ProtectedPaths(policyPath string, cwd string) []string {
	var paths []string
	add := func(p string) {
		if p == "" {
			return
		}
		if !filepath.IsAbs(p) && cwd != "" {
			p = filepath.Join(cwd, p)
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return
		}
		paths = append(paths, filepath.Clean(abs))
	}
	add(policyPath)
	if cwd != "" {
		add(filepath.Join(cwd, ".aflock"))
		add(filepath.Join(cwd, ".claude", "settings.json"))
		add(filepath.Join(cwd, ".claude", "settings.local.json"))
	}
	return paths
}

// CheckSelfProtect denies tool calls that would modify one of aflock's own
// guardrail files (issue #100). File-writing tools are matched on their
// resolved target path. Bash is matched on best-effort string analysis: this
// layer is defense in depth, not a guarantee — an obfuscated command can slip
// past it, which is why the mid-session digest check (CheckPolicyTamper)
// exists to void any benefit from a successful rewrite.
func CheckSelfProtect(toolName string, toolInput map[string]interface{}, protected []string) (denied bool, reason string) {
	switch toolName {
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		target, _ := toolInput["file_path"].(string)
		if target == "" {
			target, _ = toolInput["notebook_path"].(string)
		}
		if target == "" {
			return false, ""
		}
		abs, err := filepath.Abs(target)
		if err != nil {
			return false, ""
		}
		abs = filepath.Clean(abs)
		if isGuardrailPath(abs, protected) {
			return true, fmt.Sprintf(
				"[aflock] BLOCKED: %s is an aflock guardrail file and cannot be modified by the agent (issue #100)",
				target)
		}
	case "Bash":
		command, _ := toolInput["command"].(string)
		if command == "" {
			return false, ""
		}
		token, referenced := bashReferencesGuardrail(command, protected)
		if referenced && bashHasWriteIndicator(command) {
			return true, fmt.Sprintf(
				"[aflock] BLOCKED: command references aflock guardrail file %s together with a write operation; guardrail files cannot be modified by the agent (issue #100)",
				token)
		}
	}
	return false, ""
}

// isGuardrailPath reports whether abs (absolute, cleaned) is one of aflock's
// guardrail files: an exact protected path, any file named .aflock, or a
// Claude Code settings file that carries hook wiring.
func isGuardrailPath(abs string, protected []string) bool {
	for _, p := range protected {
		if abs == p {
			return true
		}
	}
	if filepath.Base(abs) == ".aflock" {
		return true
	}
	for _, suffix := range guardrailSuffixes {
		if strings.HasSuffix(abs, suffix) {
			return true
		}
	}
	return false
}

// bashReferencesGuardrail reports whether the command mentions a guardrail
// file token, returning the first matched token for the deny reason.
func bashReferencesGuardrail(command string, protected []string) (string, bool) {
	tokens := []string{
		".aflock",
		filepath.Join(".claude", "settings.json"),
		filepath.Join(".claude", "settings.local.json"),
	}
	tokens = append(tokens, protected...)
	for _, token := range tokens {
		if strings.Contains(command, token) {
			return token, true
		}
	}
	return "", false
}

func bashHasWriteIndicator(command string) bool {
	for _, indicator := range bashWriteIndicators {
		if strings.Contains(command, indicator) {
			return true
		}
	}
	return false
}

// HashPolicyFile returns the SHA-256 hex digest of the raw on-disk policy
// file bytes. Used to freeze the policy contents at session init so
// CheckPolicyTamper can detect mid-session rewrites (issue #100).
func HashPolicyFile(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: policy file path from session state
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// CheckPolicyTamper re-hashes the on-disk policy file and denies when it no
// longer matches the digest captured at session init. Fails closed on read
// errors: a deleted or unreadable policy file is treated as tampering, so an
// agent that rewrote (or removed) its own policy gains nothing from the edit
// (issue #100). An empty expected digest — sessions initialized before this
// check existed — skips the check.
func CheckPolicyTamper(policyPath, expectedDigest string) (denied bool, reason string) {
	if policyPath == "" || expectedDigest == "" {
		return false, ""
	}
	current, err := HashPolicyFile(policyPath)
	if err != nil || current != expectedDigest {
		return true, "[aflock] BLOCKED: policy file has been modified mid-session (digest mismatch); refusing all tool calls (issue #100)"
	}
	return false, ""
}
