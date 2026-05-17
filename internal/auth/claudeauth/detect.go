// Package claudeauth detects which authentication mode claude-code is
// using for the current session: pay-per-token API key vs subscription
// (Pro/Max OAuth).
//
// Why this matters: aflock's JSONL-derived metrics (tokens, cost) match
// what Anthropic actually bills only under API-key mode, where the
// public per-token rates apply directly. Under subscription, Anthropic
// uses an internal accounting that JSONL-based tracking cannot reproduce
// (claude-code's internal haiku-routing calls + opus system calls land
// in the bill but never in the transcript). So cost-based limits like
// maxSpendUSD should enforce under API-key mode and be advisory-only
// under subscription mode. Closes #111.
//
// Detection precedence (first match wins):
//  1. AFLOCK_AUTH_MODE env var ("api_key" | "subscription") — explicit override
//  2. ANTHROPIC_API_KEY env var present — claude-code uses key over OAuth
//  3. ~/.claude/.credentials.json contains an apiKey field — API key
//  4. ~/.claude/.credentials.json contains a claudeAiOauth block — subscription
//  5. macOS Keychain has "Claude Code-credentials" entry — subscription
//  6. Otherwise — Unknown (caller should treat as subscription for advisory safety)
package claudeauth

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Mode names the authentication mode claude-code is using.
type Mode string

const (
	// ModeAPIKey indicates claude-code is billing per token via an
	// Anthropic API key (env var, .credentials.json apiKey, etc.).
	// JSONL-derived cost numbers match actual billing under this mode.
	ModeAPIKey Mode = "api_key"

	// ModeSubscription indicates claude-code is using Pro/Max OAuth
	// (Anthropic Console subscription). JSONL-derived cost numbers
	// will NOT match Claude /usage's $ because subscription accounting
	// is internal to Anthropic.
	ModeSubscription Mode = "subscription"

	// ModeUnknown means detection could not conclude. Callers should
	// treat this as subscription-equivalent for the purpose of cost
	// limit enforcement — better to advise than to falsely deny when
	// the auth signal is ambiguous.
	ModeUnknown Mode = "unknown"
)

// Detect returns the auth mode claude-code is using for the current
// session. Best-effort and side-effect-free: never prompts the user, never
// reads secret material, never writes anything. On macOS the keychain
// probe lists the entry's metadata only (no password access prompt).
func Detect() Mode {
	if m := envOverride(); m != ModeUnknown {
		return m
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return ModeAPIKey
	}
	if m := detectFromCredentialsFile(); m != ModeUnknown {
		return m
	}
	if runtime.GOOS == "darwin" && macosKeychainHasClaudeCode() {
		return ModeSubscription
	}
	return ModeUnknown
}

func envOverride() Mode {
	switch os.Getenv("AFLOCK_AUTH_MODE") {
	case string(ModeAPIKey):
		return ModeAPIKey
	case string(ModeSubscription):
		return ModeSubscription
	}
	return ModeUnknown
}

// credentialsFile mirrors the subset of ~/.claude/.credentials.json that
// signals auth mode. claude-code has used both shapes historically:
// `apiKey` (string) for API-key mode and `claudeAiOauth` (object) for
// OAuth. Other fields are ignored. We never read the secret material;
// only the presence of these keys.
type credentialsFile struct {
	APIKey        string          `json:"apiKey,omitempty"`
	ClaudeAIOauth json.RawMessage `json:"claudeAiOauth,omitempty"`
}

func detectFromCredentialsFile() Mode {
	home, err := os.UserHomeDir()
	if err != nil {
		return ModeUnknown
	}
	path := filepath.Join(home, ".claude", ".credentials.json")
	data, err := os.ReadFile(path) //nolint:gosec // G304: well-known path under user home
	if err != nil {
		return ModeUnknown
	}
	var c credentialsFile
	if err := json.Unmarshal(data, &c); err != nil {
		return ModeUnknown
	}
	if c.APIKey != "" {
		return ModeAPIKey
	}
	if len(c.ClaudeAIOauth) > 0 {
		return ModeSubscription
	}
	return ModeUnknown
}

// macosKeychainHasClaudeCode returns true when the macOS login keychain
// has a generic-password entry with service "Claude Code-credentials" —
// claude-code's storage location for OAuth tokens on darwin. Uses
// `security find-generic-password` without -w so only entry metadata is
// listed; the password is never read and no UI prompt is triggered.
func macosKeychainHasClaudeCode() bool {
	cmd := exec.Command("security", "find-generic-password", "-s", "Claude Code-credentials")
	return cmd.Run() == nil
}
