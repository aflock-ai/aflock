// Package claudeauth detects which authentication mode claude-code is
// using for the current session: pay-per-token API key vs subscription
// (Pro/Max OAuth).
//
// Why this matters: aflock's JSONL-derived metrics (tokens, cost) line
// up with what Anthropic actually bills only under API-key mode, where
// the public per-token rates apply directly. Under subscription mode
// Anthropic uses an internal accounting that JSONL-based tracking
// cannot reproduce (claude-code's internal haiku title gen, compaction
// summaries, and other helper calls hit the bill but never the
// transcript). Cost-based limits like maxSpendUSD should therefore
// enforce under API-key mode and stay advisory under subscription mode.
//
// Detection precedence (first match wins):
//  1. AFLOCK_AUTH_MODE env var ("api_key" | "subscription") — explicit override
//  2. ANTHROPIC_API_KEY env var present — claude-code uses key over OAuth
//  3. ~/.claude/.credentials.json contains an apiKey field — API key
//  4. ~/.claude/.credentials.json contains a claudeAiOauth block — subscription
//  5. macOS Keychain has "Claude Code-credentials" entry — subscription
//  6. Otherwise — Unknown (caller treats as subscription for advisory safety)
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
	// Anthropic API key. JSONL-derived cost numbers match actual billing.
	ModeAPIKey Mode = "api_key"

	// ModeSubscription indicates claude-code is using Pro/Max OAuth.
	// JSONL-derived cost will NOT match Anthropic's internal accounting.
	ModeSubscription Mode = "subscription"

	// ModeUnknown means detection could not conclude. Callers treat this
	// as subscription-equivalent for cost-limit enforcement — better to
	// advise than to falsely deny when the auth signal is ambiguous.
	ModeUnknown Mode = "unknown"
)

// Detect returns the auth mode claude-code is using for the current
// session. Best-effort and side-effect-free: never prompts, never reads
// secret material, never writes anything. The macOS keychain probe
// lists entry metadata only (no password access prompt).
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

// credentialsFile mirrors the subset of ~/.claude/.credentials.json
// that signals auth mode. claude-code has used both shapes historically:
// `apiKey` (string) for API-key mode and `claudeAiOauth` (object) for
// OAuth. We never read the secret material; only the presence of these
// fields.
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
// has a generic-password entry with service "Claude Code-credentials".
// Uses `security find-generic-password` without -w so only entry
// metadata is listed; the password is never read and no UI prompt fires.
func macosKeychainHasClaudeCode() bool {
	cmd := exec.Command("security", "find-generic-password", "-s", "Claude Code-credentials")
	return cmd.Run() == nil
}
