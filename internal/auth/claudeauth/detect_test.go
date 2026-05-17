package claudeauth

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetect_EnvOverrideWins asserts the AFLOCK_AUTH_MODE override beats
// every other signal. Useful for tests, CI, and explicit user override.
func TestDetect_EnvOverrideWins(t *testing.T) {
	t.Setenv("AFLOCK_AUTH_MODE", "api_key")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("HOME", t.TempDir())
	if got := Detect(); got != ModeAPIKey {
		t.Errorf("expected ModeAPIKey from AFLOCK_AUTH_MODE override, got %q", got)
	}

	t.Setenv("AFLOCK_AUTH_MODE", "subscription")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-...")
	if got := Detect(); got != ModeSubscription {
		t.Errorf("expected override to beat ANTHROPIC_API_KEY, got %q", got)
	}
}

// TestDetect_ApiKeyEnvVar covers the common pay-per-token path: user has
// ANTHROPIC_API_KEY exported and claude-code is billing it directly.
func TestDetect_ApiKeyEnvVar(t *testing.T) {
	t.Setenv("AFLOCK_AUTH_MODE", "")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-api-...")
	t.Setenv("HOME", t.TempDir())
	if got := Detect(); got != ModeAPIKey {
		t.Errorf("expected ModeAPIKey when ANTHROPIC_API_KEY is set, got %q", got)
	}
}

// TestDetect_CredentialsFileApiKey covers the legacy "apiKey" field in
// ~/.claude/.credentials.json — older claude-code installs stored a flat
// API key here. Treat presence of the apiKey field as ModeAPIKey.
func TestDetect_CredentialsFileApiKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AFLOCK_AUTH_MODE", "")
	t.Setenv("ANTHROPIC_API_KEY", "")

	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	creds := `{"apiKey":"sk-ant-fake-for-tests"}`
	if err := os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"), []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Detect(); got != ModeAPIKey {
		t.Errorf("expected ModeAPIKey from credentials.json apiKey field, got %q", got)
	}
}

// TestDetect_CredentialsFileOauth covers the Pro/Max subscription path:
// ~/.claude/.credentials.json holds a claudeAiOauth object with the
// access token + refresh token. Presence of the object is enough to
// signal subscription; we never read the token itself.
func TestDetect_CredentialsFileOauth(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AFLOCK_AUTH_MODE", "")
	t.Setenv("ANTHROPIC_API_KEY", "")

	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	creds := `{"claudeAiOauth":{"accessToken":"redacted","refreshToken":"redacted"}}`
	if err := os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"), []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Detect(); got != ModeSubscription {
		t.Errorf("expected ModeSubscription from claudeAiOauth block, got %q", got)
	}
}

// TestDetect_UnknownWhenNoSignal covers the fallback path. No env var,
// no credentials file, and the macOS keychain probe (when on darwin)
// finds no entry. We can also reach this branch on Linux when the
// credentials.json simply doesn't exist.
func TestDetect_UnknownWhenNoSignal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AFLOCK_AUTH_MODE", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	// Don't create credentials.json. On macOS the keychain probe may
	// still find a real entry on the developer's machine, so this test
	// is informational on darwin: if it returns ModeSubscription, that's
	// the keychain leaking a real signal. We assert only that we don't
	// falsely return ModeAPIKey here.
	got := Detect()
	if got == ModeAPIKey {
		t.Errorf("expected non-api_key (Unknown or Subscription via keychain), got %q", got)
	}
}

// TestDetect_CredentialsFileMalformed asserts we don't panic on a
// corrupt credentials.json and don't infer the wrong mode from junk.
func TestDetect_CredentialsFileMalformed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AFLOCK_AUTH_MODE", "")
	t.Setenv("ANTHROPIC_API_KEY", "")

	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Detect()
	if got == ModeAPIKey {
		t.Errorf("malformed credentials shouldn't yield ModeAPIKey, got %q", got)
	}
}
