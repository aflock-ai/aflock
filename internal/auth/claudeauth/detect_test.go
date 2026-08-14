package claudeauth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetect_EnvOverrideWins(t *testing.T) {
	t.Setenv("AFLOCK_AUTH_MODE", "api_key")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("HOME", t.TempDir())
	if got := Detect(); got != ModeAPIKey {
		t.Errorf("expected ModeAPIKey from AFLOCK_AUTH_MODE override, got %q", got)
	}

	t.Setenv("AFLOCK_AUTH_MODE", "subscription")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
	if got := Detect(); got != ModeSubscription {
		t.Errorf("expected override to beat ANTHROPIC_API_KEY, got %q", got)
	}
}

func TestDetect_ApiKeyEnvVar(t *testing.T) {
	t.Setenv("AFLOCK_AUTH_MODE", "")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-api-fake")
	t.Setenv("HOME", t.TempDir())
	if got := Detect(); got != ModeAPIKey {
		t.Errorf("expected ModeAPIKey when ANTHROPIC_API_KEY is set, got %q", got)
	}
}

func TestDetect_CredentialsFileApiKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AFLOCK_AUTH_MODE", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	creds := `{"apiKey":"sk-ant-fake"}`
	if err := os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"), []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Detect(); got != ModeAPIKey {
		t.Errorf("expected ModeAPIKey from credentials.json apiKey field, got %q", got)
	}
}

func TestDetect_CredentialsFileOauth(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AFLOCK_AUTH_MODE", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	creds := `{"claudeAiOauth":{"accessToken":"redacted","refreshToken":"redacted","expiresAt":0}}`
	if err := os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"), []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Detect(); got != ModeSubscription {
		t.Errorf("expected ModeSubscription from credentials.json claudeAiOauth, got %q", got)
	}
}

func TestDetect_NoSignals(t *testing.T) {
	t.Setenv("AFLOCK_AUTH_MODE", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("HOME", t.TempDir())
	// On darwin Detect may still find a real keychain entry on the dev
	// machine — accept either ModeUnknown or ModeSubscription here.
	got := Detect()
	if got != ModeUnknown && got != ModeSubscription {
		t.Errorf("expected ModeUnknown or ModeSubscription with no signals, got %q", got)
	}
}
