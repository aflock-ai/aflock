package aieval

import (
	"strings"
	"testing"
)

// Regression test for issue #61 / M9: validateURL previously only enforced
// scheme + host, so metadata/loopback IPs passed. The fix blocks them.
// This was originally written to reproduce the bug; it now asserts the
// inverted behavior.
func TestValidateURL_BlocksMetadataAndLoopback(t *testing.T) {
	cases := []struct {
		url  string
		hint string
	}{
		{"http://169.254.169.254/latest/meta-data/", "metadata"},
		{"http://127.0.0.1:8000/", "loopback"},
	}
	for _, tc := range cases {
		err := validateURL(tc.url)
		if err == nil {
			t.Errorf("validateURL(%q) returned nil; expected SSRF rejection", tc.url)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), tc.hint) {
			t.Errorf("validateURL(%q) error %q should mention %q", tc.url, err, tc.hint)
		}
	}
}

// AFLOCK_AIEVAL_ALLOW_INTERNAL=1 must NOT permit cloud metadata IPs even
// though it relaxes loopback/private restrictions for local development.
func TestValidateURL_MetadataAlwaysBlocked(t *testing.T) {
	t.Setenv("AFLOCK_AIEVAL_ALLOW_INTERNAL", "1")
	if err := validateURL("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Error("metadata IP must remain blocked even with ALLOW_INTERNAL=1")
	}
}

// Issue #67 review: the Ollama default URL (http://localhost:11434) must
// validate successfully without the user setting AFLOCK_AIEVAL_ALLOW_INTERNAL.
// Regression guard for the UX bug introduced in #61.
func TestValidateURLWithContext_OllamaLocalhostDefault(t *testing.T) {
	t.Setenv("AFLOCK_AIEVAL_ALLOW_INTERNAL", "")
	if err := validateURLWithContext("http://localhost:11434", true); err != nil {
		t.Errorf("ollama localhost default should validate with localBackend=true, got: %v", err)
	}
}

// But IMDS must STILL be blocked for local backends — no escape hatch there.
func TestValidateURLWithContext_LocalBackendStillBlocksMetadata(t *testing.T) {
	t.Setenv("AFLOCK_AIEVAL_ALLOW_INTERNAL", "")
	if err := validateURLWithContext("http://169.254.169.254/", true); err == nil {
		t.Error("localBackend=true must still block cloud metadata IP")
	}
}
