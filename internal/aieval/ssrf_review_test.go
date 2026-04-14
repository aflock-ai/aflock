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
