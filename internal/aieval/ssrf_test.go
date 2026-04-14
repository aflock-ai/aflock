package aieval

import (
	"net"
	"strings"
	"testing"
)

// TestBlockedIPReason exercises the IP classification table directly so we
// don't need DNS or live network for the negative cases (issue #61 / M9).
func TestBlockedIPReason(t *testing.T) {
	cases := []struct {
		ip     string
		blocks bool
		hint   string
	}{
		// Blocked
		{"127.0.0.1", true, "loopback"},
		{"127.5.5.5", true, "loopback"},
		{"::1", true, "loopback"},
		{"169.254.169.254", true, "metadata"},
		{"169.254.0.42", true, "link-local"},
		{"10.0.0.1", true, "RFC 1918"},
		{"172.16.0.1", true, "RFC 1918"},
		{"172.31.255.255", true, "RFC 1918"},
		{"192.168.1.1", true, "RFC 1918"},
		{"100.64.0.1", true, "RFC 6598"},
		{"0.0.0.0", true, "unspecified"},
		{"::", true, "unspecified"},
		{"fc00::1", true, "unique-local"},
		{"fd12:3456::1", true, "unique-local"},
		{"fe80::1", true, "link-local"},

		// Allowed (public)
		{"8.8.8.8", false, ""},
		{"1.1.1.1", false, ""},
		{"172.32.0.1", false, ""}, // just outside RFC 1918
		{"172.15.255.255", false, ""},
		{"192.169.0.1", false, ""}, // not 192.168
		{"100.63.255.255", false, ""},
		{"100.128.0.1", false, ""},
		{"2606:4700:4700::1111", false, ""}, // Cloudflare public IPv6
	}

	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("parse %q failed", tc.ip)
			}
			got := blockedIPReason(ip)
			if tc.blocks && got == "" {
				t.Errorf("%s should be blocked but blockedIPReason returned empty", tc.ip)
			}
			if !tc.blocks && got != "" {
				t.Errorf("%s should be allowed but blockedIPReason returned %q", tc.ip, got)
			}
			if tc.blocks && tc.hint != "" && !strings.Contains(strings.ToLower(got), strings.ToLower(tc.hint)) {
				t.Errorf("%s: reason %q should mention %q", tc.ip, got, tc.hint)
			}
		})
	}
}

// TestValidateURL_RejectsLoopback ensures the integrated path (parse + resolve
// + classify) actually rejects an obviously-internal hostname. We use literal
// IPs so the test doesn't depend on DNS state.
func TestValidateURL_RejectsLoopback(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1/",
		"http://127.0.0.1:11434/api/generate",
		"https://[::1]/",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5:8080/",
		"http://192.168.1.1/",
	} {
		if err := validateURL(raw); err == nil {
			t.Errorf("validateURL(%q) returned nil; expected SSRF rejection", raw)
		}
	}
}

func TestValidateURL_AcceptsPublic(t *testing.T) {
	// Use a literal public IP so we don't depend on outbound DNS.
	if err := validateURL("https://8.8.8.8/"); err != nil {
		t.Errorf("validateURL on public IP rejected: %v", err)
	}
}

func TestValidateURL_RejectsNonHTTPScheme(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/passwd",
		"gopher://example.com/",
		"ftp://example.com/",
	} {
		if err := validateURL(raw); err == nil {
			t.Errorf("validateURL(%q) returned nil; expected scheme rejection", raw)
		}
	}
}
