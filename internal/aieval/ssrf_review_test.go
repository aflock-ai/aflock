package aieval

import "testing"

// Review test: validateURL only enforces scheme + host, so metadata/loopback IPs pass.
func TestValidateURL_AllowsMetadataIP(t *testing.T) {
	urls := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:8000/",
		"http://localhost:8000/",
	}
	for _, u := range urls {
		if err := validateURL(u); err != nil {
			t.Fatalf("validateURL unexpectedly rejected %q: %v", u, err)
		}
	}
}
