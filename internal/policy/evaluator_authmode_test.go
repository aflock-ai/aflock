package policy

import (
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

func TestIsAdvisoryLimit(t *testing.T) {
	e := NewEvaluator(&aflock.Policy{}, "")
	cases := []struct {
		name      string
		limit     string
		authMode  string
		advisory  bool
	}{
		{"api_key cost enforced", "maxSpendUSD", "api_key", false},
		{"subscription cost advisory", "maxSpendUSD", "subscription", true},
		{"unknown cost advisory", "maxSpendUSD", "unknown", true},
		{"subscription tokens still enforced", "maxTokensIn", "subscription", false},
		{"subscription tokens out still enforced", "maxTokensOut", "subscription", false},
		{"subscription turns still enforced", "maxTurns", "subscription", false},
		{"subscription toolcalls still enforced", "maxToolCalls", "subscription", false},
		{"empty authMode treats as api_key", "maxSpendUSD", "", false},
	}
	for _, c := range cases {
		got := e.IsAdvisoryLimit(c.limit, c.authMode)
		if got != c.advisory {
			t.Errorf("%s: IsAdvisoryLimit(%q,%q)=%v, want %v", c.name, c.limit, c.authMode, got, c.advisory)
		}
	}
}
