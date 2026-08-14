package policy

import (
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

func TestIsAdvisoryLimit(t *testing.T) {
	e := NewEvaluator(&aflock.Policy{}, "")
	cases := []struct {
		name         string
		limit        string
		authMode     string
		costMeasured bool
		advisory     bool
	}{
		{"api_key + measured cost enforced", "maxSpendUSD", "api_key", true, false},
		{"api_key + unmeasured cost advisory", "maxSpendUSD", "api_key", false, true},
		{"subscription cost advisory", "maxSpendUSD", "subscription", true, true},
		{"unknown cost advisory", "maxSpendUSD", "unknown", true, true},
		{"subscription tokens still enforced", "maxTokensIn", "subscription", false, false},
		{"subscription tokens out still enforced", "maxTokensOut", "subscription", false, false},
		{"subscription turns still enforced", "maxTurns", "subscription", false, false},
		{"subscription toolcalls still enforced", "maxToolCalls", "subscription", false, false},
		{"tokens enforced even when cost unmeasured", "maxTokensIn", "api_key", false, false},
		{"empty authMode enforces", "maxSpendUSD", "", false, false},
	}
	for _, c := range cases {
		got := e.IsAdvisoryLimit(c.limit, c.authMode, c.costMeasured)
		if got != c.advisory {
			t.Errorf("%s: IsAdvisoryLimit(%q,%q,%v)=%v, want %v", c.name, c.limit, c.authMode, c.costMeasured, got, c.advisory)
		}
	}
}
