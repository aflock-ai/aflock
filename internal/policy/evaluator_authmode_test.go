package policy

import (
	"testing"
)

// TestIsAdvisoryLimit_CostLimitsUnderSubscription proves the table
// CodexBar-style local-scan metrics use: cost-based limits drop to
// advisory under subscription mode because JSONL × public rates can't
// reproduce Anthropic's subscription billing.
func TestIsAdvisoryLimit_CostLimitsUnderSubscription(t *testing.T) {
	e := &Evaluator{}
	cases := []struct {
		limit    string
		authMode string
		want     bool
		reason   string
	}{
		// Cost-based limits: advisory under non-api_key
		{"maxSpendUSD", "subscription", true, "spend under subscription is unenforceable"},
		{"maxTokensIn", "subscription", true, "token-in undercounts under subscription"},
		{"maxTokensOut", "subscription", true, "token-out undercounts under subscription"},
		{"maxSpendUSD", "unknown", true, "unknown auth defaults to advisory"},
		{"maxTokensIn", "", true, "empty auth string defaults to advisory"},
		// Cost-based limits: enforced under api_key
		{"maxSpendUSD", "api_key", false, "spend under api_key is the actual bill"},
		{"maxTokensIn", "api_key", false, "token-in under api_key is real billing"},
		{"maxTokensOut", "api_key", false, "token-out under api_key is real billing"},
		// Non-cost limits: enforced regardless of auth mode
		{"maxTurns", "subscription", false, "turns count accurately in JSONL under both modes"},
		{"maxTurns", "api_key", false, "turns count accurately in JSONL under both modes"},
		{"maxToolCalls", "subscription", false, "tool calls are tracked by aflock directly"},
		{"maxToolCalls", "api_key", false, "tool calls are tracked by aflock directly"},
	}
	for _, c := range cases {
		t.Run(c.limit+"/"+c.authMode, func(t *testing.T) {
			got := e.IsAdvisoryLimit(c.limit, c.authMode)
			if got != c.want {
				t.Errorf("IsAdvisoryLimit(%q, %q) = %v, want %v (%s)",
					c.limit, c.authMode, got, c.want, c.reason)
			}
		})
	}
}

// TestIsAdvisoryLimit_UnknownLimitName guards against silent advisory
// promotion for limits we don't recognize. If a future limit is added
// to the policy schema but not added to IsAdvisoryLimit's switch, it
// stays enforced (false) — safer default than silently letting it
// through.
func TestIsAdvisoryLimit_UnknownLimitName(t *testing.T) {
	e := &Evaluator{}
	for _, mode := range []string{"api_key", "subscription", "unknown", ""} {
		if e.IsAdvisoryLimit("maxBananas", mode) {
			t.Errorf("unknown limit name should not become advisory under mode %q", mode)
		}
	}
}
