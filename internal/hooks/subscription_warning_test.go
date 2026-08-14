package hooks

import (
	"strings"
	"testing"

	"github.com/aflock-ai/aflock/internal/auth/claudeauth"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

func TestSubscriptionAdvisoryWarning(t *testing.T) {
	costPol := &aflock.Policy{
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD: &aflock.Limit{Value: 10.0, Enforcement: "fail-fast"},
		},
	}
	tokenOnly := &aflock.Policy{
		Limits: &aflock.LimitsPolicy{
			MaxTokensIn: &aflock.Limit{Value: 500_000, Enforcement: "fail-fast"},
		},
	}

	cases := []struct {
		name    string
		pol     *aflock.Policy
		mode    claudeauth.Mode
		wantMsg bool
	}{
		{"subscription + cost limit", costPol, claudeauth.ModeSubscription, true},
		{"unknown mode + cost limit", costPol, claudeauth.ModeUnknown, true},
		{"api_key + cost limit", costPol, claudeauth.ModeAPIKey, false},
		{"subscription + token-only", tokenOnly, claudeauth.ModeSubscription, false},
		{"nil policy", nil, claudeauth.ModeSubscription, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := subscriptionAdvisoryWarning(tc.pol, string(tc.mode))
			if tc.wantMsg && !strings.Contains(msg, "maxSpendUSD is advisory") {
				t.Errorf("want advisory message, got %q", msg)
			}
			if !tc.wantMsg && msg != "" {
				t.Errorf("want empty, got %q", msg)
			}
		})
	}
}
