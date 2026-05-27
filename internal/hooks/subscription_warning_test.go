package hooks

import (
	"strings"
	"testing"

	"github.com/aflock-ai/aflock/internal/auth/claudeauth"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// TestSubscriptionAdvisoryWarning_PrintsUnderSubscription pins the
// SessionStart upfront warning called for by issue #111: when claude-code
// is using subscription billing and the policy declares maxSpendUSD,
// the user must see the advisory note before any tool runs.
func TestSubscriptionAdvisoryWarning_PrintsUnderSubscription(t *testing.T) {
	pol := &aflock.Policy{
		Name: "warn-fixture",
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD: &aflock.Limit{Value: 10.0, Enforcement: "fail-fast"},
		},
	}
	msg := subscriptionAdvisoryWarning(pol, string(claudeauth.ModeSubscription))
	if !strings.Contains(msg, "advisory only") {
		t.Errorf("expected 'advisory only' in warning, got %q", msg)
	}
	if !strings.Contains(msg, "maxSpendUSD") {
		t.Errorf("expected limit name in warning, got %q", msg)
	}
	if !strings.Contains(msg, string(claudeauth.ModeSubscription)) {
		t.Errorf("expected mode label in warning, got %q", msg)
	}
}

// TestSubscriptionAdvisoryWarning_SilentUnderAPIKey — when running
// under api_key billing the warning must NOT fire, since maxSpendUSD
// is authoritatively enforced and the message would mislead users.
func TestSubscriptionAdvisoryWarning_SilentUnderAPIKey(t *testing.T) {
	pol := &aflock.Policy{
		Name: "warn-fixture",
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD: &aflock.Limit{Value: 10.0, Enforcement: "fail-fast"},
		},
	}
	if msg := subscriptionAdvisoryWarning(pol, string(claudeauth.ModeAPIKey)); msg != "" {
		t.Errorf("expected silent under api_key, got %q", msg)
	}
}

// TestSubscriptionAdvisoryWarning_SilentWithoutMaxSpendUSD — the
// warning is specifically about cost. A policy that only declares
// token/turn limits has nothing to flag because those stay enforced
// under both auth modes per #127's IsAdvisoryLimit design.
func TestSubscriptionAdvisoryWarning_SilentWithoutMaxSpendUSD(t *testing.T) {
	pol := &aflock.Policy{
		Name: "tokens-only",
		Limits: &aflock.LimitsPolicy{
			MaxTokensIn: &aflock.Limit{Value: 500_000, Enforcement: "fail-fast"},
			MaxTurns:    &aflock.Limit{Value: 50, Enforcement: "post-hoc"},
		},
	}
	if msg := subscriptionAdvisoryWarning(pol, string(claudeauth.ModeSubscription)); msg != "" {
		t.Errorf("expected silent without maxSpendUSD, got %q", msg)
	}
}

// TestSubscriptionAdvisoryWarning_NilPolicy guards the degenerate
// inputs so a missing or limit-less policy never panics.
func TestSubscriptionAdvisoryWarning_NilPolicy(t *testing.T) {
	if msg := subscriptionAdvisoryWarning(nil, string(claudeauth.ModeSubscription)); msg != "" {
		t.Errorf("expected silent for nil policy, got %q", msg)
	}
	if msg := subscriptionAdvisoryWarning(&aflock.Policy{}, string(claudeauth.ModeSubscription)); msg != "" {
		t.Errorf("expected silent for policy without limits, got %q", msg)
	}
}

// TestSubscriptionAdvisoryWarning_UnknownModeBehavesLikeSubscription —
// claudeauth.Detect returns ModeUnknown when no signal resolves. The
// safe behavior is to surface the advisory rather than silently
// implying enforcement, matching the policy that ModeUnknown should be
// treated as subscription-equivalent (see claudeauth/detect.go).
func TestSubscriptionAdvisoryWarning_UnknownModeBehavesLikeSubscription(t *testing.T) {
	pol := &aflock.Policy{
		Name: "warn-fixture",
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD: &aflock.Limit{Value: 10.0, Enforcement: "fail-fast"},
		},
	}
	if msg := subscriptionAdvisoryWarning(pol, string(claudeauth.ModeUnknown)); msg == "" {
		t.Errorf("expected warning under ModeUnknown, got empty string")
	}
}
