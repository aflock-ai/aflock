package mcp

import (
	"strings"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

func TestValidateMCPLimits_NilPolicy(t *testing.T) {
	if err := validateMCPLimits(nil); err != nil {
		t.Errorf("nil policy should pass, got %v", err)
	}
}

func TestValidateMCPLimits_NoLimits(t *testing.T) {
	p := &aflock.Policy{Name: "no-limits"}
	if err := validateMCPLimits(p); err != nil {
		t.Errorf("policy without limits should pass, got %v", err)
	}
}

func TestValidateMCPLimits_FailFast_Refuses(t *testing.T) {
	cases := []struct {
		name   string
		policy *aflock.Policy
	}{
		{
			name: "explicit fail-fast on maxSpendUSD",
			policy: &aflock.Policy{Limits: &aflock.LimitsPolicy{
				MaxSpendUSD: &aflock.Limit{Value: 5, Enforcement: "fail-fast"},
			}},
		},
		{
			name: "empty enforcement on maxTurns (treated as fail-fast)",
			policy: &aflock.Policy{Limits: &aflock.LimitsPolicy{
				MaxTurns: &aflock.Limit{Value: 50, Enforcement: ""},
			}},
		},
		{
			name: "fail-fast on maxTokensIn",
			policy: &aflock.Policy{Limits: &aflock.LimitsPolicy{
				MaxTokensIn: &aflock.Limit{Value: 1000, Enforcement: "fail-fast"},
			}},
		},
		{
			name: "fail-fast on maxTokensOut",
			policy: &aflock.Policy{Limits: &aflock.LimitsPolicy{
				MaxTokensOut: &aflock.Limit{Value: 1000, Enforcement: "fail-fast"},
			}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateMCPLimits(c.policy)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "fail-fast") {
				t.Errorf("error should mention fail-fast, got %q", err.Error())
			}
			if !strings.Contains(err.Error(), "#94") {
				t.Errorf("error should reference issue #94, got %q", err.Error())
			}
		})
	}
}

func TestValidateMCPLimits_PostHoc_Allows(t *testing.T) {
	p := &aflock.Policy{Limits: &aflock.LimitsPolicy{
		MaxSpendUSD: &aflock.Limit{Value: 5, Enforcement: "post-hoc"},
		MaxTurns:    &aflock.Limit{Value: 50, Enforcement: "post-hoc"},
	}}
	if err := validateMCPLimits(p); err != nil {
		t.Errorf("post-hoc should be allowed, got %v", err)
	}
}

func TestValidateMCPLimits_SupportedLimits_Allows(t *testing.T) {
	// MaxToolCalls and MaxWallTimeSeconds increment correctly on the
	// MCP path; they must not trigger the bypass guard.
	p := &aflock.Policy{Limits: &aflock.LimitsPolicy{
		MaxToolCalls:       &aflock.Limit{Value: 100, Enforcement: "fail-fast"},
		MaxWallTimeSeconds: &aflock.Limit{Value: 600, Enforcement: "fail-fast"},
	}}
	if err := validateMCPLimits(p); err != nil {
		t.Errorf("supported limits should be allowed, got %v", err)
	}
}

func TestValidateMCPLimits_MultipleFailFast_Aggregated(t *testing.T) {
	p := &aflock.Policy{Limits: &aflock.LimitsPolicy{
		MaxSpendUSD: &aflock.Limit{Value: 5, Enforcement: "fail-fast"},
		MaxTurns:    &aflock.Limit{Value: 50, Enforcement: "fail-fast"},
	}}
	err := validateMCPLimits(p)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "maxSpendUSD") {
		t.Errorf("error should list maxSpendUSD, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "maxTurns") {
		t.Errorf("error should list maxTurns, got %q", err.Error())
	}
}

func TestValidateMCPLimits_MixedEnforcement(t *testing.T) {
	// One fail-fast (refuse) plus one post-hoc (warn) — error wins.
	p := &aflock.Policy{Limits: &aflock.LimitsPolicy{
		MaxSpendUSD: &aflock.Limit{Value: 5, Enforcement: "fail-fast"},
		MaxTurns:    &aflock.Limit{Value: 50, Enforcement: "post-hoc"},
	}}
	err := validateMCPLimits(p)
	if err == nil {
		t.Fatal("expected error from fail-fast, got nil")
	}
	if !strings.Contains(err.Error(), "maxSpendUSD") {
		t.Errorf("error should mention fail-fast limit, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "maxTurns") {
		t.Errorf("post-hoc limit should not appear in error, got %q", err.Error())
	}
}
