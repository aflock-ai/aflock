package policy

import (
	"encoding/json"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// The cryptographic card-verification path is covered by internal/a2a tests;
// these cover the policy gate around it: endpoint classification, the
// requireSignedCard decision, and URL extraction from tool inputs.

func agentsPolicy(ap *aflock.AgentsPolicy) *aflock.Policy {
	return &aflock.Policy{Version: "1.0", Name: "a2a-test", Agents: ap}
}

func webFetchInput(t *testing.T, url string) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(aflock.WebFetchToolInput{URL: url})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAgentGate_NoAgentsSectionAllows(t *testing.T) {
	e := NewEvaluator(agentsPolicy(nil), "")
	decision, _, material := e.EvaluateAgentConnection("WebFetch", webFetchInput(t, "https://agents.partner.example/a2a/v1"))
	if decision != aflock.DecisionAllow || material != nil {
		t.Fatalf("no agents section must be a no-op, got %v %v", decision, material)
	}
}

func TestAgentGate_NonMatchingEndpointAllows(t *testing.T) {
	e := NewEvaluator(agentsPolicy(&aflock.AgentsPolicy{
		Endpoints:         []string{"agents.partner.example"},
		RequireSignedCard: true,
	}), "")
	decision, _, material := e.EvaluateAgentConnection("WebFetch", webFetchInput(t, "https://api.anthropic.com/v1/messages"))
	if decision != aflock.DecisionAllow || material != nil {
		t.Fatalf("non-agent endpoint must pass through, got %v %v", decision, material)
	}
}

func TestAgentGate_RequireSignedCardDeniesWithoutCard(t *testing.T) {
	e := NewEvaluator(agentsPolicy(&aflock.AgentsPolicy{
		Endpoints:         []string{"agents.partner.example"},
		RequireSignedCard: true,
	}), "")
	decision, reason, _ := e.EvaluateAgentConnection("WebFetch", webFetchInput(t, "https://agents.partner.example/a2a/v1"))
	if decision != aflock.DecisionDeny {
		t.Fatalf("agent endpoint without a pinned card must be denied, got %v (%s)", decision, reason)
	}
}

func TestAgentGate_UnverifiedAllowedLeavesTrace(t *testing.T) {
	e := NewEvaluator(agentsPolicy(&aflock.AgentsPolicy{
		Endpoints: []string{"agents.partner.example"},
		// RequireSignedCard false: connection allowed, but recorded.
	}), "")
	decision, _, material := e.EvaluateAgentConnection("WebFetch", webFetchInput(t, "https://agents.partner.example/a2a/v1"))
	if decision != aflock.DecisionAllow {
		t.Fatalf("decision = %v, want allow", decision)
	}
	if material == nil || material.Label != "agent-connection" {
		t.Fatalf("unverified agent connection must leave a material trace, got %+v", material)
	}
}

func TestAgentGate_MissingCardFileDenies(t *testing.T) {
	e := NewEvaluator(agentsPolicy(&aflock.AgentsPolicy{
		Endpoints:         []string{"agents.partner.example"},
		RequireSignedCard: true,
		Cards:             map[string]string{"partner": "does-not-exist.json"},
	}), t.TempDir())
	decision, reason, _ := e.EvaluateAgentConnection("WebFetch", webFetchInput(t, "https://agents.partner.example/a2a/v1"))
	if decision != aflock.DecisionDeny {
		t.Fatalf("unreadable card must fail closed, got %v (%s)", decision, reason)
	}
}

func TestAgentGate_BashURLExtraction(t *testing.T) {
	e := NewEvaluator(agentsPolicy(&aflock.AgentsPolicy{
		Endpoints:         []string{"agents.partner.example"},
		RequireSignedCard: true,
	}), "")
	input, err := json.Marshal(aflock.BashToolInput{Command: `curl -s "https://agents.partner.example/a2a/v1" | jq .`})
	if err != nil {
		t.Fatal(err)
	}
	decision, _, _ := e.EvaluateAgentConnection("Bash", input)
	if decision != aflock.DecisionDeny {
		t.Fatalf("bash curl to an agent endpoint must hit the gate, got %v", decision)
	}
}
