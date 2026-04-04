// Package rego provides Rego policy evaluation for aflock's verification pipeline.
//
// It adapts the same OPA SDK patterns used by rookery's attestation/policy/rego.go
// but accepts raw JSON input instead of requiring rookery's Attestor interface.
// This enables top-level (cross-step) Rego evaluation where the input contains
// the full policy, all attestations, and session materials.
//
// Security controls (matching rookery):
//   - Blocked builtins: http.send, opa.runtime, net.lookup_ip_addr, net.cidr_*
//   - 30-second evaluation timeout
//   - StrictBuiltinErrors: fails on undefined builtin use
//   - Missing deny rule detection
package rego

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/open-policy-agent/opa/ast"  //nolint:staticcheck // TODO: migrate to opa/v1
	"github.com/open-policy-agent/opa/rego" //nolint:staticcheck // TODO: migrate to opa/v1
)

const evalTimeout = 30 * time.Second

// EvalResult contains the result of evaluating a single Rego policy.
type EvalResult struct {
	Name    string   `json:"name"`
	Passed  bool     `json:"passed"`
	Reasons []string `json:"reasons,omitempty"` // denial reasons if failed
}

// Evaluate runs a list of Rego policies against the given JSON input.
// Each policy must define a `deny` rule that returns a list of denial reason strings.
// Empty deny = pass. Non-empty deny = fail with reasons.
//
// The input is provided as raw JSON bytes and decoded with UseNumber() to preserve
// numeric precision (matching rookery's approach).
//
// Returns one EvalResult per policy, plus any fatal errors.
func Evaluate(policies []Policy, inputJSON []byte) ([]EvalResult, error) {
	if len(policies) == 0 {
		return nil, nil
	}

	// Decode input JSON with number preservation
	decoder := json.NewDecoder(bytes.NewReader(inputJSON))
	decoder.UseNumber()
	var input interface{}
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("decode input: %w", err)
	}

	var results []EvalResult

	for _, pol := range policies {
		result, err := evaluateOne(pol, input)
		if err != nil {
			return nil, fmt.Errorf("rego evaluator %q: %w", pol.Name, err)
		}
		results = append(results, *result)
	}

	return results, nil
}

// Policy represents a Rego policy to evaluate.
type Policy struct {
	Name   string // human-readable name
	Module string // Rego source code
}

// evaluateOne runs a single Rego policy against the input.
func evaluateOne(pol Policy, input interface{}) (*EvalResult, error) {
	parsedModule, err := ast.ParseModule(pol.Name, pol.Module)
	if err != nil {
		return nil, fmt.Errorf("parse rego module: %w", err)
	}

	query := fmt.Sprintf("%v.deny", parsedModule.Package.Path)

	r := rego.New(
		rego.Query(query),
		rego.ParsedModule(parsedModule),
		rego.Input(input),
		rego.Capabilities(restrictedCapabilities()),
		rego.StrictBuiltinErrors(true),
		rego.UnsafeBuiltins(unsafeBuiltins),
	)

	ctx, cancel := context.WithTimeout(context.Background(), evalTimeout)
	defer cancel()

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}

	// Security: empty result set means the deny rule is undefined.
	// This prevents silent bypass from malformed policy modules.
	if len(rs) == 0 {
		return nil, fmt.Errorf("policy %q returned no results: missing 'deny' rule", pol.Name)
	}

	var denyReasons []string
	for _, expr := range rs {
		for _, val := range expr.Expressions {
			reasons, ok := val.Value.([]interface{})
			if !ok {
				continue
			}
			for _, reason := range reasons {
				if s, ok := reason.(string); ok {
					denyReasons = append(denyReasons, s)
				}
			}
		}
	}

	return &EvalResult{
		Name:    pol.Name,
		Passed:  len(denyReasons) == 0,
		Reasons: denyReasons,
	}, nil
}

// unsafeBuiltins blocks dangerous OPA builtins that could allow
// data exfiltration or network access from Rego policies.
var unsafeBuiltins = map[string]struct{}{
	"http.send":           {},
	"opa.runtime":         {},
	"net.lookup_ip_addr":  {},
	"net.cidr_contains":   {},
	"net.cidr_intersects": {},
	"net.cidr_merge":      {},
	"net.cidr_expand":     {},
}

// restrictedCapabilities returns OPA capabilities with dangerous builtins removed.
func restrictedCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	filtered := make([]*ast.Builtin, 0, len(caps.Builtins))
	for _, b := range caps.Builtins {
		if _, blocked := unsafeBuiltins[b.Name]; !blocked {
			filtered = append(filtered, b)
		}
	}
	caps.Builtins = filtered
	return caps
}
