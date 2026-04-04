package plan

import (
	"encoding/json"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

func TestGeneratePolicy_Basic(t *testing.T) {
	plan := &ParsedPlan{
		Name: "Weather Dashboard",
		DeterministicSteps: []StepDef{
			{Name: "lint", Command: "npm run lint"},
			{Name: "test", Command: "npm test"},
			{Name: "build", Command: "npm run build"},
		},
		UATSteps: []UATStepDef{
			{Name: "uat-search", Prompt: "PASS if frames show search input and results"},
			{Name: "uat-forecast", Prompt: "PASS if frames show 5-day forecast"},
		},
	}

	pol, err := GeneratePolicy(plan, GenerateOptions{})
	if err != nil {
		t.Fatalf("GeneratePolicy failed: %v", err)
	}

	// Check policy name
	if pol.Name != "weather-dashboard" {
		t.Errorf("Name = %q, want %q", pol.Name, "weather-dashboard")
	}

	// Check steps
	if len(pol.Steps) != 5 {
		t.Errorf("Steps = %d, want 5", len(pol.Steps))
	}
	if _, ok := pol.Steps["lint"]; !ok {
		t.Error("missing step: lint")
	}
	if _, ok := pol.Steps["uat-search"]; !ok {
		t.Error("missing step: uat-search")
	}

	// Check required attestations
	if len(pol.RequiredAttestations) != 5 {
		t.Errorf("RequiredAttestations = %d, want 5", len(pol.RequiredAttestations))
	}

	// Check AI evaluators
	if pol.Evaluators == nil {
		t.Fatal("Evaluators is nil")
	}
	if len(pol.Evaluators.AI) != 2 {
		t.Errorf("AI evaluators = %d, want 2", len(pol.Evaluators.AI))
	}
	if pol.Evaluators.AI[0].Name != "uat-search" {
		t.Errorf("AI[0].Name = %q, want %q", pol.Evaluators.AI[0].Name, "uat-search")
	}
	if pol.Evaluators.AI[0].Model != "claude-opus-4-5-20251101" {
		t.Errorf("AI[0].Model = %q", pol.Evaluators.AI[0].Model)
	}

	// Check attestation directory
	if pol.AttestationDir != "./attestations" {
		t.Errorf("AttestationDir = %q, want %q", pol.AttestationDir, "./attestations")
	}

	// Check attestationsFrom contains expected globs
	if len(pol.AttestationsFrom) == 0 {
		t.Error("AttestationsFrom is empty")
	}
	hasTurn := false
	hasTest := false
	hasUAT := false
	for _, af := range pol.AttestationsFrom {
		switch af {
		case "turn-*":
			hasTurn = true
		case "test-*":
			hasTest = true
		case "uat-*":
			hasUAT = true
		}
	}
	if !hasTurn {
		t.Error("AttestationsFrom missing turn-*")
	}
	if !hasTest {
		t.Error("AttestationsFrom missing test-*")
	}
	if !hasUAT {
		t.Error("AttestationsFrom missing uat-*")
	}
}

func TestGeneratePolicy_WithLimits(t *testing.T) {
	plan := &ParsedPlan{Name: "test"}

	pol, err := GeneratePolicy(plan, GenerateOptions{DefaultLimits: true})
	if err != nil {
		t.Fatalf("GeneratePolicy failed: %v", err)
	}

	if pol.Limits == nil {
		t.Fatal("Limits is nil")
	}
	if pol.Limits.MaxSpendUSD == nil {
		t.Fatal("MaxSpendUSD is nil")
	}
	if pol.Limits.MaxSpendUSD.Value != 10.00 {
		t.Errorf("MaxSpendUSD = %f, want 10.00", pol.Limits.MaxSpendUSD.Value)
	}
}

func TestGeneratePolicy_InferFileRules(t *testing.T) {
	plan := &ParsedPlan{
		Name: "test",
		FilesModified: []string{
			"src/components/Search.tsx",
			"src/api/todos.ts",
			"tests/search.test.ts",
		},
	}

	pol, err := GeneratePolicy(plan, GenerateOptions{InferFileRules: true})
	if err != nil {
		t.Fatalf("GeneratePolicy failed: %v", err)
	}

	if pol.Files == nil {
		t.Fatal("Files is nil")
	}
	if len(pol.Files.Allow) == 0 {
		t.Error("Files.Allow is empty")
	}

	// Should have src/** and tests/**
	hasSrc := false
	hasTests := false
	for _, a := range pol.Files.Allow {
		if a == "src/**" {
			hasSrc = true
		}
		if a == "tests/**" {
			hasTests = true
		}
	}
	if !hasSrc {
		t.Errorf("Files.Allow missing src/**, got %v", pol.Files.Allow)
	}
	if !hasTests {
		t.Errorf("Files.Allow missing tests/**, got %v", pol.Files.Allow)
	}
}

func TestGeneratePolicy_Merge(t *testing.T) {
	existing := &aflock.Policy{
		Version: "1.0",
		Name:    "existing-policy",
		Steps: map[string]aflock.Step{
			"security-scan": {Name: "security-scan"},
		},
		RequiredAttestations: []string{"security-scan"},
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read", "Edit"},
		},
	}

	plan := &ParsedPlan{
		Name: "New Feature",
		DeterministicSteps: []StepDef{
			{Name: "test", Command: "npm test"},
		},
		UATSteps: []UATStepDef{
			{Name: "uat-feature", Prompt: "PASS if feature works"},
		},
	}

	pol, err := GeneratePolicy(plan, GenerateOptions{MergeWith: existing})
	if err != nil {
		t.Fatalf("GeneratePolicy failed: %v", err)
	}

	// Should keep existing step
	if _, ok := pol.Steps["security-scan"]; !ok {
		t.Error("lost existing step: security-scan")
	}

	// Should add new steps
	if _, ok := pol.Steps["test"]; !ok {
		t.Error("missing new step: test")
	}
	if _, ok := pol.Steps["uat-feature"]; !ok {
		t.Error("missing new step: uat-feature")
	}

	// Should keep existing tool rules
	if pol.Tools == nil || len(pol.Tools.Allow) != 2 {
		t.Error("lost existing tool rules")
	}

	// Should have all attestations
	if len(pol.RequiredAttestations) != 3 {
		t.Errorf("RequiredAttestations = %d, want 3", len(pol.RequiredAttestations))
	}
}

func TestGeneratePolicyJSON_ValidJSON(t *testing.T) {
	plan := &ParsedPlan{
		Name: "Test Plan",
		DeterministicSteps: []StepDef{
			{Name: "test", Command: "go test ./..."},
		},
	}

	data, err := GeneratePolicyJSON(plan, GenerateOptions{})
	if err != nil {
		t.Fatalf("GeneratePolicyJSON failed: %v", err)
	}

	// Verify it's valid JSON
	var pol aflock.Policy
	if err := json.Unmarshal(data, &pol); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if pol.Name != "test-plan" {
		t.Errorf("Name = %q, want %q", pol.Name, "test-plan")
	}
}

func TestGeneratePolicy_EndToEnd(t *testing.T) {
	// Parse markdown → generate policy → verify output
	content := `# Search Feature

## Deterministic Steps
- lint: npm run lint
- test: npm test

## Acceptance Criteria
- Search input is visible on main page
- Typing a query filters results
`

	plan, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	pol, err := GeneratePolicy(plan, GenerateOptions{DefaultLimits: true})
	if err != nil {
		t.Fatalf("GeneratePolicy failed: %v", err)
	}

	// Verify steps
	if _, ok := pol.Steps["lint"]; !ok {
		t.Error("missing step: lint")
	}
	if _, ok := pol.Steps["test"]; !ok {
		t.Error("missing step: test")
	}

	// Verify UAT steps generated from acceptance criteria
	if _, ok := pol.Steps["uat-1"]; !ok {
		t.Error("missing step: uat-1")
	}
	if _, ok := pol.Steps["uat-2"]; !ok {
		t.Error("missing step: uat-2")
	}

	// Verify evaluators
	if pol.Evaluators == nil || len(pol.Evaluators.AI) != 2 {
		t.Errorf("expected 2 AI evaluators, got %v", pol.Evaluators)
	}

	// Verify serializable
	data, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var roundTrip aflock.Policy
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("roundtrip failed: %v", err)
	}
}
