package plan

import (
	"testing"
)

func TestParse_TableFormat(t *testing.T) {
	content := `# Weather Dashboard Plan

## Deterministic Steps

| Step | Command |
|------|---------|
| lint | npm run lint |
| test | npm test |
| build | npm run build |

## UAT Test Scenarios

| Step | AI Evaluator Prompt |
|------|---------------------|
| uat-search | "PASS if frames show: search input with city name typed, search action, weather results displayed for that city" |
| uat-forecast | "PASS if frames show 5-day forecast with daily temperatures" |
`

	plan, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if plan.Name != "Weather Dashboard Plan" {
		t.Errorf("Name = %q, want %q", plan.Name, "Weather Dashboard Plan")
	}

	if len(plan.DeterministicSteps) != 3 {
		t.Fatalf("DeterministicSteps = %d, want 3", len(plan.DeterministicSteps))
	}
	if plan.DeterministicSteps[0].Name != "lint" {
		t.Errorf("Step[0].Name = %q, want %q", plan.DeterministicSteps[0].Name, "lint")
	}
	if plan.DeterministicSteps[0].Command != "npm run lint" {
		t.Errorf("Step[0].Command = %q, want %q", plan.DeterministicSteps[0].Command, "npm run lint")
	}
	if plan.DeterministicSteps[2].Name != "build" {
		t.Errorf("Step[2].Name = %q, want %q", plan.DeterministicSteps[2].Name, "build")
	}

	if len(plan.UATSteps) != 2 {
		t.Fatalf("UATSteps = %d, want 2", len(plan.UATSteps))
	}
	if plan.UATSteps[0].Name != "uat-search" {
		t.Errorf("UAT[0].Name = %q, want %q", plan.UATSteps[0].Name, "uat-search")
	}
	if plan.UATSteps[0].Prompt == "" {
		t.Error("UAT[0].Prompt is empty")
	}
	if plan.UATSteps[1].Name != "uat-forecast" {
		t.Errorf("UAT[1].Name = %q, want %q", plan.UATSteps[1].Name, "uat-forecast")
	}
}

func TestParse_ListFormat(t *testing.T) {
	content := `# Todo App Feature

## Deterministic Steps
- lint: npm run lint
- test: npm test
- build: npm run build

## Acceptance Criteria
- Search page shows results when user types a query
- 5-day forecast displays daily temperatures
`

	plan, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if plan.Name != "Todo App Feature" {
		t.Errorf("Name = %q, want %q", plan.Name, "Todo App Feature")
	}

	if len(plan.DeterministicSteps) != 3 {
		t.Fatalf("DeterministicSteps = %d, want 3", len(plan.DeterministicSteps))
	}
	if plan.DeterministicSteps[1].Name != "test" {
		t.Errorf("Step[1].Name = %q, want %q", plan.DeterministicSteps[1].Name, "test")
	}
	if plan.DeterministicSteps[1].Command != "npm test" {
		t.Errorf("Step[1].Command = %q, want %q", plan.DeterministicSteps[1].Command, "npm test")
	}

	// Acceptance criteria should generate UAT steps
	if len(plan.UATSteps) != 2 {
		t.Fatalf("UATSteps = %d, want 2", len(plan.UATSteps))
	}
	if plan.UATSteps[0].Name != "uat-1" {
		t.Errorf("UAT[0].Name = %q, want %q", plan.UATSteps[0].Name, "uat-1")
	}
	if plan.UATSteps[0].Prompt == "" {
		t.Error("UAT[0].Prompt is empty")
	}
}

func TestParse_SectionFormat(t *testing.T) {
	content := `# Email Client

## UAT Scenarios

### uat-inbox
**AI Policy Prompt**: PASS if frames show email inbox with list of emails

### uat-compose
**AI Policy Prompt**: PASS if frames show compose window with to, subject, body fields
`

	plan, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(plan.UATSteps) != 2 {
		t.Fatalf("UATSteps = %d, want 2", len(plan.UATSteps))
	}
	if plan.UATSteps[0].Name != "uat-inbox" {
		t.Errorf("UAT[0].Name = %q, want %q", plan.UATSteps[0].Name, "uat-inbox")
	}
	if plan.UATSteps[0].Prompt != "PASS if frames show email inbox with list of emails" {
		t.Errorf("UAT[0].Prompt = %q", plan.UATSteps[0].Prompt)
	}
	if plan.UATSteps[1].Name != "uat-compose" {
		t.Errorf("UAT[1].Name = %q, want %q", plan.UATSteps[1].Name, "uat-compose")
	}
}

func TestParse_FileExtraction(t *testing.T) {
	content := `# Fix Path Traversal

## Files Modified
- internal/policy/evaluator.go | Add symlink resolution
- internal/policy/bash_analyzer.go | Add file arg extraction

## Implementation
Modify ` + "`internal/policy/matcher.go`" + ` to add new patterns.
`

	plan, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(plan.FilesModified) < 2 {
		t.Fatalf("FilesModified = %d, want >= 2", len(plan.FilesModified))
	}

	found := false
	for _, f := range plan.FilesModified {
		if f == "internal/policy/evaluator.go" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("FilesModified missing 'internal/policy/evaluator.go', got %v", plan.FilesModified)
	}
}

func TestParse_MixedTable(t *testing.T) {
	// Table with both deterministic and UAT steps
	content := `# Dashboard

## Steps

| Step | Command | AI Evaluator Prompt |
|------|---------|---------------------|
| lint | npm run lint | |
| test | npm test | |
| uat-search | | "PASS if search works correctly" |
`

	plan, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(plan.DeterministicSteps) != 2 {
		t.Errorf("DeterministicSteps = %d, want 2", len(plan.DeterministicSteps))
	}
	if len(plan.UATSteps) != 1 {
		t.Errorf("UATSteps = %d, want 1", len(plan.UATSteps))
	}
}

func TestParse_EmptyContent(t *testing.T) {
	plan, err := Parse("")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if plan.Name != "untitled-plan" {
		t.Errorf("Name = %q, want %q", plan.Name, "untitled-plan")
	}
	if len(plan.DeterministicSteps) != 0 {
		t.Errorf("DeterministicSteps = %d, want 0", len(plan.DeterministicSteps))
	}
}

func TestParse_ScanForPromptDoesNotConsumeNextHeading(t *testing.T) {
	// When a UAT heading has no prompt, scanForPrompt should return the next
	// heading as an unconsumed line so it gets re-processed. Previously,
	// scanForPrompt consumed the "### uat-inbox" heading while scanning for
	// uat-empty's prompt, causing uat-inbox to be silently dropped.
	content := `# Email Client

## UAT Scenarios

### uat-empty
Some text without a prompt

### uat-inbox
**AI Policy Prompt**: PASS if inbox shows emails

### uat-compose
**AI Policy Prompt**: PASS if compose window shows fields
`

	plan, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(plan.UATSteps) != 2 {
		t.Fatalf("UATSteps = %d, want 2; got %+v", len(plan.UATSteps), plan.UATSteps)
	}

	// uat-empty has no prompt, so it should NOT appear in UATSteps
	for _, step := range plan.UATSteps {
		if step.Name == "uat-empty" {
			t.Errorf("uat-empty should not be in UATSteps (it has no prompt), got %+v", step)
		}
	}

	if plan.UATSteps[0].Name != "uat-inbox" {
		t.Errorf("UAT[0].Name = %q, want %q", plan.UATSteps[0].Name, "uat-inbox")
	}
	if plan.UATSteps[0].Prompt != "PASS if inbox shows emails" {
		t.Errorf("UAT[0].Prompt = %q, want %q", plan.UATSteps[0].Prompt, "PASS if inbox shows emails")
	}

	if plan.UATSteps[1].Name != "uat-compose" {
		t.Errorf("UAT[1].Name = %q, want %q", plan.UATSteps[1].Name, "uat-compose")
	}
	if plan.UATSteps[1].Prompt != "PASS if compose window shows fields" {
		t.Errorf("UAT[1].Prompt = %q, want %q", plan.UATSteps[1].Prompt, "PASS if compose window shows fields")
	}
}

func TestParse_RealWorldPlan(t *testing.T) {
	// Simulates a real Claude plan with mixed content
	content := `# Add Search Feature to Todo App

## Context
Users need to search their todos by title and tags.

## Implementation Steps

### Step 1: Add search component
Create src/components/Search.tsx with input field and results list.

### Step 2: Add search API
Add search endpoint to src/api/todos.ts.

### Step 3: Write tests
Add tests in tests/search.test.ts.

## Deterministic Steps
- lint: npm run lint
- test: npm test
- build: npm run build

## Acceptance Criteria
- Search input is visible on the main page
- Typing a query filters todos by title
- Clearing search shows all todos again
- Empty search state shows helpful message

## Files Modified/Created

| File | Action |
|------|--------|
| src/components/Search.tsx | NEW |
| src/api/todos.ts | EDIT |
| tests/search.test.ts | NEW |
`

	plan, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if plan.Name != "Add Search Feature to Todo App" {
		t.Errorf("Name = %q", plan.Name)
	}

	if len(plan.DeterministicSteps) != 3 {
		t.Errorf("DeterministicSteps = %d, want 3", len(plan.DeterministicSteps))
	}

	// 4 acceptance criteria → 4 UAT steps
	if len(plan.UATSteps) != 4 {
		t.Errorf("UATSteps = %d, want 4", len(plan.UATSteps))
	}

	if len(plan.FilesModified) < 3 {
		t.Errorf("FilesModified = %d, want >= 3", len(plan.FilesModified))
	}
}
