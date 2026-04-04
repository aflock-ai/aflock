package plan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// GenerateOptions controls policy generation behavior.
type GenerateOptions struct {
	// MergeWith is an existing policy to merge steps/evaluators into.
	// If nil, a new policy is created from scratch.
	MergeWith *aflock.Policy

	// OutputPath is where the generated policy will be written.
	OutputPath string

	// DefaultModel is the AI model for evaluators (default: claude-opus-4-5-20251101).
	DefaultModel string

	// InferFileRules generates files.allow from the plan's modified files.
	InferFileRules bool

	// DefaultLimits adds sensible default limits.
	DefaultLimits bool
}

// GeneratePolicy converts a parsed plan into an aflock policy.
func GeneratePolicy(plan *ParsedPlan, opts GenerateOptions) (*aflock.Policy, error) {
	if opts.DefaultModel == "" {
		opts.DefaultModel = "claude-opus-4-5-20251101"
	}

	var pol *aflock.Policy
	if opts.MergeWith != nil {
		pol = opts.MergeWith
	} else {
		pol = newBasePolicy(plan.Name, opts)
	}

	// Add deterministic steps
	if pol.Steps == nil {
		pol.Steps = make(map[string]aflock.Step)
	}
	for _, step := range plan.DeterministicSteps {
		pol.Steps[step.Name] = aflock.Step{
			Name: step.Name,
			Attestations: []aflock.StepAttestation{{
				Type: "https://aflock.ai/attestations/command-run/v0.1",
			}},
		}
		addRequiredAttestation(pol, step.Name)
	}

	// Add UAT steps with AI evaluators
	for _, uat := range plan.UATSteps {
		pol.Steps[uat.Name] = aflock.Step{
			Name: uat.Name,
			Attestations: []aflock.StepAttestation{{
				Type: "https://aflock.ai/attestations/command-run/v0.1",
			}},
		}
		addRequiredAttestation(pol, uat.Name)

		// Add AI evaluator
		model := uat.Model
		if model == "" {
			model = opts.DefaultModel
		}
		addAIEvaluator(pol, uat.Name, uat.Prompt, model)
	}

	// Infer file rules from modified files
	if opts.InferFileRules && len(plan.FilesModified) > 0 {
		inferFileRules(pol, plan.FilesModified)
	}

	// Set attestation directory and attestationsFrom if steps exist
	if len(pol.Steps) > 0 && pol.AttestationDir == "" {
		pol.AttestationDir = "./attestations"
		// Build attestationsFrom globs from step prefixes
		hasUAT := false
		hasDeterministic := false
		for name := range pol.Steps {
			if strings.HasPrefix(name, "uat") {
				hasUAT = true
			} else {
				hasDeterministic = true
			}
		}
		var from []string
		from = append(from, "turn-*")
		if hasDeterministic {
			from = append(from, "test-*")
		}
		if hasUAT {
			from = append(from, "uat-*")
		}
		pol.AttestationsFrom = from
	}

	return pol, nil
}

// GeneratePolicyJSON generates a policy and returns it as formatted JSON.
func GeneratePolicyJSON(plan *ParsedPlan, opts GenerateOptions) ([]byte, error) {
	pol, err := GeneratePolicy(plan, opts)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(pol, "", "  ")
}

// WritePolicy generates a policy and writes it to the output path.
func WritePolicy(plan *ParsedPlan, opts GenerateOptions) (string, error) {
	data, err := GeneratePolicyJSON(plan, opts)
	if err != nil {
		return "", fmt.Errorf("generate policy: %w", err)
	}

	outputPath := opts.OutputPath
	if outputPath == "" {
		outputPath = ".aflock"
	}

	// Ensure parent directory exists
	if dir := filepath.Dir(outputPath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", fmt.Errorf("create output directory: %w", err)
		}
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return "", fmt.Errorf("write policy: %w", err)
	}

	return outputPath, nil
}

func newBasePolicy(name string, opts GenerateOptions) *aflock.Policy {
	// Sanitize name for policy
	policyName := strings.ToLower(name)
	policyName = strings.ReplaceAll(policyName, " ", "-")
	// Remove non-alphanumeric chars except hyphens
	var cleaned []byte
	for _, c := range []byte(policyName) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			cleaned = append(cleaned, c)
		}
	}
	policyName = string(cleaned)
	if policyName == "" {
		policyName = "plan-policy"
	}

	expiry := time.Now().AddDate(1, 0, 0)
	pol := &aflock.Policy{
		Version:              "1.0",
		Name:                 policyName,
		Expires:              &expiry,
		Steps:                make(map[string]aflock.Step),
		RequiredAttestations: []string{},
	}

	// Add default tool rules
	pol.Tools = &aflock.ToolsPolicy{
		Allow: []string{"Read", "Edit", "Write", "Glob", "Grep", "Bash", "LSP"},
		Deny:  []string{},
	}

	// Add default file rules
	pol.Files = &aflock.FilesPolicy{
		Deny: []string{"**/.env", "**/secrets/**"},
	}

	// Add default limits
	if opts.DefaultLimits {
		pol.Limits = &aflock.LimitsPolicy{
			MaxSpendUSD: &aflock.Limit{Value: 10.00, Enforcement: "fail-fast"},
			MaxTurns:    &aflock.Limit{Value: 50, Enforcement: "post-hoc"},
		}
	}

	return pol
}

func addRequiredAttestation(pol *aflock.Policy, name string) {
	for _, existing := range pol.RequiredAttestations {
		if existing == name {
			return
		}
	}
	pol.RequiredAttestations = append(pol.RequiredAttestations, name)
}

func addAIEvaluator(pol *aflock.Policy, name, prompt, model string) {
	if pol.Evaluators == nil {
		pol.Evaluators = &aflock.EvaluatorsPolicy{}
	}

	// Check for duplicate
	for _, existing := range pol.Evaluators.AI {
		if existing.Name == name {
			return
		}
	}

	pol.Evaluators.AI = append(pol.Evaluators.AI, aflock.AIEvaluator{
		Name:   name,
		Prompt: prompt,
		Model:  model,
	})
}

func inferFileRules(pol *aflock.Policy, files []string) {
	if pol.Files == nil {
		pol.Files = &aflock.FilesPolicy{}
	}

	// Extract unique directory prefixes for allow rules
	dirs := make(map[string]bool)
	for _, f := range files {
		dir := filepath.Dir(f)
		if dir == "." {
			continue
		}
		// Use the top-level directory with glob
		parts := strings.SplitN(dir, "/", 2)
		dirs[parts[0]+"/**"] = true
	}

	for dir := range dirs {
		if !containsString(pol.Files.Allow, dir) {
			pol.Files.Allow = append(pol.Files.Allow, dir)
		}
	}
}
