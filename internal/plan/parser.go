// Package plan parses Claude plan markdown files and generates aflock policies.
package plan

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ParsedPlan represents structured data extracted from a Claude plan markdown file.
type ParsedPlan struct {
	Name               string       // Plan name from the first H1 heading
	DeterministicSteps []StepDef    // Steps like lint, test, build with commands
	UATSteps           []UATStepDef // UAT steps with AI evaluator prompts
	FilesModified      []string     // File paths mentioned in the plan
	AcceptanceCriteria []string     // Raw acceptance criteria text
}

// StepDef defines a deterministic verification step.
type StepDef struct {
	Name    string // Step identifier (e.g., "lint", "test", "build")
	Command string // Shell command to run (e.g., "npm run lint")
}

// UATStepDef defines a UAT step with AI evaluation.
type UATStepDef struct {
	Name   string // Step identifier (e.g., "uat-search")
	Prompt string // AI evaluator prompt (PASS/FAIL criteria)
	Model  string // Claude model (optional, defaults to claude-opus-4-5-20251101)
}

// ParseFile reads a Claude plan markdown file and extracts structured data.
func ParseFile(path string) (*ParsedPlan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read plan file: %w", err)
	}
	return Parse(string(data))
}

// Parse extracts structured data from Claude plan markdown content.
func Parse(content string) (*ParsedPlan, error) {
	plan := &ParsedPlan{}

	scanner := bufio.NewScanner(strings.NewReader(content))
	var currentSection string
	var inTable bool
	var tableHeaders []string
	var pendingLine string // line returned by scanForPrompt that needs re-processing

	for {
		var line string
		if pendingLine != "" {
			line = pendingLine
			pendingLine = ""
		} else {
			if !scanner.Scan() {
				break
			}
			line = scanner.Text()
		}
		trimmed := strings.TrimSpace(line)

		// Extract plan name from first H1
		if plan.Name == "" && strings.HasPrefix(trimmed, "# ") && !strings.HasPrefix(trimmed, "## ") {
			plan.Name = strings.TrimPrefix(trimmed, "# ")
			continue
		}

		// Track current section by headings
		if strings.HasPrefix(trimmed, "## ") || strings.HasPrefix(trimmed, "### ") {
			currentSection = normalizeSectionName(trimmed)
			inTable = false
			tableHeaders = nil

			// Check if heading itself is a UAT step definition (### uat-inbox)
			heading := extractHeadingText(trimmed)
			if strings.HasPrefix(heading, "uat-") {
				// Next lines might contain the prompt
				prompt, unconsumed := scanForPrompt(scanner)
				if prompt != "" {
					plan.UATSteps = append(plan.UATSteps, UATStepDef{
						Name:   heading,
						Prompt: prompt,
					})
				}
				if unconsumed != "" {
					pendingLine = unconsumed
				}
			}
			continue
		}

		// Detect table headers
		if strings.Contains(trimmed, "|") && !inTable {
			headers := parseTableRow(trimmed)
			if len(headers) >= 2 && isStepTable(headers) {
				tableHeaders = headers
				inTable = true
				continue
			}
		}

		// Skip table separator (|---|---|)
		if inTable && isTableSeparator(trimmed) {
			continue
		}

		// Parse table rows
		if inTable && strings.Contains(trimmed, "|") {
			cols := parseTableRow(trimmed)
			parseTableRowIntoPlan(plan, tableHeaders, cols)
			continue
		}

		// End of table
		if inTable && !strings.Contains(trimmed, "|") {
			inTable = false
			tableHeaders = nil
		}

		// Parse list items in relevant sections
		if (strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ")) && !inTable {
			listItem := strings.TrimPrefix(strings.TrimPrefix(trimmed, "- "), "* ")
			parseListItem(plan, currentSection, listItem)
		}

		// Extract file paths mentioned anywhere
		extractFilePaths(plan, trimmed)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan plan content: %w", err)
	}

	// If no name was found, derive from content
	if plan.Name == "" {
		plan.Name = "untitled-plan"
	}

	// Generate UAT steps from acceptance criteria if none were explicitly defined
	if len(plan.UATSteps) == 0 && len(plan.AcceptanceCriteria) > 0 {
		for i, criteria := range plan.AcceptanceCriteria {
			stepName := fmt.Sprintf("uat-%d", i+1)
			prompt := fmt.Sprintf("PASS if %s. FAIL otherwise.", strings.TrimSuffix(strings.TrimRight(criteria, "."), "."))
			plan.UATSteps = append(plan.UATSteps, UATStepDef{
				Name:   stepName,
				Prompt: prompt,
			})
		}
	}

	return plan, nil
}

// PlanSource groups discovered plans by their source directory.
type PlanSource struct {
	Dir   string   // Directory path
	Label string   // "project" or "global"
	Plans []string // Full paths to plan files
}

// ListPlans returns available plan files from both project-local .claude/plans/
// and global ~/.claude/plans/. Project-local plans are listed first.
func ListPlans() ([]PlanSource, error) {
	var sources []PlanSource

	// 1. Check project-local .claude/plans/ (relative to CWD)
	cwd, err := os.Getwd()
	if err == nil {
		localDir := filepath.Join(cwd, ".claude", "plans")
		if local := listPlansInDir(localDir); len(local) > 0 {
			sources = append(sources, PlanSource{
				Dir:   localDir,
				Label: "project",
				Plans: local,
			})
		}
	}

	// 2. Check global ~/.claude/plans/
	homeDir, err := os.UserHomeDir()
	if err != nil {
		if len(sources) > 0 {
			return sources, nil
		}
		return nil, fmt.Errorf("get home dir: %w", err)
	}

	globalDir := filepath.Join(homeDir, ".claude", "plans")
	if global := listPlansInDir(globalDir); len(global) > 0 {
		sources = append(sources, PlanSource{
			Dir:   globalDir,
			Label: "global",
			Plans: global,
		})
	}

	return sources, nil
}

// ListPlansInDir returns available plan files from a specific directory.
func ListPlansInDir(dir string) []string {
	return listPlansInDir(dir)
}

func listPlansInDir(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var plans []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") {
			plans = append(plans, filepath.Join(dir, entry.Name()))
		}
	}
	return plans
}

// normalizeSectionName normalizes a heading to a comparable section name.
func normalizeSectionName(heading string) string {
	heading = strings.TrimLeft(heading, "# ")
	heading = strings.ToLower(heading)
	heading = strings.TrimSpace(heading)
	return heading
}

// extractHeadingText extracts the text from a markdown heading.
func extractHeadingText(heading string) string {
	heading = strings.TrimLeft(heading, "# ")
	heading = strings.TrimSpace(heading)
	// Remove backticks
	heading = strings.Trim(heading, "`")
	return heading
}

// scanForPrompt reads ahead to find an AI policy prompt after a UAT heading.
// It returns the prompt (if found) and any unconsumed line that should be
// re-processed by the caller (e.g. a heading that belongs to the next section).
func scanForPrompt(scanner *bufio.Scanner) (string, string) {
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Look for "AI Policy Prompt:", "Prompt:", or quoted text
		if strings.Contains(line, "AI Policy Prompt") || strings.Contains(line, "Evaluator Prompt") {
			// Extract the prompt value after the colon
			if idx := strings.Index(line, ":"); idx != -1 {
				prompt := strings.TrimSpace(line[idx+1:])
				prompt = strings.Trim(prompt, "\"'")
				return prompt, ""
			}
		}
		// If line starts with "PASS if" or is a quoted string, treat as prompt
		if strings.HasPrefix(line, "PASS if") || strings.HasPrefix(line, "\"PASS") {
			return strings.Trim(line, "\"'"), ""
		}
		// If we hit another heading or non-prompt content, stop and return
		// the unconsumed line so the caller can re-process it
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "*") {
			return "", line
		}
	}
	return "", ""
}

// parseTableRow splits a markdown table row into column values.
func parseTableRow(line string) []string {
	line = strings.Trim(line, "|")
	parts := strings.Split(line, "|")
	var cols []string
	for _, part := range parts {
		col := strings.TrimSpace(part)
		col = strings.Trim(col, "`")
		cols = append(cols, col)
	}
	return cols
}

// isStepTable checks if table headers indicate a step definition table.
func isStepTable(headers []string) bool {
	for _, h := range headers {
		lower := strings.ToLower(h)
		if lower == "step" || lower == "steps" || lower == "name" {
			return true
		}
	}
	return false
}

// isTableSeparator checks if a line is a markdown table separator.
func isTableSeparator(line string) bool {
	cleaned := strings.ReplaceAll(line, "|", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, ":", "")
	cleaned = strings.TrimSpace(cleaned)
	return cleaned == ""
}

// parseTableRowIntoPlan parses a table row into the plan based on column headers.
func parseTableRowIntoPlan(plan *ParsedPlan, headers, cols []string) {
	if len(cols) == 0 {
		return
	}

	// Map columns by header name
	colMap := make(map[string]string)
	for i, h := range headers {
		if i < len(cols) {
			colMap[strings.ToLower(h)] = cols[i]
		}
	}

	stepName := firstNonEmpty(colMap["step"], colMap["steps"], colMap["name"])
	if stepName == "" {
		return
	}
	stepName = strings.Trim(stepName, "`\"' ")

	command := firstNonEmpty(colMap["command"], colMap["cmd"], colMap["description"])
	prompt := firstNonEmpty(colMap["ai evaluator prompt"], colMap["ai policy prompt"], colMap["prompt"], colMap["evaluator prompt"], colMap["acceptance criteria"])
	prompt = strings.Trim(prompt, "\"'")

	if strings.HasPrefix(stepName, "uat") && prompt != "" {
		plan.UATSteps = append(plan.UATSteps, UATStepDef{
			Name:   stepName,
			Prompt: prompt,
		})
	} else if stepName != "" {
		plan.DeterministicSteps = append(plan.DeterministicSteps, StepDef{
			Name:    stepName,
			Command: command,
		})
	}
}

// parseListItem parses a list item based on the current section.
func parseListItem(plan *ParsedPlan, section, item string) {
	switch {
	case containsAny(section, "deterministic", "steps", "commands", "validation"):
		// Parse "lint: npm run lint" or "- lint" format
		if parts := strings.SplitN(item, ":", 2); len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			cmd := strings.TrimSpace(parts[1])
			plan.DeterministicSteps = append(plan.DeterministicSteps, StepDef{
				Name:    name,
				Command: cmd,
			})
		}
	case containsAny(section, "uat", "acceptance", "criteria", "scenarios", "verification"):
		plan.AcceptanceCriteria = append(plan.AcceptanceCriteria, item)
	case containsAny(section, "files", "modified", "created"):
		// File paths in lists
		path := extractPathFromListItem(item)
		if path != "" {
			plan.FilesModified = append(plan.FilesModified, path)
		}
	}
}

// filePathRegex matches common file path patterns.
var filePathRegex = regexp.MustCompile(`(?:^|[\s\x60])([a-zA-Z0-9_./-]+\.[a-zA-Z0-9]+)`)

// extractFilePaths finds file paths mentioned in a line.
func extractFilePaths(plan *ParsedPlan, line string) {
	matches := filePathRegex.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) > 1 {
			path := match[1]
			// Filter to likely source paths
			if isLikelySourcePath(path) {
				if !containsString(plan.FilesModified, path) {
					plan.FilesModified = append(plan.FilesModified, path)
				}
			}
		}
	}
}

// isLikelySourcePath checks if a path looks like a source code file.
func isLikelySourcePath(path string) bool {
	ext := filepath.Ext(path)
	switch ext {
	case ".go", ".js", ".ts", ".tsx", ".jsx", ".py", ".rs", ".java", ".rb", ".c", ".cpp", ".h":
		return true
	case ".json", ".yaml", ".yml", ".toml", ".md":
		// Only if they look like project files
		return strings.Contains(path, "/")
	}
	return false
}

// extractPathFromListItem extracts a file path from a list item like "internal/policy/evaluator.go | Add symlink..."
func extractPathFromListItem(item string) string {
	// Handle "path | description" or "path — description" format
	for _, sep := range []string{"|", "—", "–", " - "} {
		if idx := strings.Index(item, sep); idx != -1 {
			candidate := strings.TrimSpace(item[:idx])
			candidate = strings.Trim(candidate, "`\"'")
			if isLikelySourcePath(candidate) {
				return candidate
			}
		}
	}
	// Try the whole item
	candidate := strings.Trim(strings.TrimSpace(item), "`\"'")
	if isLikelySourcePath(candidate) {
		return candidate
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func containsAny(s string, substrs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
