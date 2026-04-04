package replay

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aflock-ai/aflock/internal/policy"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Result is the policy evaluation result for a single action.
type Result struct {
	Action   Action
	Decision aflock.PermissionDecision
	Reason   string
}

// Report is the full replay output.
type Report struct {
	Session    *Session
	PolicyName string
	PolicyPath string
	Results    []Result
	AllowCount int
	DenyCount  int
	AskCount   int
}

// Run replays a parsed session against a policy and returns the report.
func Run(session *Session, pol *aflock.Policy, policyPath string) *Report {
	projectRoot := filepath.Dir(policyPath)
	evaluator := policy.NewEvaluator(pol, projectRoot)

	report := &Report{
		Session:    session,
		PolicyName: pol.Name,
		PolicyPath: policyPath,
	}

	for _, action := range session.Actions {
		decision, reason := evaluator.EvaluatePreToolUse(action.Tool, action.RawInput)

		result := Result{
			Action:   action,
			Decision: decision,
			Reason:   reason,
		}

		switch decision {
		case aflock.DecisionAllow:
			report.AllowCount++
		case aflock.DecisionDeny:
			report.DenyCount++
		case aflock.DecisionAsk:
			report.AskCount++
		}

		report.Results = append(report.Results, result)
	}

	return report
}

// FormatText renders the report as a human-readable text table.
func (r *Report) FormatText() string {
	var b strings.Builder

	// ANSI colors for header
	hGreen := "\033[32m"
	hRed := "\033[31m"
	hCyan := "\033[36m"
	hDim := "\033[90m"
	hBold := "\033[1m"
	hReset := "\033[0m"
	hPurple := "\033[35m"

	// Header
	fmt.Fprintf(&b, "%s%sAFLOCK REPLAY%s — %s%s%s\n", hBold, hPurple, hReset, hCyan, r.PolicyName, hReset)
	fmt.Fprintf(&b, "%s%s%s\n\n", hDim, strings.Repeat("━", 60), hReset)

	// Identity check
	modelCheck := hGreen + "✓" + hReset
	if r.Session.Model == "" || r.Session.Model == "unknown" {
		modelCheck = "?"
	}
	fmt.Fprintf(&b, "Model:  %s%-24s%s %s\n", hCyan, r.Session.Model, hReset, modelCheck)

	// Limits check
	if pol := r.loadPolicy(); pol != nil && pol.Limits != nil {
		if pol.Limits.MaxTurns != nil {
			turnCheck := hGreen + "✓" + hReset
			if float64(r.Session.Turns) > pol.Limits.MaxTurns.Value {
				turnCheck = hRed + "✗ EXCEEDED" + hReset
			}
			fmt.Fprintf(&b, "Turns:  %-24s %s\n",
				fmt.Sprintf("%d/%.0f", r.Session.Turns, pol.Limits.MaxTurns.Value), turnCheck)
		} else {
			fmt.Fprintf(&b, "Turns:  %d\n", r.Session.Turns)
		}
	} else {
		fmt.Fprintf(&b, "Turns:  %d\n", r.Session.Turns)
	}

	fmt.Fprintf(&b, "Calls:  %d\n", len(r.Session.Actions))
	fmt.Fprintf(&b, "Tokens: in=%d out=%d\n\n", r.Session.TokensIn, r.Session.TokensOut)

	// ANSI colors
	green := "\033[32m"
	red := "\033[31m"
	yellow := "\033[33m"
	cyan := "\033[36m"
	dim := "\033[90m"
	bold := "\033[1m"
	reset := "\033[0m"

	// Table header
	fmt.Fprintf(&b, "%s%-4s  %-10s  %-45s  %s%s\n",
		dim, "#", "TOOL", "INPUT", "DECISION", reset)
	fmt.Fprintf(&b, "%s%s%s\n", dim, strings.Repeat("─", 75), reset)

	// Determine the best root for shortening paths.
	// Use policy dir first, but also detect the session's working directory
	// from file paths (handles case where policy is in a different directory).
	policyRoot, _ := filepath.Abs(filepath.Dir(r.PolicyPath))
	sessionRoot := detectSessionRoot(r.Results)
	shortenRoot := policyRoot
	if sessionRoot != "" && sessionRoot != policyRoot {
		// Policy is in a different dir than where the session ran.
		// Use the session's CWD for shortening — it matches the file paths.
		shortenRoot = sessionRoot
	}

	for _, res := range r.Results {
		detail := shortenInput(res.Action.Tool, res.Action.InputDetail(), shortenRoot)
		if len(detail) > 45 {
			detail = detail[:42] + "..."
		}

		// Color the decision
		var decColor string
		switch res.Decision {
		case aflock.DecisionAllow:
			decColor = green
		case aflock.DecisionDeny:
			decColor = red
		case aflock.DecisionAsk:
			decColor = yellow
		default:
			decColor = dim
		}

		fmt.Fprintf(&b, "%-4d  %s%-10s%s  %-45s  %s%s%s\n",
			res.Action.Index,
			cyan, res.Action.Tool, reset,
			detail,
			decColor, string(res.Decision), reset)

		// Reason on second line for deny/ask only
		if res.Decision != aflock.DecisionAllow && res.Reason != "" {
			reason := shortenReason(res.Reason, shortenRoot)
			fmt.Fprintf(&b, "      %s↳ %s%s\n", dim, reason, reset)
		}
	}

	fmt.Fprintf(&b, "%s%s%s\n", dim, strings.Repeat("─", 75), reset)

	// Verdict with color
	if r.DenyCount > 0 {
		fmt.Fprintf(&b, "%s%sVERDICT: FAIL — %d violation(s)%s  (%s%d allow%s, %s%d deny%s, %s%d ask%s)\n",
			bold, red, r.DenyCount, reset,
			green, r.AllowCount, reset,
			red, r.DenyCount, reset,
			yellow, r.AskCount, reset)
	} else {
		fmt.Fprintf(&b, "%s%sVERDICT: PASS%s  (%s%d allow%s, %s%d deny%s, %s%d ask%s)\n",
			bold, green, reset,
			green, r.AllowCount, reset,
			red, r.DenyCount, reset,
			yellow, r.AskCount, reset)
	}

	return b.String()
}

// FormatJSON renders the report as JSON.
func (r *Report) FormatJSON() (string, error) {
	type jsonAction struct {
		Index    int            `json:"index"`
		Tool     string         `json:"tool"`
		ID       string         `json:"id"`
		Input    map[string]any `json:"input"`
		Decision string         `json:"decision"`
		Reason   string         `json:"reason,omitempty"`
	}

	type jsonReport struct {
		Policy     string       `json:"policy"`
		PolicyPath string       `json:"policyPath"`
		Model      string       `json:"model"`
		Turns      int          `json:"turns"`
		ToolCalls  int          `json:"toolCalls"`
		TokensIn   int64        `json:"tokensIn"`
		TokensOut  int64        `json:"tokensOut"`
		AllowCount int          `json:"allowCount"`
		DenyCount  int          `json:"denyCount"`
		AskCount   int          `json:"askCount"`
		Verdict    string       `json:"verdict"`
		Actions    []jsonAction `json:"actions"`
	}

	verdict := "pass"
	if r.DenyCount > 0 {
		verdict = "fail"
	}

	jr := jsonReport{
		Policy:     r.PolicyName,
		PolicyPath: r.PolicyPath,
		Model:      r.Session.Model,
		Turns:      r.Session.Turns,
		ToolCalls:  len(r.Session.Actions),
		TokensIn:   r.Session.TokensIn,
		TokensOut:  r.Session.TokensOut,
		AllowCount: r.AllowCount,
		DenyCount:  r.DenyCount,
		AskCount:   r.AskCount,
		Verdict:    verdict,
	}

	for _, res := range r.Results {
		jr.Actions = append(jr.Actions, jsonAction{
			Index:    res.Action.Index,
			Tool:     res.Action.Tool,
			ID:       res.Action.ID,
			Input:    res.Action.Input,
			Decision: string(res.Decision),
			Reason:   res.Reason,
		})
	}

	data, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// detectSessionRoot finds the common directory of file operations (Read/Write/Edit)
// in the session. Only uses file_path inputs — Bash commands reference binaries
// across the filesystem and would make the common prefix too broad.
func detectSessionRoot(results []Result) string {
	var paths []string
	for _, res := range results {
		switch res.Action.Tool {
		case "Read", "Write", "Edit", "Glob", "Grep":
			if fp, ok := res.Action.Input["file_path"].(string); ok && filepath.IsAbs(fp) {
				paths = append(paths, filepath.Dir(fp))
			}
		}
	}
	if len(paths) == 0 {
		return ""
	}

	// Find common prefix
	common := paths[0]
	for _, p := range paths[1:] {
		for !strings.HasPrefix(p, common) {
			common = filepath.Dir(common)
			if common == "/" || common == "." {
				return ""
			}
		}
	}
	return common
}

// shortenInput makes tool inputs more readable by:
// 1. Stripping the project root from file paths
// 2. Stripping absolute paths from Bash commands, keeping just the command + relative path
// 3. Shortening binary paths to just the binary name
func shortenInput(tool, detail, absRoot string) string {
	if absRoot == "" {
		return detail
	}

	switch tool {
	case "Read", "Write", "Edit", "Glob", "Grep":
		// Already handled by InputDetail() for file_path, but double-check
		return strings.TrimPrefix(detail, absRoot+"/")

	case "Bash":
		// Replace the project root path with relative references
		// Try with trailing slash first (longer match), then without
		result := strings.ReplaceAll(detail, absRoot+"/", "")
		result = strings.ReplaceAll(result, absRoot, ".")

		// Strip any remaining absolute paths to binaries — keep just the binary name
		// e.g., /Users/rahulxf/work-dir/aflock/bin/aflock → aflock
		parts := strings.Fields(result)
		for i, part := range parts {
			if strings.HasPrefix(part, "/") && !strings.HasPrefix(part, "/dev/") &&
				!strings.HasPrefix(part, "/tmp/") && !strings.HasPrefix(part, "/etc/") {
				parts[i] = filepath.Base(part)
			}
		}
		return strings.Join(parts, " ")
	}

	return strings.TrimPrefix(detail, absRoot+"/")
}

// shortenReason strips absolute paths from deny/ask reasons to make them readable.
func shortenReason(reason, absRoot string) string {
	if absRoot == "" {
		return reason
	}
	// Strip the project root from the reason text
	result := strings.ReplaceAll(reason, absRoot+"/", "")
	result = strings.ReplaceAll(result, absRoot, "")
	return result
}

// loadPolicy re-reads the policy for limit checks in formatting.
func (r *Report) loadPolicy() *aflock.Policy {
	pol, _, err := policy.Load(r.PolicyPath)
	if err != nil {
		return nil
	}
	return pol
}
