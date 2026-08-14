package policy

import (
	"fmt"
	"strings"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// CheckSubagentMisconfig reports whether the loaded policy permits spawning an
// unconstrained subagent, which opens the issue #100 enforcement bypass.
//
// Claude Code's Task/Agent tools spawn a subagent whose NATIVE Bash/Write/Edit
// calls route through Claude Code's harness, not through aflock — so aflock
// cannot see or block them. A policy is flagged when BOTH:
//
//   - it permits Task or Agent (the spawn is not denied), AND
//   - it declares no sublayouts. Sublayouts gate Task/Agent spawns at
//     PreToolUse in hook mode (R3-291), so a policy that declares them is opting
//     into constrained delegation on purpose and is not flagged.
//
// Permission is evaluated with the SAME matching the enforcement path uses
// (EvaluatePreToolUse), so a deny of "*" or "{Task,Agent}" correctly suppresses
// the warning and an allow expressed via a glob is still detected. Returns
// (false, "") when the policy is safe.
func CheckSubagentMisconfig(pol *aflock.Policy) (warn bool, msg string) {
	if pol == nil {
		return false, ""
	}
	if len(pol.Sublayouts) > 0 {
		return false, ""
	}

	eval := NewEvaluator(pol, "")
	var permitted []string
	for _, tool := range aflock.SubagentSpawnTools {
		if decision, _ := eval.EvaluatePreToolUse(tool, nil); decision != aflock.DecisionDeny {
			permitted = append(permitted, tool)
		}
	}
	if len(permitted) == 0 {
		return false, ""
	}

	return true, fmt.Sprintf(
		"policy %q permits subagent spawning (%s) without declaring sublayouts. "+
			"A spawned subagent's native tools route through Claude Code, not aflock, "+
			"so they are NOT enforced (issue #100). Deny %s in tools.deny (and in "+
			".claude/settings.local.json when running in MCP mode), or declare "+
			"sublayouts to constrain delegation.",
		pol.Name, strings.Join(permitted, ", "), strings.Join(permitted, " and "))
}
