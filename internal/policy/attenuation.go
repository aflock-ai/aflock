package policy

import (
	"fmt"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// AttenuationViolations checks that sublayout limits are <= parent limits.
// Empty result means the sublayout is validly attenuated. Sublayouts may
// declare fewer limits than the parent; only fields set on both sides are
// compared. A nil parent or sub means there's nothing to compare against.
//
// Used at spawn time (hooks-mode PreToolUse, MCP-mode aflock_delegate)
// and at verify time. Sharing one rule keeps the two enforcement paths
// from drifting.
func AttenuationViolations(parent, sub *aflock.LimitsPolicy) []string {
	if sub == nil || parent == nil {
		return nil
	}
	var violations []string
	check := func(name string, p, s *aflock.Limit) {
		if p == nil || s == nil {
			return
		}
		if s.Value > p.Value {
			violations = append(violations, fmt.Sprintf("%s: sublayout %.2f > parent %.2f", name, s.Value, p.Value))
		}
	}
	check("maxSpendUSD", parent.MaxSpendUSD, sub.MaxSpendUSD)
	check("maxTokensIn", parent.MaxTokensIn, sub.MaxTokensIn)
	check("maxTokensOut", parent.MaxTokensOut, sub.MaxTokensOut)
	check("maxTurns", parent.MaxTurns, sub.MaxTurns)
	check("maxWallTimeSeconds", parent.MaxWallTimeSeconds, sub.MaxWallTimeSeconds)
	check("maxToolCalls", parent.MaxToolCalls, sub.MaxToolCalls)
	return violations
}
