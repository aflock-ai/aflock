package hooks

import (
	"github.com/aflock-ai/aflock/internal/usage"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// refreshUsageFromTranscript parses the claude-code session JSONL at
// transcriptPath and writes the aggregated token/cache/turn counts into
// state.Metrics. CostUSD is computed from published per-token rates and
// is only treated as authoritative when authMode == api_key; under
// other modes we still store the number but flag it via the policy
// evaluator's IsAdvisoryLimit so cost-based deny rules stay advisory.
//
// transcriptPath is best-effort. An empty path or unreadable file
// silently leaves the metrics as-is — callers always have a non-nil
// Metrics from Initialize, so downstream policy enforcement can fall
// back to the in-process counters (turns, toolCalls, files).
func refreshUsageFromTranscript(state *aflock.SessionState, transcriptPath, authMode string) {
	if state == nil || state.Metrics == nil || transcriptPath == "" {
		return
	}
	u, err := usage.ScanFile(transcriptPath, state.SessionID)
	if err != nil || u == nil {
		return
	}
	state.Metrics.TokensIn = u.InputTokens
	state.Metrics.TokensOut = u.OutputTokens
	state.Metrics.CacheReadTokens = u.CacheReadTokens
	state.Metrics.CacheWrite5mTokens = u.CacheCreate5mTokens
	state.Metrics.CacheWrite1hTokens = u.CacheCreate1hTokens
	// Turns derived from the transcript is authoritative — replaces the
	// in-process counter which was always 0 before this wiring landed.
	if u.Turns > 0 {
		state.Metrics.Turns = u.Turns
	}
	cost := usage.Compute(u)
	state.Metrics.UsageSource = cost.Source
	if authMode == "api_key" {
		state.Metrics.CostUSD = cost.TotalUSD
		state.Metrics.CostMeasured = true
	} else {
		// Keep the computed value visible for diagnostics, but mark it
		// unmeasured so audit downstream knows not to enforce against
		// it. Policy.Evaluator.IsAdvisoryLimit makes the same call on
		// the enforcement side.
		state.Metrics.CostUSD = cost.TotalUSD
		state.Metrics.CostMeasured = false
	}
}
