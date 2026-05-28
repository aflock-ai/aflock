package hooks

import (
	"fmt"
	"os"

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
	state.Metrics.CostUSD = cost.TotalUSD

	// Cost is authoritative only under api_key AND when every model in
	// the transcript was priceable. An unpriced model contributes $0 to
	// the total, so a session running one would silently slip under
	// maxSpendUSD — mark cost unmeasured (keeps the cap advisory via
	// IsAdvisoryLimit) and warn loudly so the gap is visible in audit.
	if authMode == "api_key" && len(cost.UnknownModels) == 0 {
		state.Metrics.CostMeasured = true
	} else {
		state.Metrics.CostMeasured = false
		if authMode == "api_key" && len(cost.UnknownModels) > 0 {
			fmt.Fprintf(os.Stderr,
				"[aflock] Warning: %d unpriced model(s) %v in transcript — cost is under-counted, maxSpendUSD downgraded to advisory. Add rates via AFLOCK_PRICE_* or update internal/usage/pricing.go.\n",
				len(cost.UnknownModels), cost.UnknownModels)
		}
	}
}
