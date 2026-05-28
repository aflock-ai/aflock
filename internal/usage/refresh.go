package usage

import (
	"fmt"
	"os"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// RefreshSessionMetrics parses the claude-code session JSONL at
// transcriptPath and writes the aggregated token/cache/turn counts into
// state.Metrics, then prices them. Shared by hooks PostToolUse and the
// MCP server's per-tool limit check (issue #72) so both enforcement
// planes derive metrics the same way.
//
// filterSessionID restricts which transcript rows count: hooks pass the
// Claude session_id they were handed; the MCP server passes the session
// id it discovered for the workspace, or "" to accept every assistant
// row in the file (the file is already per-session there).
//
// CostUSD is authoritative (CostMeasured=true) only under api_key AND
// when every model in the transcript was priceable — an unpriced model
// computes as $0 and would otherwise let a session slip under
// maxSpendUSD, so we mark it unmeasured and warn (see IsAdvisoryLimit).
//
// transcriptPath is best-effort: an empty path or unreadable file
// leaves metrics untouched.
func RefreshSessionMetrics(state *aflock.SessionState, transcriptPath, filterSessionID, authMode string) {
	if state == nil || state.Metrics == nil || transcriptPath == "" {
		return
	}
	u, err := ScanFile(transcriptPath, filterSessionID)
	if err != nil || u == nil {
		return
	}
	state.Metrics.TokensIn = u.InputTokens
	state.Metrics.TokensOut = u.OutputTokens
	state.Metrics.CacheReadTokens = u.CacheReadTokens
	state.Metrics.CacheWrite5mTokens = u.CacheCreate5mTokens
	state.Metrics.CacheWrite1hTokens = u.CacheCreate1hTokens
	if u.Turns > 0 {
		state.Metrics.Turns = u.Turns
	}
	cost := Compute(u)
	state.Metrics.UsageSource = cost.Source
	state.Metrics.CostUSD = cost.TotalUSD

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
