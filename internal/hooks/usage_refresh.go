package hooks

import (
	"github.com/aflock-ai/aflock/internal/usage"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// refreshUsageFromTranscript refreshes hooks-mode session metrics from
// the Claude transcript. The shared logic lives in
// usage.RefreshSessionMetrics (reused by the MCP server, issue #72);
// hooks filter transcript rows by the Claude session_id they were
// handed, which equals state.SessionID in hooks mode.
func refreshUsageFromTranscript(state *aflock.SessionState, transcriptPath, authMode string) {
	if state == nil {
		return
	}
	usage.RefreshSessionMetrics(state, transcriptPath, state.SessionID, authMode)
}
