package usage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

func transcript(t *testing.T, model string, in, out int) string {
	t.Helper()
	line := `{"type":"assistant","sessionId":"s1","requestId":"r1","message":{"id":"m1","model":"` +
		model + `","usage":{"input_tokens":` + itoa(in) + `,"output_tokens":` + itoa(out) + `}}}` + "\n"
	p := filepath.Join(t.TempDir(), "t.jsonl")
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestRefreshSessionMetrics_PopulatesAndPrices is the core of the #72
// MCP fix: the shared refresh both populates token counts and prices a
// known model as authoritative under api_key. Filter "" (as the MCP
// caller passes) accepts the row even though its sessionId differs from
// the aflock session id.
func TestRefreshSessionMetrics_PopulatesAndPrices(t *testing.T) {
	st := &aflock.SessionState{SessionID: "mcp-abc", Metrics: &aflock.SessionMetrics{}}
	RefreshSessionMetrics(st, transcript(t, "claude-opus-4-7", 10000, 500), "", "api_key")

	if st.Metrics.TokensIn != 10000 {
		t.Errorf("TokensIn=%d, want 10000", st.Metrics.TokensIn)
	}
	if !st.Metrics.CostMeasured || st.Metrics.CostUSD <= 0 {
		t.Errorf("known model under api_key must be measured with cost>0, got measured=%v cost=%v",
			st.Metrics.CostMeasured, st.Metrics.CostUSD)
	}
}

// TestRefreshSessionMetrics_UnknownModelUnmeasured — unpriced model
// must not be treated as measured (would under-count maxSpendUSD).
func TestRefreshSessionMetrics_UnknownModelUnmeasured(t *testing.T) {
	st := &aflock.SessionState{SessionID: "mcp-abc", Metrics: &aflock.SessionMetrics{}}
	RefreshSessionMetrics(st, transcript(t, "claude-future-9", 10000, 500), "", "api_key")
	if st.Metrics.CostMeasured {
		t.Error("unpriced model must not be CostMeasured")
	}
}
