package usage

import (
	"math"
	"testing"
)

// TestComputeCostUSD_Opus47KnownTokens checks the math against published
// rates. Input $15/M, output $75/M, no cache. Expectation:
//
//	1,000,000 input + 500,000 output = 1*15 + 0.5*75 = $15 + $37.50 = $52.50
func TestComputeCostUSD_Opus47KnownTokens(t *testing.T) {
	c := Cumulative{
		InputTokens:  1_000_000,
		OutputTokens: 500_000,
		Model:        "claude-opus-4-7",
	}
	got := ComputeCostUSD(c)
	want := 52.50
	if math.Abs(got-want) > 0.01 {
		t.Errorf("ComputeCostUSD = %.4f, want %.2f", got, want)
	}
}

// TestComputeCostUSD_CacheTiersFallback exercises the scalar-only path
// (no cache_creation breakdown). The scalar is credited entirely to the
// 5m bucket, so cache_write at 1.25x:
//
//	100k cache_creation @ ($15/M * 1.25) = $1.875
//	100k cache_read     @ ($15/M * 0.10) = $0.15
//	Total = $2.025
func TestComputeCostUSD_CacheTiersFallback(t *testing.T) {
	c := Cumulative{
		CacheCreationInputTokens: 100_000,
		CacheReadInputTokens:     100_000,
		Model:                    "claude-opus-4-7",
	}
	got := ComputeCostUSD(c)
	want := 2.025
	if math.Abs(got-want) > 0.001 {
		t.Errorf("ComputeCostUSD = %.4f, want %.4f", got, want)
	}
}

// TestComputeCostUSD_CacheTiersBrokenOut verifies distinct multipliers
// per tier when the breakdown is present:
//
//	50k 5m  @ ($15/M * 1.25) = $0.9375
//	50k 1h  @ ($15/M * 2.00) = $1.5
//	100k cr @ ($15/M * 0.10) = $0.15
//	Total = $2.5875
func TestComputeCostUSD_CacheTiersBrokenOut(t *testing.T) {
	c := Cumulative{
		CacheCreation5mTokens: 50_000,
		CacheCreation1hTokens: 50_000,
		CacheReadInputTokens:  100_000,
		// CacheCreationInputTokens scalar intentionally NOT set — the
		// per-tier fields must take precedence when populated.
		Model: "claude-opus-4-7",
	}
	got := ComputeCostUSD(c)
	want := 2.5875
	if math.Abs(got-want) > 0.001 {
		t.Errorf("ComputeCostUSD = %.4f, want %.4f", got, want)
	}
}

// TestComputeCostUSD_CacheTiersIgnoreScalarWhenBrokenOut ensures the
// scalar back-compat path is NOT additive — when 5m+1h are populated,
// scalar must be ignored (it equals their sum, double-charging would
// be a bug).
func TestComputeCostUSD_CacheTiersIgnoreScalarWhenBrokenOut(t *testing.T) {
	c := Cumulative{
		CacheCreationInputTokens: 100_000, // would be 5m+1h sum on real data
		CacheCreation5mTokens:    40_000,
		CacheCreation1hTokens:    60_000,
		Model:                    "claude-opus-4-7",
	}
	got := ComputeCostUSD(c)
	// Only per-tier numbers should contribute:
	//   40k * 15 * 1.25 / M = $0.75
	//   60k * 15 * 2.00 / M = $1.80
	want := 2.55
	if math.Abs(got-want) > 0.001 {
		t.Errorf("scalar must be ignored when tiers populated; got %.4f, want %.4f", got, want)
	}
}

// TestResolvePricing_EnvOverride confirms env vars take precedence over
// defaults. Critical for prod when prices change before a release ships.
func TestResolvePricing_EnvOverride(t *testing.T) {
	t.Setenv("AFLOCK_PRICE_INPUT_CLAUDE_OPUS_4_7", "20.00")
	t.Setenv("AFLOCK_PRICE_OUTPUT_CLAUDE_OPUS_4_7", "100.00")

	p, known := ResolvePricing("claude-opus-4-7")
	if !known {
		t.Fatal("expected known")
	}
	if p.InputPerMTok != 20.00 {
		t.Errorf("InputPerMTok = %.2f, want 20.00", p.InputPerMTok)
	}
	if p.OutputPerMTok != 100.00 {
		t.Errorf("OutputPerMTok = %.2f, want 100.00", p.OutputPerMTok)
	}
	// Defaults preserved for non-overridden fields.
	if p.CacheReadMult != 0.10 {
		t.Errorf("CacheReadMult = %.4f, want 0.10 (default)", p.CacheReadMult)
	}
}

// TestResolvePricing_UnknownModelWithEnvBecomesKnown — fully overriding an
// unknown model via env should mark it known so cost is computed instead
// of warned-and-zeroed.
func TestResolvePricing_UnknownModelWithEnvBecomesKnown(t *testing.T) {
	t.Setenv("AFLOCK_PRICE_INPUT_FUTURE_MODEL_X", "5.00")

	_, known := ResolvePricing("future-model-x")
	if !known {
		t.Error("expected known after env override on unknown model")
	}
}

// TestComputeCostUSD_UnknownModel returns 0 (and logs warning, suppressed
// in test by default since stderr isn't captured).
func TestComputeCostUSD_UnknownModel(t *testing.T) {
	c := Cumulative{
		InputTokens:  1_000_000,
		OutputTokens: 500_000,
		Model:        "totally-bogus-model-9000",
	}
	got := ComputeCostUSD(c)
	if got != 0 {
		t.Errorf("expected 0 for unknown model, got %.4f", got)
	}
}

// TestComputeCostUSD_EmptyModel — defensive: zero in, zero out.
func TestComputeCostUSD_EmptyModel(t *testing.T) {
	c := Cumulative{InputTokens: 100, OutputTokens: 50}
	if got := ComputeCostUSD(c); got != 0 {
		t.Errorf("expected 0 for empty model, got %.4f", got)
	}
}

// TestModelSlug spot-checks the env-var slug normalization.
func TestModelSlug(t *testing.T) {
	cases := map[string]string{
		"claude-opus-4-7":  "CLAUDE_OPUS_4_7",
		"claude-haiku-4-5": "CLAUDE_HAIKU_4_5",
		"some.weird.model": "SOME_WEIRD_MODEL",
	}
	for in, want := range cases {
		if got := modelSlug(in); got != want {
			t.Errorf("modelSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCumulative_Add verifies running totals fold correctly.
func TestCumulative_Add(t *testing.T) {
	a := Cumulative{InputTokens: 10, OutputTokens: 5, AssistantTurns: 1, Model: "m1"}
	b := Cumulative{InputTokens: 20, OutputTokens: 8, AssistantTurns: 2, Model: "m2"}
	a.Add(b)
	if a.InputTokens != 30 || a.OutputTokens != 13 || a.AssistantTurns != 3 {
		t.Errorf("after Add: %+v", a)
	}
	if a.Model != "m2" {
		t.Errorf("Model should follow latest non-empty, got %q", a.Model)
	}
	// Adding empty Model should not clobber.
	a.Add(Cumulative{InputTokens: 1})
	if a.Model != "m2" {
		t.Errorf("empty Model in Add should not clobber, got %q", a.Model)
	}
}
