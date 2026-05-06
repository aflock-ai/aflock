package usage

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Pricing captures the cost weights for one Claude model.
// PerMTok rates are USD per million tokens.
// Cache multipliers are relative to InputPerMTok. Anthropic charges
// distinct rates for the two cache write tiers:
//
//   - CacheWrite5mMult: 5-minute ephemeral writes (~1.25x)
//   - CacheWrite1hMult: 1-hour ephemeral writes (~2.00x)
//   - CacheReadMult:    cache reads (~0.10x)
type Pricing struct {
	InputPerMTok     float64
	OutputPerMTok    float64
	CacheWrite5mMult float64
	CacheWrite1hMult float64
	CacheReadMult    float64
}

// defaultPricing is keyed on the canonical model string Claude Code writes
// in JSONL `message.model`. Rates as of 2026-05; override via env if they
// drift. Unknown models fall through with a one-time WARNING log and zero
// cost — we don't guess.
var defaultPricing = map[string]Pricing{
	"claude-opus-4-7":   {InputPerMTok: 15.00, OutputPerMTok: 75.00, CacheWrite5mMult: 1.25, CacheWrite1hMult: 2.00, CacheReadMult: 0.10},
	"claude-opus-4-6":   {InputPerMTok: 15.00, OutputPerMTok: 75.00, CacheWrite5mMult: 1.25, CacheWrite1hMult: 2.00, CacheReadMult: 0.10},
	"claude-sonnet-4-6": {InputPerMTok: 3.00, OutputPerMTok: 15.00, CacheWrite5mMult: 1.25, CacheWrite1hMult: 2.00, CacheReadMult: 0.10},
	"claude-sonnet-4":   {InputPerMTok: 3.00, OutputPerMTok: 15.00, CacheWrite5mMult: 1.25, CacheWrite1hMult: 2.00, CacheReadMult: 0.10},
	"claude-haiku-4-5":  {InputPerMTok: 0.80, OutputPerMTok: 4.00, CacheWrite5mMult: 1.25, CacheWrite1hMult: 2.00, CacheReadMult: 0.10},
}

var (
	unknownLogMu  sync.Mutex
	loggedUnknown = make(map[string]bool)
)

// modelSlug normalizes a model identifier into an env-var-safe suffix.
// "claude-opus-4-7" -> "CLAUDE_OPUS_4_7".
func modelSlug(model string) string {
	s := strings.ReplaceAll(model, "-", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return strings.ToUpper(s)
}

// ResolvePricing returns the effective pricing for model, applying any
// AFLOCK_PRICE_<KIND>_<MODEL_SLUG> env overrides on top of defaults.
//
// Env var pattern (model = "claude-opus-4-7"):
//
//	AFLOCK_PRICE_INPUT_CLAUDE_OPUS_4_7=15.00
//	AFLOCK_PRICE_OUTPUT_CLAUDE_OPUS_4_7=75.00
//	AFLOCK_PRICE_CACHE_WRITE_MULT_CLAUDE_OPUS_4_7=1.25
//	AFLOCK_PRICE_CACHE_READ_MULT_CLAUDE_OPUS_4_7=0.10
//
// known is true iff the model has either a default entry OR at least one
// env override (so "fully overriding an unknown model" works).
func ResolvePricing(model string) (p Pricing, known bool) {
	p, known = defaultPricing[model]
	slug := modelSlug(model)

	if v := os.Getenv("AFLOCK_PRICE_INPUT_" + slug); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			p.InputPerMTok = f
			known = true
		}
	}
	if v := os.Getenv("AFLOCK_PRICE_OUTPUT_" + slug); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			p.OutputPerMTok = f
			known = true
		}
	}
	// Cache-write multipliers — distinct envs per tier. Legacy
	// AFLOCK_PRICE_CACHE_WRITE_MULT_<MODEL> sets BOTH tiers (back-compat
	// for setups that overrode the previous single-multiplier API).
	if v := os.Getenv("AFLOCK_PRICE_CACHE_WRITE_MULT_" + slug); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			p.CacheWrite5mMult = f
			p.CacheWrite1hMult = f
			known = true
		}
	}
	if v := os.Getenv("AFLOCK_PRICE_CACHE_WRITE_5M_MULT_" + slug); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			p.CacheWrite5mMult = f
			known = true
		}
	}
	if v := os.Getenv("AFLOCK_PRICE_CACHE_WRITE_1H_MULT_" + slug); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			p.CacheWrite1hMult = f
			known = true
		}
	}
	if v := os.Getenv("AFLOCK_PRICE_CACHE_READ_MULT_" + slug); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			p.CacheReadMult = f
			known = true
		}
	}

	return p, known
}

// ComputeCostUSD returns the USD cost of c using the model's pricing.
// If c.Model is unknown (no defaults, no env overrides), logs a one-time
// WARNING and returns 0 — we deliberately do not guess.
func ComputeCostUSD(c Cumulative) float64 {
	if c.Model == "" {
		return 0
	}
	p, known := ResolvePricing(c.Model)
	if !known {
		unknownLogMu.Lock()
		if !loggedUnknown[c.Model] {
			loggedUnknown[c.Model] = true
			fmt.Fprintf(os.Stderr,
				"[aflock] WARNING: unknown model %q in pricing table — costUSD will be 0. "+
					"Set AFLOCK_PRICE_INPUT_%s / AFLOCK_PRICE_OUTPUT_%s to override.\n",
				c.Model, modelSlug(c.Model), modelSlug(c.Model))
		}
		unknownLogMu.Unlock()
		return 0
	}
	cost := 0.0
	cost += float64(c.InputTokens) * p.InputPerMTok / 1_000_000
	cost += float64(c.OutputTokens) * p.OutputPerMTok / 1_000_000
	// Apply distinct multipliers per cache-write tier when broken out.
	// If only the scalar CacheCreationInputTokens is populated (older
	// JSONLs without cache_creation block), fall back to the 5m rate —
	// matches Anthropic's pre-1h-tier default.
	if c.CacheCreation5mTokens > 0 || c.CacheCreation1hTokens > 0 {
		cost += float64(c.CacheCreation5mTokens) * p.InputPerMTok * p.CacheWrite5mMult / 1_000_000
		cost += float64(c.CacheCreation1hTokens) * p.InputPerMTok * p.CacheWrite1hMult / 1_000_000
	} else {
		cost += float64(c.CacheCreationInputTokens) * p.InputPerMTok * p.CacheWrite5mMult / 1_000_000
	}
	cost += float64(c.CacheReadInputTokens) * p.InputPerMTok * p.CacheReadMult / 1_000_000
	return cost
}

// LogResolvedPricing prints the active pricing for every known model at
// startup. Call once during server init so users can verify resolved rates
// (especially after env overrides) before tool calls start metering cost.
func LogResolvedPricing() {
	models := make([]string, 0, len(defaultPricing))
	for m := range defaultPricing {
		models = append(models, m)
	}
	sort.Strings(models)
	fmt.Fprintf(os.Stderr, "[aflock] Pricing (USD/M tokens):\n")
	for _, m := range models {
		p, _ := ResolvePricing(m)
		fmt.Fprintf(os.Stderr,
			"  %-22s input=$%.2f output=$%.2f cache_write_5m=%.2fx cache_write_1h=%.2fx cache_read=%.2fx\n",
			m, p.InputPerMTok, p.OutputPerMTok, p.CacheWrite5mMult, p.CacheWrite1hMult, p.CacheReadMult)
	}
}
