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
// CacheWriteMult and CacheReadMult are multipliers on InputPerMTok
// (Anthropic's published model: cache writes ~1.25x input, cache reads ~0.10x).
type Pricing struct {
	InputPerMTok   float64
	OutputPerMTok  float64
	CacheWriteMult float64
	CacheReadMult  float64
}

// defaultPricing is keyed on the canonical model string Claude Code writes
// in JSONL `message.model`. Rates as of 2026-05; override via env if they
// drift. Unknown models fall through with a one-time WARNING log and zero
// cost — we don't guess.
var defaultPricing = map[string]Pricing{
	"claude-opus-4-7":   {InputPerMTok: 15.00, OutputPerMTok: 75.00, CacheWriteMult: 1.25, CacheReadMult: 0.10},
	"claude-opus-4-6":   {InputPerMTok: 15.00, OutputPerMTok: 75.00, CacheWriteMult: 1.25, CacheReadMult: 0.10},
	"claude-sonnet-4-6": {InputPerMTok: 3.00, OutputPerMTok: 15.00, CacheWriteMult: 1.25, CacheReadMult: 0.10},
	"claude-sonnet-4":   {InputPerMTok: 3.00, OutputPerMTok: 15.00, CacheWriteMult: 1.25, CacheReadMult: 0.10},
	"claude-haiku-4-5":  {InputPerMTok: 0.80, OutputPerMTok: 4.00, CacheWriteMult: 1.25, CacheReadMult: 0.10},
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
	if v := os.Getenv("AFLOCK_PRICE_CACHE_WRITE_MULT_" + slug); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			p.CacheWriteMult = f
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
	cost += float64(c.CacheCreationInputTokens) * p.InputPerMTok * p.CacheWriteMult / 1_000_000
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
			"  %-22s input=$%.2f output=$%.2f cache_write=%.2fx cache_read=%.2fx\n",
			m, p.InputPerMTok, p.OutputPerMTok, p.CacheWriteMult, p.CacheReadMult)
	}
}
