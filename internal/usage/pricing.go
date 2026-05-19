package usage

import (
	"os"
	"strconv"
	"strings"
)

// Rates are USD per million tokens (input / output) for one model
// family. Cache-creation 5m and cache-read multipliers are applied on
// top of the input rate; the 1h cache-creation rate is its own dollar
// figure since Anthropic publishes that tier separately for some
// models.
type Rates struct {
	InputPerM        float64
	OutputPerM       float64
	CacheCreate5mPerM float64 // typically 1.25 × input
	CacheCreate1hPerM float64 // typically 2.00 × input
	CacheReadPerM     float64 // typically 0.10 × input
}

// builtinRates is a hardcoded snapshot of Anthropic's published
// per-million-token API pricing. We match by case-insensitive substring
// against the model string from the JSONL: e.g., "claude-opus-4-7"
// matches "opus-4". Unknown models fall through to ZeroRates and the
// caller records a "unknown model" warning so audit can spot drift.
//
// Source: docs.anthropic.com/en/docs/build-with-claude/pricing
// Update as Anthropic publishes new tiers. Overrides via env vars
// (AFLOCK_PRICE_<KEY>) let operators patch this without a rebuild.
var builtinRates = []struct {
	match string
	rates Rates
}{
	{"opus-4", Rates{
		InputPerM:         15.00,
		OutputPerM:        75.00,
		CacheCreate5mPerM: 18.75,
		CacheCreate1hPerM: 30.00,
		CacheReadPerM:     1.50,
	}},
	{"sonnet-4", Rates{
		InputPerM:         3.00,
		OutputPerM:        15.00,
		CacheCreate5mPerM: 3.75,
		CacheCreate1hPerM: 6.00,
		CacheReadPerM:     0.30,
	}},
	{"haiku-4", Rates{
		InputPerM:         1.00,
		OutputPerM:        5.00,
		CacheCreate5mPerM: 1.25,
		CacheCreate1hPerM: 2.00,
		CacheReadPerM:     0.10,
	}},
	{"haiku-3-5", Rates{
		InputPerM:         0.80,
		OutputPerM:        4.00,
		CacheCreate5mPerM: 1.00,
		CacheCreate1hPerM: 1.60,
		CacheReadPerM:     0.08,
	}},
	{"sonnet-3-7", Rates{
		InputPerM:         3.00,
		OutputPerM:        15.00,
		CacheCreate5mPerM: 3.75,
		CacheCreate1hPerM: 6.00,
		CacheReadPerM:     0.30,
	}},
}

// RatesFor returns the published rates for a model string, applying any
// AFLOCK_PRICE_* env overrides. The second return value is the matched
// family key — empty when the model is unknown to us (caller treats as
// no-cost-data).
//
// Override env vars (USD per million tokens):
//
//	AFLOCK_PRICE_OPUS_INPUT, AFLOCK_PRICE_OPUS_OUTPUT,
//	AFLOCK_PRICE_OPUS_CACHE_WRITE_5M, AFLOCK_PRICE_OPUS_CACHE_WRITE_1H,
//	AFLOCK_PRICE_OPUS_CACHE_READ
//	(...and the same for SONNET, HAIKU)
func RatesFor(model string) (Rates, string) {
	low := strings.ToLower(model)
	for _, e := range builtinRates {
		if strings.Contains(low, e.match) {
			return applyOverrides(e.rates, familyKey(e.match)), familyKey(e.match)
		}
	}
	return Rates{}, ""
}

func familyKey(match string) string {
	// "opus-4" → "OPUS", "sonnet-3-7" → "SONNET". Operators care about
	// the family, not the version, when wiring overrides.
	for _, fam := range []string{"opus", "sonnet", "haiku"} {
		if strings.HasPrefix(match, fam) {
			return strings.ToUpper(fam)
		}
	}
	return ""
}

func applyOverrides(r Rates, fam string) Rates {
	if fam == "" {
		return r
	}
	if v, ok := envFloat("AFLOCK_PRICE_" + fam + "_INPUT"); ok {
		r.InputPerM = v
	}
	if v, ok := envFloat("AFLOCK_PRICE_" + fam + "_OUTPUT"); ok {
		r.OutputPerM = v
	}
	if v, ok := envFloat("AFLOCK_PRICE_" + fam + "_CACHE_WRITE_5M"); ok {
		r.CacheCreate5mPerM = v
	}
	if v, ok := envFloat("AFLOCK_PRICE_" + fam + "_CACHE_WRITE_1H"); ok {
		r.CacheCreate1hPerM = v
	}
	if v, ok := envFloat("AFLOCK_PRICE_" + fam + "_CACHE_READ"); ok {
		r.CacheReadPerM = v
	}
	return r
}

func envFloat(key string) (float64, bool) {
	s := os.Getenv(key)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// CostResult bundles the dollar number with the metadata audit needs to
// trust it: which models contributed, whether any model was unknown,
// and the source tag (always "transcript" today — Anthropic admin/usage
// API integration would emit "admin-api").
type CostResult struct {
	TotalUSD       float64           `json:"totalUSD"`
	PerModel       map[string]float64 `json:"perModel,omitempty"`
	UnknownModels  []string           `json:"unknownModels,omitempty"`
	Source         string             `json:"source"`
}

// Compute prices a SessionUsage at the published per-model rates. It is
// the caller's responsibility to decide whether to actually surface the
// dollar number — under subscription auth mode the number is
// systematically wrong and should be hidden or labelled advisory.
//
// Unknown models contribute 0 to the total and are returned in
// UnknownModels so the caller can warn or skip enforcement.
func Compute(u *SessionUsage) CostResult {
	out := CostResult{
		PerModel: make(map[string]float64),
		Source:   "transcript",
	}
	if u == nil {
		return out
	}
	if len(u.PerModel) == 0 {
		// No model attribution at all — usually a malformed/legacy
		// transcript. Skip rather than guess: dollar numbers should not
		// silently substitute the wrong rate.
		return out
	}
	for model, roll := range u.PerModel {
		rates, fam := RatesFor(model)
		if fam == "" {
			out.UnknownModels = append(out.UnknownModels, model)
			continue
		}
		c := perMillion(roll.InputTokens, rates.InputPerM) +
			perMillion(roll.OutputTokens, rates.OutputPerM) +
			perMillion(roll.CacheCreate5mTokens, rates.CacheCreate5mPerM) +
			perMillion(roll.CacheCreate1hTokens, rates.CacheCreate1hPerM) +
			perMillion(roll.CacheReadTokens, rates.CacheReadPerM)
		out.PerModel[model] = c
		out.TotalUSD += c
	}
	if len(out.PerModel) == 0 {
		out.PerModel = nil
	}
	return out
}

func perMillion(tokens int64, ratePerM float64) float64 {
	return float64(tokens) / 1_000_000.0 * ratePerM
}
