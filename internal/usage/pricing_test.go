package usage

import (
	"math"
	"testing"
)

func TestRatesFor_Families(t *testing.T) {
	cases := []struct {
		model    string
		family   string
		expectIn float64
	}{
		{"claude-opus-4-7", "OPUS", 15.00},
		{"claude-sonnet-4-6", "SONNET", 3.00},
		{"claude-haiku-4-5-20251001", "HAIKU", 1.00},
		{"some-other-model", "", 0},
	}
	for _, c := range cases {
		r, fam := RatesFor(c.model)
		if fam != c.family {
			t.Errorf("RatesFor(%q) family = %q, want %q", c.model, fam, c.family)
		}
		if c.family != "" && r.InputPerM != c.expectIn {
			t.Errorf("RatesFor(%q) input = %v, want %v", c.model, r.InputPerM, c.expectIn)
		}
	}
}

func TestRatesFor_EnvOverride(t *testing.T) {
	t.Setenv("AFLOCK_PRICE_OPUS_INPUT", "9.99")
	t.Setenv("AFLOCK_PRICE_OPUS_CACHE_READ", "0.42")
	r, _ := RatesFor("claude-opus-4-7")
	if r.InputPerM != 9.99 {
		t.Errorf("override input = %v, want 9.99", r.InputPerM)
	}
	if r.CacheReadPerM != 0.42 {
		t.Errorf("override cache read = %v, want 0.42", r.CacheReadPerM)
	}
}

func TestCompute_MultiModel(t *testing.T) {
	u := &SessionUsage{
		PerModel: map[string]ModelRoll{
			"claude-opus-4-7": {
				InputTokens:         1_000_000,
				OutputTokens:        1_000_000,
				CacheCreate5mTokens: 1_000_000,
				CacheReadTokens:     1_000_000,
			},
			"claude-sonnet-4-6": {
				InputTokens:  500_000,
				OutputTokens: 500_000,
			},
		},
	}
	got := Compute(u)
	// opus: 15 + 75 + 18.75 + 1.5 = 110.25
	// sonnet: 0.5*3 + 0.5*15 = 1.5 + 7.5 = 9.0
	want := 110.25 + 9.0
	if math.Abs(got.TotalUSD-want) > 0.0001 {
		t.Errorf("TotalUSD = %v, want %v", got.TotalUSD, want)
	}
	if got.Source != "transcript" {
		t.Errorf("Source = %q, want transcript", got.Source)
	}
	if len(got.UnknownModels) != 0 {
		t.Errorf("UnknownModels = %v, want empty", got.UnknownModels)
	}
}

func TestCompute_UnknownModelRecorded(t *testing.T) {
	u := &SessionUsage{
		PerModel: map[string]ModelRoll{
			"gpt-4-turbo": {InputTokens: 1_000_000, OutputTokens: 1_000_000},
		},
	}
	got := Compute(u)
	if got.TotalUSD != 0 {
		t.Errorf("unknown model should not contribute cost, got %v", got.TotalUSD)
	}
	if len(got.UnknownModels) != 1 || got.UnknownModels[0] != "gpt-4-turbo" {
		t.Errorf("UnknownModels = %v, want [gpt-4-turbo]", got.UnknownModels)
	}
}

func TestCompute_NilOrEmpty(t *testing.T) {
	if got := Compute(nil); got.TotalUSD != 0 {
		t.Errorf("nil usage: TotalUSD = %v, want 0", got.TotalUSD)
	}
	if got := Compute(&SessionUsage{}); got.TotalUSD != 0 {
		t.Errorf("empty usage: TotalUSD = %v, want 0", got.TotalUSD)
	}
}
