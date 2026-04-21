package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- DeriveIdentity ---

func TestDeriveIdentity_Deterministic(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
		Binary: &BinaryIdentity{
			Name:    "claude-code",
			Version: "1.0.26",
		},
		Environment: &EnvironmentIdentity{
			Type: "local",
		},
		Tools:        []string{"bash", "read", "write"},
		PolicyDigest: "abc123",
	}

	hash1 := a.DeriveIdentity()
	hash2 := a.DeriveIdentity()

	if hash1 != hash2 {
		t.Fatalf("DeriveIdentity is not deterministic: %s != %s", hash1, hash2)
	}
	if len(hash1) != 64 {
		t.Fatalf("Expected 64-char hex hash, got %d chars: %s", len(hash1), hash1)
	}
}

func TestDeriveIdentity_ToolOrderDoesNotMatter(t *testing.T) {
	base := func(tools []string) *AgentIdentity {
		return &AgentIdentity{
			Model:        "claude-opus-4-5-20251101",
			ModelVersion: "4.5.20251101",
			Binary: &BinaryIdentity{
				Name:    "claude-code",
				Version: "1.0.26",
			},
			Environment: &EnvironmentIdentity{
				Type: "local",
			},
			Tools:        tools,
			PolicyDigest: "abc123",
		}
	}

	a := base([]string{"bash", "read", "write"})
	b := base([]string{"write", "bash", "read"})
	c := base([]string{"read", "write", "bash"})

	hashA := a.DeriveIdentity()
	hashB := b.DeriveIdentity()
	hashC := c.DeriveIdentity()

	if hashA != hashB || hashA != hashC {
		t.Fatalf("Tool order should not affect hash: %s, %s, %s", hashA, hashB, hashC)
	}
}

func TestDeriveIdentity_DifferentToolsDifferentHash(t *testing.T) {
	base := func(tools []string) *AgentIdentity {
		return &AgentIdentity{
			Model:        "claude-opus-4-5-20251101",
			ModelVersion: "4.5.20251101",
			Tools:        tools,
		}
	}

	a := base([]string{"bash", "read"})
	b := base([]string{"bash", "write"})

	hashA := a.DeriveIdentity()
	hashB := b.DeriveIdentity()

	if hashA == hashB {
		t.Fatal("Different tools should produce different hashes")
	}
}

func TestDeriveIdentity_DifferentModelsDifferentHash(t *testing.T) {
	a := &AgentIdentity{Model: "claude-opus-4-5-20251101", ModelVersion: "4.5.20251101"}
	b := &AgentIdentity{Model: "claude-sonnet-4-20250514", ModelVersion: "4.20250514"}

	hashA := a.DeriveIdentity()
	hashB := b.DeriveIdentity()

	if hashA == hashB {
		t.Fatal("Different models should produce different hashes")
	}
}

func TestDeriveIdentity_WithBinaryDigest(t *testing.T) {
	a := &AgentIdentity{
		Model:        "test-model",
		ModelVersion: "1.0.0",
		Binary: &BinaryIdentity{
			Name:    "claude-code",
			Version: "1.0.0",
			Digest:  "sha256:deadbeef",
		},
	}
	b := &AgentIdentity{
		Model:        "test-model",
		ModelVersion: "1.0.0",
		Binary: &BinaryIdentity{
			Name:    "claude-code",
			Version: "1.0.0",
			// No digest
		},
	}

	hashA := a.DeriveIdentity()
	hashB := b.DeriveIdentity()

	if hashA == hashB {
		t.Fatal("Binary digest presence should change the hash")
	}
}

func TestDeriveIdentity_WithContainerEnvironment(t *testing.T) {
	a := &AgentIdentity{
		Model:        "test-model",
		ModelVersion: "1.0.0",
		Environment: &EnvironmentIdentity{
			Type:        "container",
			ContainerID: "abc123def456",
			ImageDigest: "sha256:deadbeef",
		},
	}
	b := &AgentIdentity{
		Model:        "test-model",
		ModelVersion: "1.0.0",
		Environment: &EnvironmentIdentity{
			Type: "local",
		},
	}

	hashA := a.DeriveIdentity()
	hashB := b.DeriveIdentity()

	if hashA == hashB {
		t.Fatal("Different environments should produce different hashes")
	}
}

func TestDeriveIdentity_WithParentIdentity(t *testing.T) {
	a := &AgentIdentity{
		Model:          "test-model",
		ModelVersion:   "1.0.0",
		ParentIdentity: "parent-hash-123",
	}
	b := &AgentIdentity{
		Model:        "test-model",
		ModelVersion: "1.0.0",
	}

	hashA := a.DeriveIdentity()
	hashB := b.DeriveIdentity()

	if hashA == hashB {
		t.Fatal("Parent identity should change the hash")
	}
}

func TestDeriveIdentity_SetsIdentityHash(t *testing.T) {
	a := &AgentIdentity{Model: "test", ModelVersion: "1.0.0"}

	if a.IdentityHash != "" {
		t.Fatal("IdentityHash should be empty before DeriveIdentity")
	}

	result := a.DeriveIdentity()

	if a.IdentityHash == "" {
		t.Fatal("DeriveIdentity should set IdentityHash")
	}
	if a.IdentityHash != result {
		t.Fatalf("Return value (%s) should match IdentityHash (%s)", result, a.IdentityHash)
	}
}

func TestDeriveIdentity_CanonicalRepresentation(t *testing.T) {
	// Verify the canonical string matches the paper's 5-component formula
	// (issue #61 / M16): SHA256(model ‖ env ‖ tools ‖ policyDigest ‖ parent).
	// Binary fields nest inside `env` per paper §3.1.
	a := &AgentIdentity{
		Model:        "test-model",
		ModelVersion: "1.0.0",
		Binary: &BinaryIdentity{
			Name:    "claude-code",
			Version: "2.0.0",
		},
		Environment: &EnvironmentIdentity{
			Type: "local",
		},
		Tools:        []string{"write", "bash"},
		PolicyDigest: "policydigest123",
	}

	a.DeriveIdentity()

	expected := "model:test-model@1.0.0|env:local;binary=claude-code@2.0.0|tools:bash,write|policy:policydigest123|parent:"
	hash := sha256.Sum256([]byte(expected))
	expectedHash := hex.EncodeToString(hash[:])

	if a.IdentityHash != expectedHash {
		t.Fatalf("Identity hash mismatch.\nExpected canonical: %s\nExpected hash: %s\nGot hash: %s", expected, expectedHash, a.IdentityHash)
	}
}

// TestDeriveIdentity_PaperFormula_FiveComponents verifies that the canonical
// string has exactly 5 top-level "|"-separated components matching the paper
// equation in §3.1 (issue #61 / M16).
func TestDeriveIdentity_PaperFormula_FiveComponents(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-6",
		ModelVersion: "20251101",
		Binary: &BinaryIdentity{
			Name: "claude-code", Version: "2.1.76", Path: "/usr/local/bin/claude", Digest: "sha256:abc",
		},
		Environment: &EnvironmentIdentity{
			Type: "container", UserID: 501, Hostname: "host", ContainerID: "c1", ImageDigest: "sha256:img",
		},
		Tools:          []string{"Bash", "Read"},
		PolicyDigest:   "sha256:pol",
		ParentIdentity: "parenthash",
	}
	a.DeriveIdentity()

	// Recompute canonical and assert structure.
	canonical := "model:claude-opus-4-6@20251101" +
		"|env:container;binary=claude-code@2.1.76;binary_path=/usr/local/bin/claude;binary_digest=sha256:abc;user=501;hostname=host;container=c1;image=sha256:img" +
		"|tools:Bash,Read" +
		"|policy:sha256:pol" +
		"|parent:parenthash"
	parts := strings.Split(canonical, "|")
	if len(parts) != 5 {
		t.Fatalf("paper formula must have 5 top-level components, got %d in %q", len(parts), canonical)
	}
	want := sha256.Sum256([]byte(canonical))
	if a.IdentityHash != hex.EncodeToString(want[:]) {
		t.Fatalf("hash mismatch — canonical layout drifted from paper formula\n  canonical: %s", canonical)
	}
}

func TestDeriveIdentity_NilBinaryAndEnvironment(t *testing.T) {
	a := &AgentIdentity{
		Model:        "test",
		ModelVersion: "1.0.0",
		Tools:        []string{},
	}

	hash := a.DeriveIdentity()

	if hash == "" {
		t.Fatal("Should produce a hash even with nil binary/environment")
	}
	if len(hash) != 64 {
		t.Fatalf("Expected 64-char hex hash, got %d", len(hash))
	}
}

func TestDeriveIdentity_EmptyTools(t *testing.T) {
	a := &AgentIdentity{
		Model:        "test",
		ModelVersion: "1.0.0",
		Tools:        []string{},
	}
	b := &AgentIdentity{
		Model:        "test",
		ModelVersion: "1.0.0",
		Tools:        nil,
	}

	hashA := a.DeriveIdentity()
	hashB := b.DeriveIdentity()

	// Both empty and nil tools should yield the same hash (tools: "")
	if hashA != hashB {
		t.Fatalf("Empty and nil tools should produce the same hash: %s vs %s", hashA, hashB)
	}
}

// --- parseModelVersion ---

func TestParseModelVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"claude-opus-4-5-20251101", "4.5.20251101"},
		{"claude-sonnet-4-20250514", "4.20250514.0"},
		{"claude-3-5-haiku-20241022", "20241022.0.0"}, // "haiku" breaks the digit-dash-digit chain, so only final number matches
		{"claude-opus-4.5.0", "4.5.0"},
		{"claude-opus-4", "4.0.0"},
		{"unknown-model", "0.0.0"},
		{"", "0.0.0"},
		{"no-version-here", "0.0.0"},
		{"model-1-2-30001231", "1.2.30001231"},
		{"model-10.20.30", "10.20.30"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseModelVersion(tt.input)
			if result != tt.expected {
				t.Errorf("parseModelVersion(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// --- ToSPIFFEID ---

func TestToSPIFFEID_Basic(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}
	a.DeriveIdentity()

	id, err := a.ToSPIFFEID("aflock.ai")
	if err != nil {
		t.Fatalf("ToSPIFFEID failed: %v", err)
	}

	spiffeStr := id.String()
	if !strings.HasPrefix(spiffeStr, "spiffe://aflock.ai/agent/") {
		t.Fatalf("SPIFFE ID should start with spiffe://aflock.ai/agent/, got: %s", spiffeStr)
	}

	// Verify it contains model and version components
	if !strings.Contains(spiffeStr, "claude-opus-4-5-20251101") {
		t.Fatalf("SPIFFE ID should contain model name, got: %s", spiffeStr)
	}
}

func TestToSPIFFEID_DeriveIdentityIfMissing(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.0",
	}

	// IdentityHash should be empty
	if a.IdentityHash != "" {
		t.Fatal("IdentityHash should be empty initially")
	}

	_, err := a.ToSPIFFEID("aflock.ai")
	if err != nil {
		t.Fatalf("ToSPIFFEID failed: %v", err)
	}

	// Should have been derived automatically
	if a.IdentityHash == "" {
		t.Fatal("ToSPIFFEID should auto-derive identity hash")
	}
}

func TestToSPIFFEID_SetsSPIFFEIDField(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.0",
	}
	a.DeriveIdentity()

	if !a.SPIFFEID.IsZero() {
		t.Fatal("SPIFFEID should be zero before ToSPIFFEID")
	}

	id, err := a.ToSPIFFEID("aflock.ai")
	if err != nil {
		t.Fatalf("ToSPIFFEID failed: %v", err)
	}

	if a.SPIFFEID != id {
		t.Fatal("ToSPIFFEID should set a.SPIFFEID")
	}
}

func TestToSPIFFEID_UsesFirst16CharsOfHash(t *testing.T) {
	a := &AgentIdentity{
		Model:        "test-model",
		ModelVersion: "1.0.0",
	}
	hash := a.DeriveIdentity()
	hashPrefix := hash[:16]

	id, err := a.ToSPIFFEID("aflock.ai")
	if err != nil {
		t.Fatalf("ToSPIFFEID failed: %v", err)
	}

	if !strings.HasSuffix(id.Path(), hashPrefix) {
		t.Fatalf("SPIFFE ID path should end with hash prefix %s, got path: %s", hashPrefix, id.Path())
	}
}

// --- sanitizeSPIFFEPath ---

func TestSanitizeSPIFFEPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"claude-opus-4-5", "claude-opus-4-5"},
		{"Claude Opus 4.5", "claude-opus-4-5"},
		{"hello_world", "hello-world"},
		{"UPPERCASE", "uppercase"},
		{"a.b.c", "a-b-c"},
		{"abc123", "abc123"},
		{"a--b", "a-b"},  // multiple non-alnum collapsed to single dash
		{"a!!!b", "a-b"}, // multiple non-alnum collapsed to single dash
		{"simple", "simple"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeSPIFFEPath(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeSPIFFEPath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// --- matchGlob ---

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*", "anything", true},
		{"*", "", true},
		{"claude-*", "claude-opus-4-5", true},
		{"claude-*", "claude-", true},
		{"claude-*", "other-model", false},
		{"exact-match", "exact-match", true},
		{"exact-match", "not-exact-match", false},
		{"claude-opus-4-5-20251101", "claude-opus-4-5-20251101", true},
		{"claude-opus-4-5-20251101", "claude-opus-4-5-20251102", false},
		{"pre*", "prefix", true},
		{"pre*", "other", false},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%s_vs_%s", tt.pattern, tt.value)
		t.Run(name, func(t *testing.T) {
			got := matchGlob(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// --- matchSemver ---

func TestMatchSemver(t *testing.T) {
	tests := []struct {
		pattern string
		version string
		want    bool
	}{
		// Wildcards
		{"*", "1.2.3", true},
		{"x", "1.2.3", true},

		// Exact match
		{"1.2.3", "1.2.3", true},
		{"1.2.3", "1.2.4", false},
		{"1.2.3", "1.3.3", false},
		{"1.2.3", "2.2.3", false},

		// X wildcards
		{"1.x", "1.2.3", true},
		{"1.x", "1.0.0", true},
		{"1.x", "2.0.0", false},
		{"1.2.x", "1.2.3", true},
		{"1.2.x", "1.2.0", true},
		{"1.2.x", "1.3.0", false},

		// >= comparisons
		{">=1.0.0", "1.0.0", true},
		{">=1.0.0", "1.0.1", true},
		{">=1.0.0", "2.0.0", true},
		{">=1.0.0", "0.9.9", false},
		{">=4.5.0", "4.5.20251101", true},
		{">=4.5.0", "4.4.9", false},
		{">=4.5.0", "4.5.0", true},
		{">=4.5.0", "5.0.0", true},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%s_vs_%s", tt.pattern, tt.version)
		t.Run(name, func(t *testing.T) {
			got := matchSemver(tt.pattern, tt.version)
			if got != tt.want {
				t.Errorf("matchSemver(%q, %q) = %v, want %v", tt.pattern, tt.version, got, tt.want)
			}
		})
	}
}

// --- compareSemver ---

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "2.0.0", -1},
		{"1.1.0", "1.0.0", 1},
		{"1.0.0", "1.1.0", -1},
		{"4.5.20251101", "4.5.0", 1},
		{"0.0.0", "0.0.0", 0},
		{"10.0.0", "9.0.0", 1},
		// Partial versions
		{"1.0", "1.0.0", 0},
		{"1", "1.0.0", 0},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%s_vs_%s", tt.a, tt.b)
		t.Run(name, func(t *testing.T) {
			got := compareSemver(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("compareSemver(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// --- Matches ---

func TestMatches_AllowedModels(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}

	tests := []struct {
		name            string
		allowedModels   []string
		allowedVersions []string
		want            bool
	}{
		{"exact match", []string{"claude-opus-4-5-20251101"}, nil, true},
		{"glob match", []string{"claude-*"}, nil, true},
		{"wildcard", []string{"*"}, nil, true},
		{"no match", []string{"claude-sonnet-4"}, nil, false},
		{"multiple with match", []string{"claude-sonnet-4", "claude-opus-4-5-20251101"}, nil, true},
		{"multiple without match", []string{"claude-sonnet-4", "claude-haiku"}, nil, false},
		{"empty allowed = allow all", nil, nil, true},
		{"empty allowed list = allow all", []string{}, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := a.Matches(tt.allowedModels, tt.allowedVersions)
			if got != tt.want {
				t.Errorf("Matches(%v, %v) = %v, want %v", tt.allowedModels, tt.allowedVersions, got, tt.want)
			}
		})
	}
}

func TestMatches_AllowedVersions(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}

	tests := []struct {
		name            string
		allowedModels   []string
		allowedVersions []string
		want            bool
	}{
		{"exact version", []string{"*"}, []string{"4.5.20251101"}, true},
		{"gte version match", []string{"*"}, []string{">=4.0.0"}, true},
		{"gte version no match", []string{"*"}, []string{">=5.0.0"}, false},
		{"x wildcard major", []string{"*"}, []string{"4.x"}, true},
		{"x wildcard no match", []string{"*"}, []string{"5.x"}, false},
		{"star version", []string{"*"}, []string{"*"}, true},
		{"no version constraint", []string{"*"}, nil, true},
		{"empty version constraint", []string{"*"}, []string{}, true},
		{"model mismatch trumps version", []string{"claude-sonnet-*"}, []string{"*"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := a.Matches(tt.allowedModels, tt.allowedVersions)
			if got != tt.want {
				t.Errorf("Matches(%v, %v) = %v, want %v", tt.allowedModels, tt.allowedVersions, got, tt.want)
			}
		})
	}
}

// --- MatchesFunctionary ---

func TestMatchesFunctionary_NonSPIFFEType(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}

	f := Functionary{
		Type: "keyless",
	}

	if a.MatchesFunctionary(f) {
		t.Fatal("Non-SPIFFE functionary should not match")
	}
}

func TestMatchesFunctionary_SPIFFEExactMatch(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}
	a.DeriveIdentity()
	id, err := a.ToSPIFFEID("aflock.ai")
	if err != nil {
		t.Fatalf("ToSPIFFEID failed: %v", err)
	}

	f := Functionary{
		Type:     "spiffe",
		SPIFFEID: id.String(),
	}

	if !a.MatchesFunctionary(f) {
		t.Fatal("Exact SPIFFE ID should match")
	}
}

func TestMatchesFunctionary_SPIFFEIDMismatch(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}
	a.DeriveIdentity()
	a.ToSPIFFEID("aflock.ai")

	f := Functionary{
		Type:     "spiffe",
		SPIFFEID: "spiffe://aflock.ai/agent/different/identity/abcdef1234567890",
	}

	if a.MatchesFunctionary(f) {
		t.Fatal("Mismatched SPIFFE ID should not match")
	}
}

func TestMatchesFunctionary_SPIFFEPattern(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}
	a.DeriveIdentity()
	a.ToSPIFFEID("aflock.ai")

	f := Functionary{
		Type:            "spiffe",
		SPIFFEIDPattern: "spiffe://aflock.ai/agent/*",
	}

	if !a.MatchesFunctionary(f) {
		t.Fatal("Matching SPIFFE ID pattern should match")
	}
}

func TestMatchesFunctionary_SPIFFEPatternMismatch(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}
	a.DeriveIdentity()
	a.ToSPIFFEID("aflock.ai")

	f := Functionary{
		Type:            "spiffe",
		SPIFFEIDPattern: "spiffe://otherdomain.com/*",
	}

	if a.MatchesFunctionary(f) {
		t.Fatal("Non-matching pattern should not match")
	}
}

func TestMatchesFunctionary_TrustDomain(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}
	a.DeriveIdentity()
	a.ToSPIFFEID("aflock.ai")

	// Match
	f1 := Functionary{
		Type:        "spiffe",
		TrustDomain: "aflock.ai",
	}
	if !a.MatchesFunctionary(f1) {
		t.Fatal("Correct trust domain should match")
	}

	// Mismatch
	f2 := Functionary{
		Type:        "spiffe",
		TrustDomain: "other.domain",
	}
	if a.MatchesFunctionary(f2) {
		t.Fatal("Wrong trust domain should not match")
	}
}

func TestMatchesFunctionary_ModelConstraint(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}
	a.DeriveIdentity()
	a.ToSPIFFEID("aflock.ai")

	// Match with glob
	f1 := Functionary{
		Type:            "spiffe",
		ModelConstraint: "claude-opus-*",
	}
	if !a.MatchesFunctionary(f1) {
		t.Fatal("Matching model constraint should match")
	}

	// Mismatch
	f2 := Functionary{
		Type:            "spiffe",
		ModelConstraint: "claude-sonnet-*",
	}
	if a.MatchesFunctionary(f2) {
		t.Fatal("Non-matching model constraint should not match")
	}
}

func TestMatchesFunctionary_VersionConstraint(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}
	a.DeriveIdentity()
	a.ToSPIFFEID("aflock.ai")

	// Match
	f1 := Functionary{
		Type:              "spiffe",
		VersionConstraint: ">=4.0.0",
	}
	if !a.MatchesFunctionary(f1) {
		t.Fatal("Matching version constraint should match")
	}

	// Mismatch
	f2 := Functionary{
		Type:              "spiffe",
		VersionConstraint: ">=5.0.0",
	}
	if a.MatchesFunctionary(f2) {
		t.Fatal("Non-matching version constraint should not match")
	}
}

func TestMatchesFunctionary_CombinedConstraints(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}
	a.DeriveIdentity()
	id, _ := a.ToSPIFFEID("aflock.ai")

	// All constraints match
	f := Functionary{
		Type:              "spiffe",
		SPIFFEID:          id.String(),
		TrustDomain:       "aflock.ai",
		ModelConstraint:   "claude-opus-*",
		VersionConstraint: ">=4.0.0",
	}
	if !a.MatchesFunctionary(f) {
		t.Fatal("All matching constraints should match")
	}

	// One constraint fails
	f.ModelConstraint = "claude-sonnet-*"
	if a.MatchesFunctionary(f) {
		t.Fatal("Any failing constraint should cause non-match")
	}
}

// --- MatchesAnyFunctionary ---

func TestMatchesAnyFunctionary_EmptyList(t *testing.T) {
	a := &AgentIdentity{Model: "test", ModelVersion: "1.0.0"}
	if !a.MatchesAnyFunctionary(nil) {
		t.Fatal("Empty functionary list should match (no constraints)")
	}
	if !a.MatchesAnyFunctionary([]Functionary{}) {
		t.Fatal("Empty functionary slice should match (no constraints)")
	}
}

func TestMatchesAnyFunctionary_OneMatches(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}
	a.DeriveIdentity()
	a.ToSPIFFEID("aflock.ai")

	functionaries := []Functionary{
		{Type: "keyless"}, // won't match
		{Type: "spiffe", ModelConstraint: "claude-sonnet-*"}, // won't match
		{Type: "spiffe", ModelConstraint: "claude-opus-*"},   // matches
	}

	if !a.MatchesAnyFunctionary(functionaries) {
		t.Fatal("Should match when at least one functionary matches")
	}
}

func TestMatchesAnyFunctionary_NoneMatch(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}
	a.DeriveIdentity()
	a.ToSPIFFEID("aflock.ai")

	functionaries := []Functionary{
		{Type: "keyless"},
		{Type: "spiffe", ModelConstraint: "claude-sonnet-*"},
		{Type: "spiffe", VersionConstraint: ">=10.0.0"},
	}

	if a.MatchesAnyFunctionary(functionaries) {
		t.Fatal("Should not match when no functionary matches")
	}
}

// --- ToFunctionary ---

func TestToFunctionary(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}
	a.DeriveIdentity()

	f := a.ToFunctionary("aflock.ai")

	if f.Type != "spiffe" {
		t.Fatalf("Expected type spiffe, got %s", f.Type)
	}
	if f.TrustDomain != "aflock.ai" {
		t.Fatalf("Expected trust domain aflock.ai, got %s", f.TrustDomain)
	}
	if f.ModelConstraint != a.Model {
		t.Fatalf("Expected model constraint %s, got %s", a.Model, f.ModelConstraint)
	}
	if f.VersionConstraint != ">=4.5.20251101" {
		t.Fatalf("Expected version constraint >=4.5.20251101, got %s", f.VersionConstraint)
	}
	if f.SPIFFEID == "" {
		t.Fatal("SPIFFEID should be set")
	}
	if !strings.HasPrefix(f.SPIFFEID, "spiffe://aflock.ai/") {
		t.Fatalf("SPIFFEID should start with spiffe://aflock.ai/, got %s", f.SPIFFEID)
	}
}

func TestToFunctionary_AutoDerivesSPIFFEID(t *testing.T) {
	a := &AgentIdentity{
		Model:        "test-model",
		ModelVersion: "1.0.0",
	}
	// Don't call DeriveIdentity or ToSPIFFEID

	f := a.ToFunctionary("aflock.ai")

	// Should have auto-derived
	if f.SPIFFEID == "" {
		t.Fatal("ToFunctionary should auto-derive SPIFFE ID")
	}
	if a.IdentityHash == "" {
		t.Fatal("ToFunctionary should auto-derive identity hash")
	}
}

// --- String ---

func TestString(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
	}

	str := a.String()

	if !strings.HasPrefix(str, "agent:claude-opus-4-5-20251101@4.5.20251101#") {
		t.Fatalf("Unexpected String() output: %s", str)
	}

	// Hash prefix should be 16 chars
	parts := strings.Split(str, "#")
	if len(parts) != 2 {
		t.Fatalf("Expected exactly one # in String(), got: %s", str)
	}
	if len(parts[1]) != 16 {
		t.Fatalf("Hash prefix should be 16 chars, got %d: %s", len(parts[1]), parts[1])
	}
}

func TestString_AutoDerivesIdentity(t *testing.T) {
	a := &AgentIdentity{
		Model:        "test",
		ModelVersion: "1.0.0",
	}

	str := a.String()

	if a.IdentityHash == "" {
		t.Fatal("String() should auto-derive identity hash")
	}
	if !strings.Contains(str, a.IdentityHash[:16]) {
		t.Fatal("String() should contain first 16 chars of identity hash")
	}
}

// --- MarshalJSON ---

func TestMarshalJSON(t *testing.T) {
	a := &AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
		Binary: &BinaryIdentity{
			Name:    "claude-code",
			Version: "1.0.0",
			Path:    "/usr/local/bin/claude",
		},
		Environment: &EnvironmentIdentity{
			Type: "local",
		},
		Tools: []string{"bash", "read"},
	}
	a.DeriveIdentity()
	a.ToSPIFFEID("aflock.ai")

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Check spiffeId field is present and non-empty
	spiffeID, ok := m["spiffeId"].(string)
	if !ok || spiffeID == "" {
		t.Fatal("spiffeId should be present in JSON output")
	}
	if !strings.HasPrefix(spiffeID, "spiffe://aflock.ai/") {
		t.Fatalf("spiffeId should start with spiffe://aflock.ai/, got: %s", spiffeID)
	}

	// Check model field
	model, ok := m["model"].(string)
	if !ok || model != "claude-opus-4-5-20251101" {
		t.Fatalf("model field mismatch: %v", m["model"])
	}

	// Check identityHash field
	identityHash, ok := m["identityHash"].(string)
	if !ok || identityHash == "" {
		t.Fatal("identityHash should be in JSON output")
	}
}

func TestMarshalJSON_ZeroSPIFFEID(t *testing.T) {
	a := &AgentIdentity{
		Model:        "test",
		ModelVersion: "1.0.0",
	}
	a.DeriveIdentity()
	// Don't call ToSPIFFEID

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// spiffeId should be empty string (zero value) or omitted
	// The custom marshaler always includes it, so check it's reasonable
	if spiffeID, ok := m["spiffeId"]; ok {
		str, isString := spiffeID.(string)
		if isString && strings.HasPrefix(str, "spiffe://") {
			t.Fatal("Zero SPIFFEID should not produce a valid spiffe:// URI")
		}
	}
}

// --- resolveActualBinary ---

func TestResolveActualBinary_RegularFile(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "my-binary")

	// Create a regular binary (not a shell script)
	err := os.WriteFile(binPath, []byte{0x7f, 'E', 'L', 'F'}, 0755)
	if err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	result := resolveActualBinary(binPath)
	// EvalSymlinks resolves /var -> /private/var on macOS
	expectedPath, _ := filepath.EvalSymlinks(binPath)
	if result != expectedPath {
		t.Fatalf("Expected %s, got %s", expectedPath, result)
	}
}

func TestResolveActualBinary_ShellWrapper(t *testing.T) {
	tmpDir := t.TempDir()

	// Resolve tmpDir through EvalSymlinks for macOS /var -> /private/var
	resolvedTmpDir, _ := filepath.EvalSymlinks(tmpDir)

	// Create the actual binary using the resolved path so the exec target is resolved too
	actualBin := filepath.Join(resolvedTmpDir, "actual-binary")
	err := os.WriteFile(actualBin, []byte{0x7f, 'E', 'L', 'F'}, 0755)
	if err != nil {
		t.Fatalf("Failed to create actual binary: %v", err)
	}

	// Create a shell wrapper that execs the actual binary (using resolved path)
	wrapper := filepath.Join(tmpDir, "wrapper")
	wrapperContent := fmt.Sprintf("#!/bin/bash\nexec \"%s\" \"$@\"\n", actualBin)
	err = os.WriteFile(wrapper, []byte(wrapperContent), 0755)
	if err != nil {
		t.Fatalf("Failed to create wrapper: %v", err)
	}

	result := resolveActualBinary(wrapper)
	expectedPath, _ := filepath.EvalSymlinks(actualBin)
	if result != expectedPath {
		t.Fatalf("Expected resolution to %s, got %s", expectedPath, result)
	}
}

func TestResolveActualBinary_Symlink(t *testing.T) {
	tmpDir := t.TempDir()

	// Create the actual binary
	actualBin := filepath.Join(tmpDir, "actual-binary")
	err := os.WriteFile(actualBin, []byte{0x7f, 'E', 'L', 'F'}, 0755)
	if err != nil {
		t.Fatalf("Failed to create actual binary: %v", err)
	}

	// Create a symlink
	symlinkPath := filepath.Join(tmpDir, "symlink-binary")
	err = os.Symlink(actualBin, symlinkPath)
	if err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	result := resolveActualBinary(symlinkPath)
	// EvalSymlinks resolves /var -> /private/var on macOS
	expectedPath, _ := filepath.EvalSymlinks(actualBin)
	if result != expectedPath {
		t.Fatalf("Expected resolution to %s, got %s", expectedPath, result)
	}
}

func TestResolveActualBinary_NonexistentPath(t *testing.T) {
	result := resolveActualBinary("/nonexistent/path/to/binary")
	if result != "/nonexistent/path/to/binary" {
		t.Fatalf("Should return original path for nonexistent file, got %s", result)
	}
}

// --- computeBinaryDigest ---

func TestComputeBinaryDigest(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "test-binary")

	content := []byte("hello world binary content")
	err := os.WriteFile(binPath, content, 0755)
	if err != nil {
		t.Fatalf("Failed to write test binary: %v", err)
	}

	digest := computeBinaryDigest(binPath)
	if digest == "" {
		t.Fatal("Expected non-empty digest for valid file")
	}

	// Verify it's a valid hex string
	if len(digest) != 64 {
		t.Fatalf("SHA256 hex digest should be 64 chars, got %d: %s", len(digest), digest)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		t.Fatalf("Digest is not valid hex: %s", digest)
	}
}

func TestComputeBinaryDigest_Deterministic(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "test-binary")

	content := []byte("deterministic content")
	err := os.WriteFile(binPath, content, 0755)
	if err != nil {
		t.Fatalf("Failed to write test binary: %v", err)
	}

	digest1 := computeBinaryDigest(binPath)
	digest2 := computeBinaryDigest(binPath)

	if digest1 != digest2 {
		t.Fatalf("Digest should be deterministic: %s != %s", digest1, digest2)
	}
}

func TestComputeBinaryDigest_DifferentContentDifferentDigest(t *testing.T) {
	tmpDir := t.TempDir()

	bin1 := filepath.Join(tmpDir, "binary1")
	bin2 := filepath.Join(tmpDir, "binary2")

	os.WriteFile(bin1, []byte("content A"), 0755)
	os.WriteFile(bin2, []byte("content B"), 0755)

	digest1 := computeBinaryDigest(bin1)
	digest2 := computeBinaryDigest(bin2)

	if digest1 == digest2 {
		t.Fatal("Different content should produce different digests")
	}
}

func TestComputeBinaryDigest_NonexistentFile(t *testing.T) {
	digest := computeBinaryDigest("/nonexistent/file/path")
	if digest != "" {
		t.Fatalf("Expected empty digest for nonexistent file, got %s", digest)
	}
}

// --- IsTrustedModel ---

func TestIsTrustedModel(t *testing.T) {
	tests := []struct {
		model string
		want  bool
	}{
		{"claude-opus-4-5-20251101", true},
		{"claude-sonnet-4-20250514", true},
		{"claude-3-5-haiku-20241022", true},
		{"gpt-4", false},
		{"", false},
		{"claude-opus", false},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			got := IsTrustedModel(tt.model)
			if got != tt.want {
				t.Errorf("IsTrustedModel(%q) = %v, want %v", tt.model, got, tt.want)
			}
		})
	}
}

// --- NewSpireClient ---

func TestNewSpireClient_DefaultSocket(t *testing.T) {
	// Clear env var to test default
	orig := os.Getenv(EnvSocketPath)
	os.Unsetenv(EnvSocketPath)
	defer func() {
		if orig != "" {
			os.Setenv(EnvSocketPath, orig)
		}
	}()

	c := NewSpireClient("")
	if c.socketPath != DefaultSocketPath {
		t.Fatalf("Expected default socket path %s, got %s", DefaultSocketPath, c.socketPath)
	}
}

func TestNewSpireClient_EnvOverride(t *testing.T) {
	orig := os.Getenv(EnvSocketPath)
	os.Setenv(EnvSocketPath, "unix:///custom/path.sock")
	defer func() {
		if orig != "" {
			os.Setenv(EnvSocketPath, orig)
		} else {
			os.Unsetenv(EnvSocketPath)
		}
	}()

	c := NewSpireClient("")
	if c.socketPath != "unix:///custom/path.sock" {
		t.Fatalf("Expected env socket path, got %s", c.socketPath)
	}
}

func TestNewSpireClient_ExplicitPath(t *testing.T) {
	c := NewSpireClient("unix:///explicit/path.sock")
	if c.socketPath != "unix:///explicit/path.sock" {
		t.Fatalf("Expected explicit socket path, got %s", c.socketPath)
	}
}
