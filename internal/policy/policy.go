// Package policy handles loading and parsing .aflock policy files.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// ErrPolicyNotFound is returned when no policy file exists in the search path.
// Callers should distinguish this from parse errors: a missing policy means
// the user hasn't opted in (allow), while a malformed policy means the user
// intended enforcement but the file is broken (deny).
var ErrPolicyNotFound = fmt.Errorf("no policy file found")

// DefaultPolicyNames are the filenames to search for policies. Signed
// variants are checked before their unsigned counterparts so that signed
// policies take precedence when both exist on disk.
var DefaultPolicyNames = []string{
	".aflock.signed",
	"policy.aflock.signed",
	".aflock.json.signed",
	".aflock",
	"policy.aflock",
	".aflock.json",
}

// requireSignedPolicy reports whether the operator has demanded that every
// load go through signature verification. Default is warn-only so existing
// unsigned policies keep working through the migration.
func requireSignedPolicy() bool {
	v := os.Getenv("AFLOCK_REQUIRE_SIGNED_POLICY")
	return v == "1" || v == "true"
}

// Load loads a policy from the specified path or searches for one in the directory.
func Load(path string) (*aflock.Policy, string, error) {
	// Resolve relative paths to absolute
	if !filepath.IsAbs(path) {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, "", fmt.Errorf("resolve path: %w", err)
		}
		path = absPath
	}

	// If path is a directory, search for policy files
	info, err := os.Stat(path) //nolint:gosec // G703: path traversal taint from CLI config, not user-controlled
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", fmt.Errorf("stat path: %w: %w", err, ErrPolicyNotFound)
		}
		return nil, "", fmt.Errorf("stat path: %w", err)
	}

	var policyPath string
	if info.IsDir() {
		policyPath, err = findPolicy(path)
		if err != nil {
			return nil, "", err
		}
	} else {
		policyPath = path
	}

	data, err := os.ReadFile(policyPath) //nolint:gosec // G304: policy file path from CLI config
	if err != nil {
		return nil, "", fmt.Errorf("read policy file: %w", err)
	}

	var sigInfo *aflock.SignatureInfo

	// If the bytes look like a DSSE envelope for an aflock policy, we MUST
	// verify or hard-fail. Falling back to raw parsing on verification failure
	// would silently downgrade a signed-policy intent into an unsigned one
	// (the original #133 fail-open). Once envelope shape is detected, the
	// only safe outcomes are verified-success or error.
	if isEnvelope(data) {
		// policyPath is passed in but ignored as a trust-config candidate —
		// see LoadTrustConfig's docstring for the threat model.
		trust, trustPath, err := LoadTrustConfig(policyPath)
		if err != nil {
			msg := "load trust config for signed policy"
			if errors.Is(err, ErrNoTrustConfig) {
				msg = "policy is signed but no trust config found (set $AFLOCK_TRUST_CONFIG or create ~/.aflock/trust.json)"
			}
			return nil, "", fmt.Errorf("%s: %w (see docs/concepts/policies.md#signing-and-trust)", msg, err)
		}
		inner, info, err := verifyAndUnwrap(context.Background(), data, trust)
		if err != nil {
			return nil, "", fmt.Errorf("verify signed policy (trust=%s): %w", trustPath, err)
		}
		data = inner
		sigInfo = info
	} else if requireSignedPolicy() {
		return nil, "", fmt.Errorf("%w (path=%s)", ErrUnsignedRequired, policyPath)
	} else {
		slog.Warn("loading unsigned policy; set AFLOCK_REQUIRE_SIGNED_POLICY=1 to enforce", "path", policyPath)
	}

	var policy aflock.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, "", fmt.Errorf("parse policy: %w", err)
	}

	// Resolve ${...} placeholders against the environment (paper §4.4 / #134).
	// Done after unmarshal so every consumer (verifier, hooks, MCP) sees
	// fully-expanded values rather than literal placeholder strings.
	if err := expandPlaceholders(&policy, os.Getenv); err != nil {
		return nil, "", fmt.Errorf("expand placeholders: %w", err)
	}

	// Bind the digest to the exact file bytes the user signed/reviewed
	// (issue #61 / L5). For envelope-loaded policies this hashes the INNER
	// payload, not the envelope, so JWT binding stays invariant under
	// re-signing with a different ephemeral Fulcio cert.
	rawHash := sha256.Sum256(data)
	policy.RawDigest = hex.EncodeToString(rawHash[:])
	policy.SignatureInfo = sigInfo

	return &policy, policyPath, nil
}

// findPolicy searches for a policy file in the given directory.
func findPolicy(dir string) (string, error) {
	for _, name := range DefaultPolicyNames {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil { //nolint:gosec // G703: path from CLI config
			return path, nil
		}
	}
	return "", fmt.Errorf("%w in %s (tried: %v)", ErrPolicyNotFound, dir, DefaultPolicyNames)
}

// LoadFromEnv loads a policy from the AFLOCK_POLICY environment variable path.
func LoadFromEnv() (*aflock.Policy, string, error) {
	path := os.Getenv("AFLOCK_POLICY")
	if path == "" {
		return nil, "", fmt.Errorf("AFLOCK_POLICY environment variable not set")
	}
	return Load(path)
}
