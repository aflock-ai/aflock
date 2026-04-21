// Package policy handles loading and parsing .aflock policy files.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// ErrPolicyNotFound is returned when no policy file exists in the search path.
// Callers should distinguish this from parse errors: a missing policy means
// the user hasn't opted in (allow), while a malformed policy means the user
// intended enforcement but the file is broken (deny).
var ErrPolicyNotFound = fmt.Errorf("no policy file found")

// DefaultPolicyNames are the filenames to search for policies.
var DefaultPolicyNames = []string{
	".aflock",
	"policy.aflock",
	".aflock.json",
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

	var policy aflock.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, "", fmt.Errorf("parse policy: %w", err)
	}

	// Bind the digest to the exact file bytes the user signed/reviewed
	// (issue #61 / L5). Re-marshaling the parsed struct would normalize
	// whitespace, key order, and number formatting, producing a digest that
	// drifts from the on-disk representation.
	rawHash := sha256.Sum256(data)
	policy.RawDigest = hex.EncodeToString(rawHash[:])

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
