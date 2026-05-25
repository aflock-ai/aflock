// Package policy handles loading and parsing .aflock policy files.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// ErrNoTrustConfig is returned when no aflock-trust.json file is found.
// Callers decide whether this is fatal (signed policy required) or fine
// (unsigned policy, warn-only mode).
var ErrNoTrustConfig = errors.New("no aflock-trust.json found")

// LoadTrustConfig resolves a trust config for a given policy path. Resolution
// order, first hit wins:
//  1. $AFLOCK_TRUST_CONFIG (explicit operator override)
//  2. <policy_dir>/aflock-trust.json (per-policy, version-controlled)
//  3. ~/.aflock/trust.json (per-user default)
//
// Trust config files are not policy — an attacker who can write the policy
// must not be able to declare their own trust root, so callers should keep
// these in operator-controlled locations.
func LoadTrustConfig(policyPath string) (*aflock.TrustConfig, string, error) {
	// AFLOCK_TRUST_CONFIG is authoritative: if the operator set it, we don't
	// silently fall through to a policy-dir/home file that might be
	// attacker-controlled. Missing/invalid is a hard error.
	if env := os.Getenv("AFLOCK_TRUST_CONFIG"); env != "" {
		cfg, err := readAndValidate(env)
		if err != nil {
			return nil, "", err
		}
		return cfg, env, nil
	}

	candidates := []string{}
	if policyPath != "" {
		dir := filepath.Dir(policyPath)
		candidates = append(candidates, filepath.Join(dir, "aflock-trust.json"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".aflock", "trust.json"))
	}

	for _, path := range candidates {
		cfg, err := readAndValidate(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, "", err
		}
		return cfg, path, nil
	}

	return nil, "", ErrNoTrustConfig
}

func readAndValidate(path string) (*aflock.TrustConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path from env or known locations
	if err != nil {
		return nil, fmt.Errorf("read trust config %s: %w", path, err)
	}

	var cfg aflock.TrustConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse trust config %s: %w", path, err)
	}

	if err := validateTrustConfig(&cfg); err != nil {
		return nil, fmt.Errorf("invalid trust config %s: %w", path, err)
	}

	return &cfg, nil
}

func validateTrustConfig(cfg *aflock.TrustConfig) error {
	if cfg.Version != "1" {
		return fmt.Errorf("unsupported version %q (want \"1\")", cfg.Version)
	}
	if len(cfg.Verifiers) == 0 {
		return errors.New("verifiers list is empty")
	}
	for i, v := range cfg.Verifiers {
		switch v.Type {
		case "sigstore":
			if v.Issuer == "" {
				return fmt.Errorf("verifier[%d]: issuer is required for type=sigstore", i)
			}
			if v.SubjectPattern == "" {
				return fmt.Errorf("verifier[%d]: subjectPattern is required for type=sigstore (use \"*\" to accept any subject, but prefer a tighter pattern)", i)
			}
		case "pubkey":
			if v.KeyPath == "" {
				return fmt.Errorf("verifier[%d]: keyPath is required for type=pubkey", i)
			}
		default:
			return fmt.Errorf("verifier[%d]: unsupported type %q (want \"sigstore\" or \"pubkey\")", i, v.Type)
		}
	}
	return nil
}
