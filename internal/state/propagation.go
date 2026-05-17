package state

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

const (
	// PropagationTTL is the maximum age of a propagation record before it's
	// considered expired. Children that start after this window inherit nothing.
	PropagationTTL = 60 * time.Second

	// propagationDir is the subdirectory under ~/.aflock for propagation files.
	propagationDir = "propagation"
)

// propagationBaseDir returns the absolute path to the propagation directory.
func propagationBaseDir() string {
	return expandPath("~/.aflock/" + propagationDir)
}

// propagationKeyPrefix returns the deterministic per-policy prefix used to
// group all propagation files for the given policy path. SHA-256 of the
// absolute path keeps different policies in disjoint namespaces.
//
// Earlier versions of this code used the prefix as the WHOLE filename, which
// meant two concurrent parent spawns of the same policy raced on a single
// file and one's record silently overwrote the other (issue #26 gap 6). The
// prefix is now combined with a per-call nonce in propagationFilename so
// every Write produces a distinct file.
func propagationKeyPrefix(policyPath string) string {
	abs, err := filepath.Abs(policyPath)
	if err != nil {
		abs = policyPath
	}
	h := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(h[:])
}

// propagationFilename returns a unique filename for a fresh propagation
// record under the given policy's prefix. Combines a monotonic timestamp
// with 8 random bytes so concurrent writers from different processes can
// never collide (issue #26 gap 6).
func propagationFilename(policyPath string) (string, error) {
	prefix := propagationKeyPrefix(policyPath)
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate propagation nonce: %w", err)
	}
	return fmt.Sprintf("%s.%d-%s.json", prefix, time.Now().UnixNano(), hex.EncodeToString(nonce[:])), nil
}

// WritePropagation writes a propagation file so that a child session can
// inherit the parent's materials, metrics, and attenuated limits. Each call
// produces a distinct file (issue #26 gap 6) — concurrent spawns of the
// same policy no longer overwrite each other.
func (m *Manager) WritePropagation(parentState *aflock.SessionState) error {
	dir := propagationBaseDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create propagation dir: %w", err)
	}

	rec := aflock.PropagationRecord{
		ParentSessionID: parentState.SessionID,
		PolicyPath:      parentState.PolicyPath,
		Materials:       parentState.Materials,
		ParentMetrics:   parentState.Metrics,
		CreatedAt:       time.Now(),
	}
	if parentState.Policy != nil {
		rec.ParentLimits = parentState.Policy.Limits
	}

	data, err := json.Marshal(&rec)
	if err != nil {
		return fmt.Errorf("marshal propagation: %w", err)
	}

	name, err := propagationFilename(parentState.PolicyPath)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write propagation: %w", err)
	}

	return nil
}

// ReadPropagation reads and consumes a single propagation file for the
// given policy path. Returns nil if no file exists or all that exist are
// expired.
//
// Multi-file claim: parents may have written several files (issue #26 gap
// 6), one per spawn. ReadPropagation enumerates all files matching the
// policy prefix, picks the oldest first (FIFO so children consume in
// spawn order), and atomically claims it via rename. Concurrent readers
// racing on the same file resolve via rename's atomicity — only one wins,
// the other tries the next file. Expired records are removed in passing so
// stale state doesn't block fresh children indefinitely.
func (m *Manager) ReadPropagation(policyPath string) (*aflock.PropagationRecord, error) {
	prefix := propagationKeyPrefix(policyPath)
	dir := propagationBaseDir()

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read propagation dir: %w", err)
	}

	type candidate struct {
		name    string
		modTime time.Time
	}
	var candidates []candidate
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip files that don't belong to this policy or are already
		// in-flight consumption markers (which carry ".consumed." in
		// the suffix).
		if len(name) < len(prefix)+1 || name[:len(prefix)] != prefix || name[len(prefix)] != '.' {
			continue
		}
		if containsConsumedMarker(name) {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		candidates = append(candidates, candidate{name: name, modTime: info.ModTime()})
	}

	// FIFO: oldest first.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].modTime.Before(candidates[j].modTime)
	})

	for _, c := range candidates {
		path := filepath.Join(dir, c.name)
		claimed := filepath.Join(dir, fmt.Sprintf("%s.consumed.%d.%d", c.name, os.Getpid(), time.Now().UnixNano()))
		if err := os.Rename(path, claimed); err != nil {
			if os.IsNotExist(err) {
				// Another reader won the race on this file — try the next one.
				continue
			}
			return nil, fmt.Errorf("claim propagation: %w", err)
		}

		data, err := os.ReadFile(claimed) //nolint:gosec // G304: path derived from validated entry under propagation dir
		if err != nil {
			_ = os.Remove(claimed)
			return nil, fmt.Errorf("read propagation: %w", err)
		}

		var rec aflock.PropagationRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			_ = os.Remove(claimed)
			return nil, fmt.Errorf("parse propagation: %w", err)
		}

		_ = os.Remove(claimed)

		// Expired records are silently skipped — don't waste a fresh spawn
		// on stale state. Continue scanning for a live one.
		if rec.IsExpiredPropagation(PropagationTTL) {
			continue
		}
		return &rec, nil
	}

	return nil, nil
}

// containsConsumedMarker reports whether the filename has the ".consumed."
// substring that ReadPropagation writes during atomic claim. Skipping these
// keeps a concurrent reader from trying to claim a marker that's already in
// the cleanup window.
func containsConsumedMarker(name string) bool {
	for i := 0; i+len(".consumed.") <= len(name); i++ {
		if name[i:i+len(".consumed.")] == ".consumed." {
			return true
		}
	}
	return false
}

// CleanStalePropagation removes propagation files older than 2x TTL.
// This is a housekeeping function to prevent accumulation of orphaned files.
func (m *Manager) CleanStalePropagation() {
	dir := propagationBaseDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	maxAge := 2 * PropagationTTL
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		// Clean up both live propagation records and orphaned .consumed
		// markers left behind by crashed readers.
		if time.Since(info.ModTime()) > maxAge {
			os.Remove(filepath.Join(dir, entry.Name())) //nolint:errcheck // best-effort cleanup
		}
	}
}
