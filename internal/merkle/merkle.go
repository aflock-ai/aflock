// Package merkle provides RFC 6962 Merkle tree operations for session log integrity.
//
// It wraps github.com/transparency-dev/merkle (the same library Sigstore's Rekor uses)
// to provide domain-separated hash computation and incremental tree building via compact ranges.
//
// Session JSONL entries are canonicalized using RFC 8785 (JCS) before hashing to ensure
// cross-implementation compatibility.
//
// Hash scheme (RFC 6962):
//
//	Leaf:  SHA-256(0x00 || data)
//	Node:  SHA-256(0x01 || left || right)
package merkle

import (
	"bytes"
	"encoding/hex"
	"fmt"

	jsoncanon "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
)

var hasher = rfc6962.DefaultHasher

// HashLeaf computes the RFC 6962 leaf hash: SHA-256(0x00 || data).
func HashLeaf(data []byte) []byte {
	return hasher.HashLeaf(data)
}

// Canonicalize applies RFC 8785 (JCS) canonicalization to a JSON entry.
// This ensures deterministic serialization for cross-implementation compatibility.
func Canonicalize(jsonData []byte) ([]byte, error) {
	canonical, err := jsoncanon.Transform(jsonData)
	if err != nil {
		return nil, fmt.Errorf("JCS canonicalization failed: %w", err)
	}
	return canonical, nil
}

// BuildRoot computes the Merkle tree root over a list of raw entries.
// Each entry is canonicalized (JCS) then hashed as an RFC 6962 leaf.
// Returns the root hash as a hex string, or an error if any entry fails canonicalization.
func BuildRoot(entries [][]byte) (string, error) {
	if len(entries) == 0 {
		return hex.EncodeToString(hasher.EmptyRoot()), nil
	}

	factory := &compact.RangeFactory{Hash: hasher.HashChildren}
	cr := factory.NewEmptyRange(0)

	for i, entry := range entries {
		canonical, err := Canonicalize(entry)
		if err != nil {
			return "", fmt.Errorf("entry %d: %w", i, err)
		}
		leafHash := HashLeaf(canonical)
		if err := cr.Append(leafHash, nil); err != nil {
			return "", fmt.Errorf("append entry %d: %w", i, err)
		}
	}

	root, err := cr.GetRootHash(nil)
	if err != nil {
		return "", fmt.Errorf("compute root: %w", err)
	}
	return hex.EncodeToString(root), nil
}

// VerifyRoot recomputes the Merkle root from entries and compares it to the expected root.
// Returns nil if the roots match, or an error describing the mismatch.
func VerifyRoot(entries [][]byte, expectedRootHex string) error {
	computedHex, err := BuildRoot(entries)
	if err != nil {
		return fmt.Errorf("build root: %w", err)
	}

	if computedHex != expectedRootHex {
		return fmt.Errorf("merkle root mismatch: computed %s, expected %s", computedHex, expectedRootHex)
	}
	return nil
}

// TreeBuilder incrementally builds a Merkle tree as entries are appended.
// It uses compact ranges, requiring only O(log n) memory.
type TreeBuilder struct {
	cr    *compact.Range
	count uint64
}

// NewTreeBuilder creates a new incremental Merkle tree builder.
func NewTreeBuilder() *TreeBuilder {
	factory := &compact.RangeFactory{Hash: hasher.HashChildren}
	return &TreeBuilder{
		cr: factory.NewEmptyRange(0),
	}
}

// Append adds a raw JSON entry to the tree. The entry is canonicalized and leaf-hashed.
func (b *TreeBuilder) Append(jsonEntry []byte) error {
	canonical, err := Canonicalize(jsonEntry)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}
	leafHash := HashLeaf(canonical)
	if err := b.cr.Append(leafHash, nil); err != nil {
		return fmt.Errorf("append: %w", err)
	}
	b.count++
	return nil
}

// Root returns the current Merkle root hash as a hex string.
func (b *TreeBuilder) Root() (string, error) {
	if b.count == 0 {
		return hex.EncodeToString(hasher.EmptyRoot()), nil
	}
	root, err := b.cr.GetRootHash(nil)
	if err != nil {
		return "", fmt.Errorf("get root: %w", err)
	}
	return hex.EncodeToString(root), nil
}

// Count returns the number of entries appended.
func (b *TreeBuilder) Count() uint64 {
	return b.count
}

// VerifyRootBytes compares a computed root (raw bytes) against an expected root (hex).
func VerifyRootBytes(computedRoot []byte, expectedRootHex string) error {
	expectedRoot, err := hex.DecodeString(expectedRootHex)
	if err != nil {
		return fmt.Errorf("decode expected root: %w", err)
	}
	if !bytes.Equal(computedRoot, expectedRoot) {
		return fmt.Errorf("merkle root mismatch: computed %x, expected %s",
			computedRoot, expectedRootHex)
	}
	return nil
}
