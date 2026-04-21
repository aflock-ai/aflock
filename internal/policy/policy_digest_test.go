package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestLoad_RawDigestMatchesFileBytes proves that policy.Load captures the
// digest of the on-disk bytes verbatim — not a re-marshaled normalization
// (issue #61 / L5). Two byte-different files that parse to the same struct
// must produce different RawDigests.
func TestLoad_RawDigestMatchesFileBytes(t *testing.T) {
	dir := t.TempDir()

	// Variant A: minified.
	pathA := filepath.Join(dir, "a.aflock")
	bytesA := []byte(`{"version":"1.0","name":"p"}`)
	if err := os.WriteFile(pathA, bytesA, 0600); err != nil {
		t.Fatalf("write A: %v", err)
	}

	// Variant B: same JSON content, pretty-printed (different bytes).
	pathB := filepath.Join(dir, "b.aflock")
	bytesB := []byte("{\n  \"version\": \"1.0\",\n  \"name\": \"p\"\n}\n")
	if err := os.WriteFile(pathB, bytesB, 0600); err != nil {
		t.Fatalf("write B: %v", err)
	}

	polA, _, err := Load(pathA)
	if err != nil {
		t.Fatalf("load A: %v", err)
	}
	polB, _, err := Load(pathB)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}

	wantA := sha256.Sum256(bytesA)
	if polA.RawDigest != hex.EncodeToString(wantA[:]) {
		t.Errorf("A RawDigest = %s, want digest of file bytes %s",
			polA.RawDigest, hex.EncodeToString(wantA[:]))
	}
	wantB := sha256.Sum256(bytesB)
	if polB.RawDigest != hex.EncodeToString(wantB[:]) {
		t.Errorf("B RawDigest = %s, want digest of file bytes %s",
			polB.RawDigest, hex.EncodeToString(wantB[:]))
	}

	// The two policies parse to the same struct (same Version+Name), but their
	// on-disk bytes differ — so the digests MUST differ. This is the property
	// L5 fixes: previously both produced the same json.Marshal-based digest.
	if polA.RawDigest == polB.RawDigest {
		t.Error("RawDigests must differ when file bytes differ, even if parsed structs match")
	}
}
