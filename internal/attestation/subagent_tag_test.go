package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

func decodeActionPredicate(t *testing.T, env *Envelope) ActionPredicate {
	t.Helper()
	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var stmt Statement
	if err := json.Unmarshal(payloadBytes, &stmt); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}
	predBytes, err := json.Marshal(stmt.Predicate)
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	var pred ActionPredicate
	if err := json.Unmarshal(predBytes, &pred); err != nil {
		t.Fatalf("unmarshal predicate: %v", err)
	}
	return pred
}

// Task/Agent attestations are tagged as trust-boundary crossings (#100); other
// tools are not.
func TestCreateActionAttestation_TrustBoundaryCrossing(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)
	ctx := context.Background()
	now := time.Now()

	tests := []struct {
		toolName string
		want     bool
	}{
		{"Task", true},
		{"Agent", true},
		{"Bash", false},
		{"Read", false},
	}
	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			rec := aflock.ActionRecord{
				Timestamp: now,
				ToolName:  tt.toolName,
				ToolUseID: "tu_" + tt.toolName,
				Decision:  "allow",
			}
			env, err := signer.CreateActionAttestation(ctx, rec, "session-tb", nil, nil, nil)
			if err != nil {
				t.Fatalf("CreateActionAttestation: %v", err)
			}
			if got := decodeActionPredicate(t, env).TrustBoundaryCrossing; got != tt.want {
				t.Errorf("TrustBoundaryCrossing for %q = %v, want %v", tt.toolName, got, tt.want)
			}
		})
	}
}

// The field is omitted from JSON for non-spawn tools (omitempty), so legacy and
// non-spawn attestations carry no field and verifiers treat it as false.
func TestActionPredicate_TrustBoundaryOmitempty(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)
	rec := aflock.ActionRecord{Timestamp: time.Now(), ToolName: "Bash", ToolUseID: "tu_x", Decision: "allow"}
	env, err := signer.CreateActionAttestation(context.Background(), rec, "s", nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateActionAttestation: %v", err)
	}
	payloadBytes, _ := base64.StdEncoding.DecodeString(env.Payload)
	if strings.Contains(string(payloadBytes), "trustBoundaryCrossing") {
		t.Errorf("trustBoundaryCrossing should be omitted for a non-spawn tool, but the key is present")
	}
}
