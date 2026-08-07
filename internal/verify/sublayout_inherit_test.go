package verify

import (
	"reflect"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// TestApplyInherit_NilInputs guards the degenerate cases — neither side
// missing should panic, and an empty inherit list is a no-op.
func TestApplyInherit_NilInputs(t *testing.T) {
	child := &aflock.Policy{Name: "child"}
	if got := applyInherit(nil, child, []string{"domains"}); got != child {
		t.Error("nil parent should return child unchanged")
	}
	if got := applyInherit(&aflock.Policy{}, nil, []string{"domains"}); got != nil {
		t.Error("nil child should return nil unchanged")
	}
	if got := applyInherit(&aflock.Policy{}, child, nil); got != child {
		t.Error("empty inherit list should return child unchanged")
	}
}

// TestApplyInherit_DomainsFilledWhenChildEmpty is the canonical case
// from the paper: child declares no domains, sublayout says inherit
// domains → effective child uses parent's domain rules.
func TestApplyInherit_DomainsFilledWhenChildEmpty(t *testing.T) {
	parent := &aflock.Policy{
		Domains: &aflock.DomainsPolicy{
			Allow: []string{"api.example.com"},
		},
	}
	child := &aflock.Policy{Name: "child"} // no Domains
	got := applyInherit(parent, child, []string{"domains"})
	if got.Domains != parent.Domains {
		t.Errorf("expected child to inherit parent's Domains, got %+v", got.Domains)
	}
	// Original child must not be mutated.
	if child.Domains != nil {
		t.Errorf("original child.Domains was mutated, want nil")
	}
}

// TestApplyInherit_ChildOverrideWins covers the precedence rule: when
// the child declares its own section, Inherit is a no-op for that
// section. Important because inheritance must never override explicit
// child policy (that would be a privilege-escalation-style surprise).
func TestApplyInherit_ChildOverrideWins(t *testing.T) {
	parent := &aflock.Policy{
		Domains: &aflock.DomainsPolicy{Allow: []string{"parent-host"}},
	}
	child := &aflock.Policy{
		Name:    "child",
		Domains: &aflock.DomainsPolicy{Allow: []string{"child-host"}},
	}
	got := applyInherit(parent, child, []string{"domains"})
	if got.Domains == nil || got.Domains.Allow[0] != "child-host" {
		t.Errorf("expected child's own Domains to win, got %+v", got.Domains)
	}
}

// TestApplyInherit_FunctionariesFilled covers the second paper example.
func TestApplyInherit_FunctionariesFilled(t *testing.T) {
	parent := &aflock.Policy{
		Functionaries: []aflock.Functionary{
			{Type: "spiffe", TrustDomain: "aflock.local"},
		},
	}
	child := &aflock.Policy{Name: "child"} // no Functionaries
	got := applyInherit(parent, child, []string{"functionaries"})
	if !reflect.DeepEqual(got.Functionaries, parent.Functionaries) {
		t.Errorf("expected child to inherit Functionaries, got %+v", got.Functionaries)
	}
}

// TestApplyInherit_FilesFilled covers the third field that appears in
// examples/compliance-evaluation.aflock even though the paper doesn't
// list it explicitly. Keeping the fixture honest.
func TestApplyInherit_FilesFilled(t *testing.T) {
	parent := &aflock.Policy{
		Files: &aflock.FilesPolicy{Allow: []string{"cmd/**"}},
	}
	child := &aflock.Policy{Name: "child"}
	got := applyInherit(parent, child, []string{"files"})
	if got.Files != parent.Files {
		t.Errorf("expected child to inherit Files, got %+v", got.Files)
	}
}

// TestApplyInherit_UnknownFieldIgnored guards forward compatibility:
// declaring inherit for a field the verifier doesn't know about must
// not panic or fail. The unknown name is silently dropped.
func TestApplyInherit_UnknownFieldIgnored(t *testing.T) {
	parent := &aflock.Policy{Name: "parent"}
	child := &aflock.Policy{Name: "child"}
	got := applyInherit(parent, child, []string{"some-future-field"})
	if got.Name != "child" {
		t.Errorf("expected pass-through, got %+v", got)
	}
}

// TestApplyInherit_MultipleFields combines all three known fields in a
// single inherit declaration — the realistic use from the compliance
// example: inherit: ["files", "domains", "functionaries"].
func TestApplyInherit_MultipleFields(t *testing.T) {
	parent := &aflock.Policy{
		Domains: &aflock.DomainsPolicy{Allow: []string{"p"}},
		Files:   &aflock.FilesPolicy{Allow: []string{"p/**"}},
		Functionaries: []aflock.Functionary{
			{Type: "keyless"},
		},
	}
	child := &aflock.Policy{Name: "child"}
	got := applyInherit(parent, child, []string{"files", "domains", "functionaries"})
	if got.Domains != parent.Domains || got.Files != parent.Files {
		t.Errorf("expected all three sections inherited, got %+v", got)
	}
	if len(got.Functionaries) != 1 || got.Functionaries[0].Type != "keyless" {
		t.Errorf("expected functionaries inherited, got %+v", got.Functionaries)
	}
}

// TestApplyInherit_DoesNotMutateOriginal is a defensive check: the
// returned policy is a fresh shallow copy. Mutating it should not
// affect the parent's struct (the parent is shared by other sublayouts).
func TestApplyInherit_DoesNotMutateOriginal(t *testing.T) {
	parent := &aflock.Policy{
		Domains: &aflock.DomainsPolicy{Allow: []string{"parent"}},
	}
	child := &aflock.Policy{Name: "child"}
	got := applyInherit(parent, child, []string{"domains"})
	// Verify we got a distinct pointer
	if got == child {
		t.Error("applyInherit returned the same pointer; expected a shallow copy")
	}
	// Mutating returned policy's Name shouldn't touch original child
	got.Name = "mutated"
	if child.Name != "child" {
		t.Errorf("mutation of returned policy leaked to original child: %s", child.Name)
	}
}

// TestVerifySession_SublayoutInheritOverlayConsumed proves the
// inheritOverlay wiring in verifySublayouts → verifySessionWithDepth
// works end-to-end: the parent declares a sublayout with Inherit, the
// recursive verify stages the overlay before recursion, the child
// verify consumes it, and pendingInherit is cleared after.
func TestVerifySession_SublayoutInheritOverlayConsumed(t *testing.T) {
	tmpDir := t.TempDir()

	childState := &aflock.SessionState{
		SessionID:           "child-inherit",
		ParentSessionID:     "parent-inherit",
		ParentSublayoutName: "with-inherit",
		Policy: &aflock.Policy{
			Name:    "researcher",
			Version: "1.0",
			// No Functionaries — must be filled in by Inherit.
		},
		Metrics: &aflock.SessionMetrics{Tools: map[string]int{}},
	}
	writeSessionState(t, tmpDir, "child-inherit", childState)

	parentState := &aflock.SessionState{
		SessionID: "parent-inherit",
		Policy: &aflock.Policy{
			Name:    "main",
			Version: "1.0",
			Functionaries: []aflock.Functionary{
				{Type: "spiffe", TrustDomain: "aflock.local"},
			},
			Sublayouts: []aflock.Sublayout{
				{
					Name:    "with-inherit",
					Policy:  "researcher.aflock",
					Inherit: []string{"functionaries"},
				},
			},
		},
		Metrics:         &aflock.SessionMetrics{Tools: map[string]int{}},
		ChildSessionIDs: []string{"child-inherit"},
	}
	writeSessionState(t, tmpDir, "parent-inherit", parentState)

	v := newTestVerifier(tmpDir)
	if _, err := v.VerifySession("parent-inherit"); err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	// After the recursion completes, pendingInherit must be cleared
	// either by the consume-on-load path or the defer-clear in
	// verifySublayouts. A stale overlay would leak into the NEXT verify.
	if v.pendingInherit != nil {
		t.Errorf("pendingInherit should be cleared after verify, got %+v", v.pendingInherit)
	}

	// The on-disk child policy file must remain unchanged — overlay is
	// an in-memory verifier-side concern. Reload and re-check.
	reloaded, err := v.stateManager.Load("child-inherit")
	if err != nil {
		t.Fatalf("reload child: %v", err)
	}
	if len(reloaded.Policy.Functionaries) != 0 {
		t.Errorf("on-disk child policy should keep its empty Functionaries; overlay must not persist. got %+v",
			reloaded.Policy.Functionaries)
	}
}
