package verify

import "github.com/aflock-ai/aflock/pkg/aflock"

// applyInherit returns an effective child policy where any section listed
// in inheritFields that the child hasn't declared on its own is filled in
// from the parent's policy.
//
// Spec source: paper §6 "Sublayouts: Hierarchical Delegation" shows
//
//	"inherit": ["domains", "functionaries"]
//
// on the sublayout entry in the parent policy. Example fixture
// examples/compliance-evaluation.aflock also exercises "files".
//
// Semantics:
//   - Inheritance fills nil/empty slots only — if the child has declared its
//     own section (non-nil), the child's value wins. Inheritance never
//     overrides explicit child policy.
//   - The original child policy struct is not mutated. A shallow copy is
//     returned with only the inherited fields rebound to the parent's
//     values. Slices/maps under those fields are shared, not deep-copied —
//     verify is read-only over these structures.
//   - Unknown field names in inheritFields are silently ignored (forward-
//     compatible with future fields the policy schema might add).
//   - Attenuation (separately enforced by verifyAttenuation) still applies
//     — Inherit cannot escalate constraints; it can only fill them in.
//
// Supported field names (lowercase, matching the JSON tag): "domains",
// "functionaries", "files".
func applyInherit(parent, child *aflock.Policy, inheritFields []string) *aflock.Policy {
	if parent == nil || child == nil || len(inheritFields) == 0 {
		return child
	}
	out := *child // shallow copy so the on-disk policy struct stays untouched
	for _, field := range inheritFields {
		switch field {
		case "domains":
			if out.Domains == nil && parent.Domains != nil {
				out.Domains = parent.Domains
			}
		case "functionaries":
			// Two fields carry functionaries: top-level Functionaries
			// (legacy) and Steps.Functionaries (current). Inherit fills
			// whichever the child left empty.
			if len(out.Functionaries) == 0 && len(parent.Functionaries) > 0 {
				out.Functionaries = parent.Functionaries
			}
		case "files":
			if out.Files == nil && parent.Files != nil {
				out.Files = parent.Files
			}
		}
	}
	return &out
}
