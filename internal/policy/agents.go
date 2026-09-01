package policy

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aflock-ai/aflock/internal/a2a"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// agentGateState caches verified AgentCards and resolved trust roots for the
// lifetime of one Evaluator (one hook invocation / one MCP server).
type agentGateState struct {
	cards       map[string]cardResult // keyed by card path
	roots       []*x509.Certificate
	rootsErr    error
	rootsLoaded bool
}

type cardResult struct {
	res *a2a.Result
	err error
}

// EvaluateAgentConnection gates agent-to-agent connections (policy.agents).
//
// A tool call is an agent connection when a URL in its input matches one of
// agents.endpoints. For such calls, the pinned signed AgentCard vouching for
// that endpoint is verified (signature, chain to policy roots, card digest)
// and the signing principal — agent / human / workflow, per SAN taxonomy —
// is matched against agents.deny then agents.allow.
//
// Returns the decision, a reason for non-allow, and, for allowed verified
// (or knowingly unverified) connections, a MaterialClassification recording
// the peer so the session state carries a receipt of who was contacted.
func (e *Evaluator) EvaluateAgentConnection(toolName string, toolInput json.RawMessage) (aflock.PermissionDecision, string, *aflock.MaterialClassification) {
	ap := e.policy.Agents
	if ap == nil || len(ap.Endpoints) == 0 {
		return aflock.DecisionAllow, "", nil
	}

	for _, target := range e.extractURLs(toolName, toolInput) {
		if !e.matchesAgentEndpoint(ap, target) {
			continue
		}

		res, why := e.verifyPeerForEndpoint(ap, target)
		if res == nil {
			if ap.RequireSignedCard {
				return aflock.DecisionDeny, fmt.Sprintf("agent endpoint '%s': %s", target, why), nil
			}
			// Unverified peer, permitted by policy — still leave a trace.
			return aflock.DecisionAllow, "", &aflock.MaterialClassification{
				Label:  "agent-connection",
				Source: "unverified|" + target,
			}
		}

		p := res.Principal
		if p.MatchIdentity(ap.Deny) {
			return aflock.DecisionDeny, fmt.Sprintf("peer agent %s:%s matches agents.deny", p.Kind, p.ID), nil
		}
		if len(ap.Allow) > 0 && !p.MatchIdentity(ap.Allow) {
			return aflock.DecisionDeny, fmt.Sprintf("peer agent %s:%s not in agents.allow", p.Kind, p.ID), nil
		}
		return aflock.DecisionAllow, "", &aflock.MaterialClassification{
			Label:  "agent-connection",
			Source: fmt.Sprintf("%s|%s|%s", p.Kind, p.ID, target),
			Digest: map[string]string{"sha256": res.CardDigest},
		}
	}

	return aflock.DecisionAllow, "", nil
}

// extractURLs pulls candidate URLs out of a tool call's input.
func (e *Evaluator) extractURLs(toolName string, toolInput json.RawMessage) []string {
	switch toolName {
	case toolWebFetch:
		var input aflock.WebFetchToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil && input.URL != "" {
			return []string{input.URL}
		}
	case "Bash":
		var input aflock.BashToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil && input.Command != "" {
			var urls []string
			for field := range strings.FieldsSeq(input.Command) {
				token := strings.Trim(field, `"'();,`)
				if strings.Contains(token, "://") {
					urls = append(urls, token)
				}
			}
			return urls
		}
	default:
		if s := e.extractInputForMatching(toolName, toolInput); strings.Contains(s, "://") {
			return []string{s}
		}
	}
	return nil
}

// matchesAgentEndpoint reports whether the URL (or its host) matches any
// agents.endpoints glob.
func (e *Evaluator) matchesAgentEndpoint(ap *aflock.AgentsPolicy, target string) bool {
	host := extractDomain(target)
	for _, pattern := range ap.Endpoints {
		if e.matcher.MatchGlob(pattern, target) || (host != "" && e.matcher.MatchGlob(pattern, host)) {
			return true
		}
	}
	return false
}

// verifyPeerForEndpoint finds a pinned card whose agentCard.url host matches
// the target's host, verified against the policy roots and issuer
// constraints. Returns (nil, reason) when no card vouches for the endpoint.
func (e *Evaluator) verifyPeerForEndpoint(ap *aflock.AgentsPolicy, target string) (*a2a.Result, string) {
	if len(ap.Cards) == 0 {
		return nil, "no AgentCards pinned in agents.cards"
	}
	if e.a2aState == nil {
		e.a2aState = &agentGateState{cards: map[string]cardResult{}}
	}
	st := e.a2aState

	if !st.rootsLoaded {
		st.roots, st.rootsErr = a2a.LoadRoots(e.policy.Roots, e.projectRoot)
		st.rootsLoaded = true
	}
	if st.rootsErr != nil {
		return nil, fmt.Sprintf("failed to load trust roots: %v", st.rootsErr)
	}

	targetHost := extractDomain(target)
	var firstErr string
	for name, path := range ap.Cards {
		full := path
		if !strings.HasPrefix(full, "/") && e.projectRoot != "" {
			full = e.projectRoot + "/" + full
		}
		cached, ok := st.cards[full]
		if !ok {
			cached = verifyCardFile(full, a2a.Options{Roots: st.roots, Issuers: ap.Issuers})
			st.cards[full] = cached
		}
		if cached.err != nil {
			if firstErr == "" {
				firstErr = fmt.Sprintf("card %q failed verification: %v", name, cached.err)
			}
			continue
		}
		if cardHost := extractDomain(cached.res.URL); cardHost != "" && cardHost == targetHost {
			return cached.res, ""
		}
	}
	if firstErr != "" {
		return nil, firstErr
	}
	return nil, "no verified AgentCard vouches for this endpoint"
}

func verifyCardFile(path string, opts a2a.Options) cardResult {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path from operator-authored policy
	if err != nil {
		return cardResult{err: fmt.Errorf("read card: %w", err)}
	}
	res, err := a2a.VerifySignedCard(data, opts)
	return cardResult{res: res, err: err}
}
