// Package verify implements attestation verification against policy.
package verify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/aflock/internal/aieval"
	"github.com/aflock-ai/aflock/internal/attestation"
	aflockMerkle "github.com/aflock-ai/aflock/internal/merkle"
	"github.com/aflock-ai/aflock/internal/policy"
	aflockRego "github.com/aflock-ai/aflock/internal/rego"
	"github.com/aflock-ai/aflock/internal/state"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Type aliases to avoid import conflicts with internal package names.
type ed25519PublicKey = ed25519.PublicKey

var ed25519Verify = ed25519.Verify

// Result represents the verification result.
type Result struct {
	Success    bool            `json:"success"`
	SessionID  string          `json:"sessionId"`
	PolicyName string          `json:"policyName"`
	VerifiedAt time.Time       `json:"verifiedAt"`
	Checks     []CheckResult   `json:"checks"`
	Metrics    *MetricsSummary `json:"metrics,omitempty"`
	Errors     []string        `json:"errors,omitempty"`
	Warnings   []string        `json:"warnings,omitempty"`
}

// CheckResult represents a single verification check.
type CheckResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

// MetricsSummary summarizes session metrics.
type MetricsSummary struct {
	TotalTurns     int     `json:"totalTurns"`
	TotalToolCalls int     `json:"totalToolCalls"`
	TotalTokensIn  int64   `json:"totalTokensIn"`
	TotalTokensOut int64   `json:"totalTokensOut"`
	TotalCostUSD   float64 `json:"totalCostUSD"`
	Duration       string  `json:"duration"`
}

// Verifier verifies session attestations against policy.
type Verifier struct {
	stateManager *state.Manager
	SkipAI       bool // Skip Phase 5 (AI Evaluation)
}

// NewVerifier creates a new verifier.
func NewVerifier() *Verifier {
	return &Verifier{
		stateManager: state.NewManager(""),
	}
}

// maxSublayoutDepth is the maximum recursion depth for sublayout verification.
// Prevents stack overflow from cyclic or deeply nested sublayout chains (issue #60 / I4).
const maxSublayoutDepth = 10

// VerifySession verifies a session's attestations against its policy.
//
//nolint:gocognit,gocyclo,funlen // session verification requires many validation steps
func (v *Verifier) VerifySession(sessionID string) (*Result, error) {
	return v.verifySessionWithDepth(sessionID, 0)
}

func (v *Verifier) verifySessionWithDepth(sessionID string, depth int) (*Result, error) {
	if depth > maxSublayoutDepth {
		return nil, fmt.Errorf("sublayout recursion depth exceeded (%d > %d)", depth, maxSublayoutDepth)
	}

	result := &Result{
		SessionID:  sessionID,
		VerifiedAt: time.Now(),
		Success:    true,
	}

	// Load session state
	sessionState, err := v.stateManager.Load(sessionID)
	if err != nil {
		return nil, fmt.Errorf("load session state: %w", err)
	}
	if sessionState == nil {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	result.PolicyName = sessionState.Policy.Name

	// Build metrics summary
	if sessionState.Metrics != nil {
		result.Metrics = &MetricsSummary{
			TotalTurns:     sessionState.Metrics.Turns,
			TotalToolCalls: sessionState.Metrics.ToolCalls,
			TotalTokensIn:  sessionState.Metrics.TokensIn,
			TotalTokensOut: sessionState.Metrics.TokensOut,
			TotalCostUSD:   sessionState.Metrics.CostUSD,
			Duration:       time.Since(sessionState.StartedAt).Round(time.Second).String(),
		}
	}

	// Phase 1: Attestation signature verification
	// Verify DSSE signatures on all attestation files in the session's attestation directory.
	// This prevents accepting forged or tampered attestation data.
	attestDir := v.stateManager.AttestationsDir(sessionID)
	if sigErrors := v.verifySessionAttestationSignatures(attestDir, sessionState); len(sigErrors) > 0 {
		result.Success = false
		for _, msg := range sigErrors {
			result.Checks = append(result.Checks, CheckResult{
				Name:    "signatures",
				Passed:  false,
				Message: msg,
			})
			result.Errors = append(result.Errors, msg)
		}
	} else {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "signatures",
			Passed: true,
		})
	}

	// Phase 1b: Session binding and timestamp freshness (anti-replay)
	if bindErrors := v.verifySessionBinding(attestDir, sessionID, sessionState.StartedAt); len(bindErrors) > 0 {
		result.Success = false
		for _, msg := range bindErrors {
			result.Checks = append(result.Checks, CheckResult{
				Name:    "session-binding",
				Passed:  false,
				Message: msg,
			})
			result.Errors = append(result.Errors, msg)
		}
	} else {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "session-binding",
			Passed: true,
		})
	}

	// Check 0: Identity verification (Phase 2)
	if sessionState.Policy.Identity != nil {
		id := IdentityFields{}
		if sessionState.AgentIdentityMeta != nil {
			id.Model = sessionState.AgentIdentityMeta.Model
			id.Environment = sessionState.AgentIdentityMeta.Environment
		}
		// Extract tools from session metrics (tool names that were used)
		if sessionState.Metrics != nil && sessionState.Metrics.Tools != nil {
			for toolName := range sessionState.Metrics.Tools {
				id.Tools = append(id.Tools, toolName)
			}
			sort.Strings(id.Tools)
		}
		identityErrors := verifyIdentityConstraints(id, sessionState.Policy.Identity)
		if len(identityErrors) > 0 {
			result.Success = false
			for _, msg := range identityErrors {
				result.Checks = append(result.Checks, CheckResult{
					Name:    "identity",
					Passed:  false,
					Message: msg,
				})
				result.Errors = append(result.Errors, msg)
			}
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "identity",
				Passed: true,
			})
		}
	}

	// Check 0.5: Materials binding / Merkle tree (Phase 3)
	if sessionState.Policy.MaterialsFrom != nil && sessionState.Policy.MaterialsFrom.Session != nil {
		merkleErrors := verifySessionMerkle(sessionState)
		if len(merkleErrors) > 0 {
			result.Success = false
			for _, msg := range merkleErrors {
				result.Checks = append(result.Checks, CheckResult{
					Name:    "materials:merkle",
					Passed:  false,
					Message: msg,
				})
				result.Errors = append(result.Errors, msg)
			}
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "materials:merkle",
				Passed: true,
			})
		}
	}

	// Check 0.7: Rego constraint evaluation (Phase 4)
	if sessionState.Policy.Evaluators != nil && len(sessionState.Policy.Evaluators.Rego) > 0 {
		regoErrors := evaluateSessionRego(sessionState)
		if len(regoErrors) > 0 {
			result.Success = false
			for _, msg := range regoErrors {
				result.Checks = append(result.Checks, CheckResult{
					Name:    "rego",
					Passed:  false,
					Message: msg,
				})
				result.Errors = append(result.Errors, msg)
			}
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "rego",
				Passed: true,
			})
		}
	}

	// Check 0.8: AI Evaluation (Phase 5)
	if sessionState.Policy.Evaluators != nil && len(sessionState.Policy.Evaluators.AI) > 0 {
		if v.SkipAI {
			result.Checks = append(result.Checks, CheckResult{
				Name:    "ai",
				Passed:  true,
				Message: "Skipped: --skip-ai flag set",
			})
			result.Warnings = append(result.Warnings, "Phase 5 (AI Evaluation) skipped: --skip-ai flag set")
		} else {
			aiErrors := evaluateSessionAI(sessionState)
			if len(aiErrors) > 0 {
				result.Success = false
				for _, msg := range aiErrors {
					result.Checks = append(result.Checks, CheckResult{
						Name:    "ai",
						Passed:  false,
						Message: msg,
					})
					result.Errors = append(result.Errors, msg)
				}
			} else {
				result.Checks = append(result.Checks, CheckResult{
					Name:   "ai",
					Passed: true,
				})
			}
		}
	}

	// Check 1: Policy limits (post-hoc)
	if sessionState.Policy.Limits != nil {
		evaluator := policy.NewEvaluator(sessionState.Policy, filepath.Dir(sessionState.PolicyPath))
		exceeded, limitName, msg := evaluator.CheckLimits(sessionState.Metrics, "post-hoc")
		if exceeded {
			result.Success = false
			result.Checks = append(result.Checks, CheckResult{
				Name:    "limits:" + limitName,
				Passed:  false,
				Message: msg,
			})
			result.Errors = append(result.Errors, msg)
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "limits:post-hoc",
				Passed: true,
			})
		}
	}

	// Check 2: Required attestations
	if len(sessionState.Policy.RequiredAttestations) > 0 {
		for _, required := range sessionState.Policy.RequiredAttestations {
			found := v.findAttestation(attestDir, required)
			if !found {
				result.Success = false
				result.Checks = append(result.Checks, CheckResult{
					Name:    "attestation:" + required,
					Passed:  false,
					Message: fmt.Sprintf("Required attestation '%s' not found", required),
				})
				result.Errors = append(result.Errors, fmt.Sprintf("Missing attestation: %s", required))
			} else {
				result.Checks = append(result.Checks, CheckResult{
					Name:   "attestation:" + required,
					Passed: true,
				})
			}
		}
	}

	// Check 3: Data flow violations
	if len(sessionState.Materials) > 0 {
		// Check if any actions were blocked due to data flow
		for _, action := range sessionState.Actions {
			if action.Decision == "deny" && strings.Contains(action.Reason, "Data flow") {
				result.Success = false
				result.Checks = append(result.Checks, CheckResult{
					Name:    "dataflow:" + action.ToolUseID,
					Passed:  false,
					Message: action.Reason,
				})
				result.Errors = append(result.Errors, action.Reason)
			}
		}
		if !containsCheckPrefix(result.Checks, "dataflow:") {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "dataflow",
				Passed: true,
			})
		}
	}

	// Check 4: Denied actions summary
	deniedCount := 0
	for _, action := range sessionState.Actions {
		if action.Decision == "deny" {
			deniedCount++
		}
	}
	if deniedCount > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("%d actions were blocked by policy", deniedCount))
	}
	result.Checks = append(result.Checks, CheckResult{
		Name:    "actions",
		Passed:  true,
		Message: fmt.Sprintf("%d total actions, %d blocked", len(sessionState.Actions), deniedCount),
	})

	// Check 5: Sublayout recursion (Phase 6)
	if len(sessionState.Policy.Sublayouts) > 0 && len(sessionState.ChildSessionIDs) > 0 {
		sublayoutErrors := v.verifySublayouts(sessionState, depth)
		if len(sublayoutErrors) > 0 {
			result.Success = false
			for _, msg := range sublayoutErrors {
				result.Checks = append(result.Checks, CheckResult{
					Name:    "sublayout",
					Passed:  false,
					Message: msg,
				})
				result.Errors = append(result.Errors, msg)
			}
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "sublayout",
				Passed: true,
			})
		}
	}

	return result, nil
}

// VerifyLatestSession finds and verifies the most recent session.
func (v *Verifier) VerifyLatestSession() (*Result, error) {
	stateDir := filepath.Join(os.Getenv("HOME"), ".aflock", "sessions")
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return nil, fmt.Errorf("read sessions dir: %w", err)
	}

	var latestSession string
	var latestTime time.Time

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		statePath := filepath.Join(stateDir, entry.Name(), "state.json")
		info, err := os.Stat(statePath) //nolint:gosec // G703: path from attestation directory
		if err != nil {
			continue
		}
		if info.ModTime().After(latestTime) {
			latestTime = info.ModTime()
			latestSession = entry.Name()
		}
	}

	if latestSession == "" {
		return nil, fmt.Errorf("no sessions found")
	}

	return v.VerifySession(latestSession)
}

// VerifyAttestation verifies a single attestation envelope.
func (v *Verifier) VerifyAttestation(envelopePath string, pol *aflock.Policy) error {
	data, err := os.ReadFile(envelopePath) //nolint:gosec // G304: envelope path from attestation directory
	if err != nil {
		return fmt.Errorf("read envelope: %w", err)
	}

	var envelope attestation.Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("parse envelope: %w", err)
	}

	// Verify payload type
	if envelope.PayloadType != attestation.PayloadType {
		return fmt.Errorf("invalid payload type: %s", envelope.PayloadType)
	}

	// Decode and parse statement
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	var statement attestation.Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return fmt.Errorf("parse statement: %w", err)
	}

	// Verify statement type — only accept v1 (v0.1 is deprecated and could allow downgrade attacks)
	if statement.Type != attestation.StatementType {
		return fmt.Errorf("invalid statement type: %s (expected %s)", statement.Type, attestation.StatementType)
	}

	// Verify signature against trusted certificates from policy roots
	if pol == nil || pol.Roots == nil || len(pol.Roots) == 0 {
		return fmt.Errorf("no policy roots configured: signature verification cannot be performed")
	}

	trustedCerts, err := loadRootCertificates(pol.Roots)
	if err != nil {
		return fmt.Errorf("load root certificates: %w", err)
	}

	if len(trustedCerts) == 0 {
		return fmt.Errorf("no valid certificates loaded from policy roots: signature verification cannot be performed")
	}

	if err := attestation.VerifyEnvelope(&envelope, trustedCerts); err != nil {
		return fmt.Errorf("signature verification: %w", err)
	}

	return nil
}

// loadRootCertificates loads X.509 certificates from policy roots configuration.
func loadRootCertificates(roots map[string]aflock.Root) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for name, root := range roots {
		if root.Certificate == "" {
			continue
		}

		// Try as file path first
		certData, err := os.ReadFile(root.Certificate)
		if err != nil {
			// Try as inline PEM/base64
			certData = []byte(root.Certificate)
		}

		block, _ := pem.Decode(certData)
		if block == nil {
			// Try base64-decoding the raw string
			decoded, err := base64.StdEncoding.DecodeString(string(certData))
			if err != nil {
				return nil, fmt.Errorf("cannot parse certificate for root %q: not PEM, file, or base64", name)
			}
			block = &pem.Block{Bytes: decoded}
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate for root %q: %w", name, err)
		}

		certs = append(certs, cert)
	}
	return certs, nil
}

// ListSessions lists all available sessions.
func (v *Verifier) ListSessions() ([]SessionInfo, error) {
	stateDir := filepath.Join(os.Getenv("HOME"), ".aflock", "sessions")
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read sessions dir: %w", err)
	}

	var sessions []SessionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		state, err := v.stateManager.Load(entry.Name())
		if err != nil || state == nil {
			continue
		}

		info := SessionInfo{
			SessionID:  entry.Name(),
			PolicyName: state.Policy.Name,
			StartedAt:  state.StartedAt,
		}
		if state.Metrics != nil {
			info.Turns = state.Metrics.Turns
			info.ToolCalls = state.Metrics.ToolCalls
		}
		sessions = append(sessions, info)
	}

	return sessions, nil
}

// SessionInfo provides summary info about a session.
type SessionInfo struct {
	SessionID  string    `json:"sessionId"`
	PolicyName string    `json:"policyName"`
	StartedAt  time.Time `json:"startedAt"`
	Turns      int       `json:"turns"`
	ToolCalls  int       `json:"toolCalls"`
}

// findAttestation checks if an attestation for the given name exists in the directory.
// It first tries exact filename matches, then scans all .intoto.json files and checks
// the predicate's toolName/action field (content-based lookup). This handles
// timestamp-prefixed filenames like 20260210-143022-ab3def12.intoto.json.
func (v *Verifier) findAttestation(dir, name string) bool {
	// First try exact filename match
	exactPaths := []string{
		filepath.Join(dir, name+".json"),
		filepath.Join(dir, name+".intoto.json"),
	}
	for _, p := range exactPaths {
		if _, err := os.Stat(p); err == nil {
			if validateAttestationStructure(p) {
				return true
			}
		}
	}

	// Scan attestation files and check their content for matching tool names.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fname := entry.Name()
		if !strings.HasSuffix(fname, ".intoto.json") && !strings.HasSuffix(fname, ".json") {
			continue
		}
		p := filepath.Join(dir, fname)
		if attestationContentMatchesName(p, name) && validateAttestationStructure(p) {
			return true
		}
	}

	return false
}

// validateAttestationStructure performs structural validation on an attestation file.
// It checks that the file is a valid DSSE envelope with non-empty payload, payloadType,
// and signatures. This does NOT perform cryptographic verification.
func validateAttestationStructure(path string) bool {
	data, err := os.ReadFile(path) //nolint:gosec // G304: attestation file path from state directory
	if err != nil {
		return false
	}

	var envelope struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return false
	}

	return envelope.Payload != "" && envelope.PayloadType != "" && len(envelope.Signatures) > 0
}

// attestationContentMatchesName checks if an attestation file's predicate toolName or
// action field matches the required name (case-insensitive).
func attestationContentMatchesName(path, name string) bool {
	data, err := os.ReadFile(path) //nolint:gosec // G304: attestation file path from state directory
	if err != nil {
		return false
	}

	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return false
	}

	var statement struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &statement); err != nil {
		return false
	}

	var predicate struct {
		ToolName string `json:"toolName"`
		Action   string `json:"action"`
	}
	if err := json.Unmarshal(statement.Predicate, &predicate); err != nil {
		return false
	}

	return strings.EqualFold(predicate.ToolName, name) || strings.EqualFold(predicate.Action, name)
}

// DefaultTimestampFreshness is the default maximum age for attestation timestamps.
const DefaultTimestampFreshness = 24 * time.Hour

// verifySessionAttestationSignatures verifies DSSE signatures on all attestation files
// in the session's attestation directory. This is Phase 1 of the verification pipeline.
func (v *Verifier) verifySessionAttestationSignatures(attestDir string, ss *aflock.SessionState) []string {
	var errors []string

	// If no roots configured in policy, skip signature verification with a warning
	if ss.Policy == nil || len(ss.Policy.Roots) == 0 {
		return nil
	}

	entries, err := os.ReadDir(attestDir)
	if err != nil {
		// No attestation directory is not an error — some sessions may not have attestations
		if os.IsNotExist(err) {
			return nil
		}
		return []string{fmt.Sprintf("read attestation directory: %v", err)}
	}

	trustedCerts, err := loadRootCertificates(ss.Policy.Roots)
	if err != nil {
		return []string{fmt.Sprintf("load root certificates: %v", err)}
	}
	if len(trustedCerts) == 0 {
		return []string{"no valid certificates loaded from policy roots"}
	}

	attestationCount := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fname := entry.Name()
		if !strings.HasSuffix(fname, ".intoto.json") && !strings.HasSuffix(fname, ".json") {
			continue
		}
		attestationCount++

		p := filepath.Join(attestDir, fname)
		data, err := os.ReadFile(p) //nolint:gosec // G304: attestation path from state directory
		if err != nil {
			errors = append(errors, fmt.Sprintf("read attestation %s: %v", fname, err))
			continue
		}

		var envelope struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
			Signatures  []struct {
				KeyID       string `json:"keyid"`
				Sig         string `json:"sig"`
				Certificate string `json:"certificate,omitempty"`
			} `json:"signatures"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			errors = append(errors, fmt.Sprintf("parse envelope %s: %v", fname, err))
			continue
		}

		if len(envelope.Signatures) == 0 {
			errors = append(errors, fmt.Sprintf("attestation %s has no signatures", fname))
			continue
		}

		payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			errors = append(errors, fmt.Sprintf("decode payload %s: %v", fname, err))
			continue
		}

		// Verify at least one signature is valid against trusted roots
		if err := verifyDSSESignaturesNoFunctionary(envelope.PayloadType, payload, envelope.Signatures, trustedCerts); err != nil {
			errors = append(errors, fmt.Sprintf("signature verification failed for %s: %v", fname, err))
		}
	}

	return errors
}

// verifyDSSESignaturesNoFunctionary verifies DSSE envelope signatures against trusted certificates
// without checking functionary constraints. Used for session-level verification where
// we just need to confirm signatures are authentic.
func verifyDSSESignaturesNoFunctionary(payloadType string, payload []byte, signatures []struct {
	KeyID       string `json:"keyid"`
	Sig         string `json:"sig"`
	Certificate string `json:"certificate,omitempty"`
}, trustedCerts []*x509.Certificate) error {
	paeBytes := createDSSEPAE(payloadType, payload)
	hash := sha256.Sum256(paeBytes)
	// Legacy PAE for backward compatibility with pre-H10-fix attestations.
	paeBytesLegacy := createDSSEPAELegacy(payloadType, payload)
	hashLegacy := sha256.Sum256(paeBytesLegacy)

	rootPool := x509.NewCertPool()
	for _, cert := range trustedCerts {
		rootPool.AddCert(cert)
	}

	for _, sig := range signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			continue
		}

		candidates := make([]*x509.Certificate, len(trustedCerts))
		copy(candidates, trustedCerts)

		if sig.Certificate != "" {
			block, _ := pem.Decode([]byte(sig.Certificate))
			if block != nil {
				if leafCert, err := x509.ParseCertificate(block.Bytes); err == nil {
					candidates = append(candidates, leafCert)
				}
			}
		}

		for _, cert := range candidates {
			if !verifySignatureWithCert(cert, paeBytes, hash[:], sigBytes) &&
				!verifySignatureWithCert(cert, paeBytesLegacy, hashLegacy[:], sigBytes) {
				continue
			}

			_, chainErr := cert.Verify(x509.VerifyOptions{
				Roots:     rootPool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			if chainErr != nil {
				continue
			}

			return nil // Valid signature from trusted cert
		}
	}

	return fmt.Errorf("no valid signature from a trusted certificate")
}

// verifySessionBinding verifies that attestation predicates are bound to the correct session
// and that timestamps are within the freshness window. This prevents attestation replay attacks.
func (v *Verifier) verifySessionBinding(attestDir, sessionID string, sessionStartedAt time.Time) []string {
	var errors []string

	entries, err := os.ReadDir(attestDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return []string{fmt.Sprintf("read attestation directory: %v", err)}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fname := entry.Name()
		if !strings.HasSuffix(fname, ".intoto.json") && !strings.HasSuffix(fname, ".json") {
			continue
		}

		p := filepath.Join(attestDir, fname)
		sessionErr, timestampErr := verifyAttestationBinding(p, sessionID, sessionStartedAt)
		if sessionErr != "" {
			errors = append(errors, fmt.Sprintf("%s: %s", fname, sessionErr))
		}
		if timestampErr != "" {
			errors = append(errors, fmt.Sprintf("%s: %s", fname, timestampErr))
		}
	}

	return errors
}

// verifyAttestationBinding checks a single attestation's session binding and timestamp freshness.
// Returns separate error messages for session mismatch and timestamp staleness.
func verifyAttestationBinding(path, expectedSessionID string, sessionStartedAt time.Time) (sessionErr, timestampErr string) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: attestation path from state directory
	if err != nil {
		return fmt.Sprintf("read file: %v", err), ""
	}

	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Sprintf("parse envelope: %v", err), ""
	}

	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return fmt.Sprintf("decode payload: %v", err), ""
	}

	var statement struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &statement); err != nil {
		return fmt.Sprintf("parse statement: %v", err), ""
	}

	var predicate struct {
		SessionID string    `json:"sessionId"`
		Timestamp time.Time `json:"timestamp"`
	}
	if err := json.Unmarshal(statement.Predicate, &predicate); err != nil {
		// Predicate may not have these fields (e.g., collection predicates)
		return "", ""
	}

	// Check session binding
	if predicate.SessionID != "" && predicate.SessionID != expectedSessionID {
		sessionErr = fmt.Sprintf("session ID mismatch: attestation bound to %q, expected %q", predicate.SessionID, expectedSessionID)
	}

	// Check timestamp freshness
	if !predicate.Timestamp.IsZero() {
		age := time.Since(predicate.Timestamp)
		if age > DefaultTimestampFreshness {
			timestampErr = fmt.Sprintf("attestation timestamp too old: %s (max %s)", age.Round(time.Second), DefaultTimestampFreshness)
		}
		// Also check that attestation wasn't created before the session started (pre-dated)
		if predicate.Timestamp.Before(sessionStartedAt.Add(-1 * time.Minute)) {
			timestampErr = fmt.Sprintf("attestation timestamp %s is before session start %s", predicate.Timestamp.Format(time.RFC3339), sessionStartedAt.Format(time.RFC3339))
		}
	}

	return sessionErr, timestampErr
}

func containsCheckPrefix(checks []CheckResult, prefix string) bool {
	for _, c := range checks {
		if strings.HasPrefix(c.Name, prefix) {
			return true
		}
	}
	return false
}

// StepResult represents the verification result for a single step.
type StepResult struct {
	Name            string   `json:"name"`
	AttestationPath string   `json:"attestationPath,omitempty"`
	Found           bool     `json:"found"`
	SignatureValid  bool     `json:"signatureValid"`
	ArtifactsMatch  bool     `json:"artifactsMatch"`
	Errors          []string `json:"errors,omitempty"`
}

// StepsResult represents the result of verifying all required steps.
type StepsResult struct {
	Success    bool                  `json:"success"`
	TreeHash   string                `json:"treeHash"`
	PolicyName string                `json:"policyName"`
	VerifiedAt time.Time             `json:"verifiedAt"`
	Steps      map[string]StepResult `json:"steps"`
	Errors     []string              `json:"errors,omitempty"`
}

// VerifySteps verifies attestations for all required steps in a policy.
// attestDir is the base directory (e.g., ~/.aflock/attestations)
// treeHash is the git tree hash to verify attestations for
//
//nolint:gocognit // step verification is inherently complex
func (v *Verifier) VerifySteps(pol *aflock.Policy, attestDir, treeHash string) (*StepsResult, error) {
	result := &StepsResult{
		Success:    true,
		TreeHash:   treeHash,
		PolicyName: pol.Name,
		VerifiedAt: time.Now(),
		Steps:      make(map[string]StepResult),
	}

	// Check policy expiration
	if pol.IsExpired() {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Sprintf("Policy expired at %s", pol.Expires))
		return result, nil
	}

	// If no steps defined, nothing to verify
	if len(pol.Steps) == 0 {
		return result, nil
	}

	// Topologically sort steps so dependencies (ArtifactsFrom) are processed first.
	// This ensures that when step B depends on step A's products, A is already verified.
	sortedSteps, err := topoSortSteps(pol.Steps)
	if err != nil {
		result.Success = false
		result.Errors = append(result.Errors, err.Error())
		return result, nil
	}

	// Verify each step has an attestation
	for _, stepName := range sortedSteps {
		step := pol.Steps[stepName]
		stepResult := StepResult{
			Name:           stepName,
			ArtifactsMatch: true, // Will be set false if check fails
		}

		// Look for attestation file
		attestPath := filepath.Join(attestDir, treeHash, stepName+".intoto.json")
		if _, err := os.Stat(attestPath); os.IsNotExist(err) { //nolint:nestif
			stepResult.Found = false
			stepResult.Errors = append(stepResult.Errors, fmt.Sprintf("Attestation not found: %s", attestPath))
			result.Success = false
		} else if err != nil {
			stepResult.Found = false
			stepResult.Errors = append(stepResult.Errors, fmt.Sprintf("Error checking attestation: %v", err))
			result.Success = false
		} else {
			stepResult.Found = true
			stepResult.AttestationPath = attestPath

			// Verify attestation contents
			if err := v.verifyStepAttestation(attestPath, &step, pol); err != nil {
				stepResult.SignatureValid = false
				stepResult.Errors = append(stepResult.Errors, fmt.Sprintf("Attestation verification failed: %v", err))
				result.Success = false
			} else {
				stepResult.SignatureValid = true
			}
		}

		// Check identity constraints (Phase 2) if attestation was found
		if stepResult.Found && pol.Identity != nil {
			if id, err := extractIdentityFromAttestation(attestPath); err != nil {
				stepResult.Errors = append(stepResult.Errors, fmt.Sprintf("Identity extraction failed: %v", err))
				result.Success = false
			} else if id != nil {
				identityErrors := verifyIdentityConstraints(*id, pol.Identity)
				for _, msg := range identityErrors {
					stepResult.Errors = append(stepResult.Errors, msg)
					result.Success = false
				}
			}
		}

		// Check artifact chain from previous steps
		if len(step.ArtifactsFrom) > 0 { //nolint:nestif
			for _, fromStep := range step.ArtifactsFrom {
				if fromResult, exists := result.Steps[fromStep]; exists && fromResult.Found {
					if err := v.compareArtifacts(fromResult.AttestationPath, attestPath); err != nil {
						stepResult.ArtifactsMatch = false
						stepResult.Errors = append(stepResult.Errors, fmt.Sprintf("Artifact chain mismatch from '%s': %v", fromStep, err))
						result.Success = false
					}
				} else {
					stepResult.ArtifactsMatch = false
					stepResult.Errors = append(stepResult.Errors, fmt.Sprintf("Artifacts from step '%s' not available", fromStep))
					result.Success = false
				}
			}
		}

		result.Steps[stepName] = stepResult
	}

	// Collect all errors
	for _, stepResult := range result.Steps {
		result.Errors = append(result.Errors, stepResult.Errors...)
	}

	return result, nil
}

// compareArtifacts checks that products from the source step appear as materials in the target step.
func (v *Verifier) compareArtifacts(fromPath, toPath string) error {
	fromProducts, err := extractDigests(fromPath, "products")
	if err != nil {
		return fmt.Errorf("extract products from source: %w", err)
	}

	toMaterials, err := extractDigests(toPath, "materials")
	if err != nil {
		return fmt.Errorf("extract materials from target: %w", err)
	}

	// If the source has no products, there's nothing to verify
	if len(fromProducts) == 0 {
		return nil
	}

	// Check that every product from the source step appears in the target's materials
	var missing []string
	for name, digests := range fromProducts {
		targetDigests, exists := toMaterials[name]
		if !exists {
			missing = append(missing, name)
			continue
		}

		// Check that at least one digest matches
		matched := false
		for algo, hash := range digests {
			if targetHash, ok := targetDigests[algo]; ok && targetHash == hash {
				matched = true
				break
			}
		}
		if !matched {
			missing = append(missing, name+" (digest mismatch)")
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("products not found in materials: %v", missing)
	}

	return nil
}

// extractDigests extracts artifact digests from an attestation envelope.
// artifactType should be "products" or "materials".
func extractDigests(attestPath, artifactType string) (map[string]map[string]string, error) {
	data, err := os.ReadFile(attestPath) //nolint:gosec // G304: attestation path from state directory
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}

	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, err
	}

	// Parse the in-toto statement to get the predicate
	var statement struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, err
	}

	// Parse the collection predicate
	var collection struct {
		Attestations []struct {
			Type        string          `json:"type"`
			Attestation json.RawMessage `json:"attestation"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(statement.Predicate, &collection); err != nil {
		return nil, err
	}

	// Look for the appropriate attestor type
	targetType := "https://aflock.ai/attestations/product/v0.1"
	if artifactType == "materials" {
		targetType = "https://aflock.ai/attestations/material/v0.1"
	}

	result := make(map[string]map[string]string)
	for _, att := range collection.Attestations {
		if att.Type != targetType {
			continue
		}

		// Parse the attestor data - both materials and products use the same format
		var artifacts map[string]struct {
			Hash map[string]string `json:"hash"`
		}
		if err := json.Unmarshal(att.Attestation, &artifacts); err != nil {
			continue
		}

		for name, artifact := range artifacts {
			result[name] = artifact.Hash
		}
	}

	return result, nil
}

// verifyStepAttestation verifies a single step's attestation against policy.
//
//nolint:gocyclo,funlen // step attestation verification has many validation paths
func (v *Verifier) verifyStepAttestation(attestPath string, step *aflock.Step, pol *aflock.Policy) error {
	data, err := os.ReadFile(attestPath) //nolint:gosec // G304: attestation path from state directory
	if err != nil {
		return fmt.Errorf("read attestation: %w", err)
	}

	// Parse as DSSE envelope (DSSE format)
	var envelope struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID       string `json:"keyid"`
			Sig         string `json:"sig"`
			Certificate string `json:"certificate,omitempty"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("parse envelope: %w", err)
	}

	if len(envelope.Signatures) == 0 {
		return fmt.Errorf("no signatures in envelope")
	}

	// Decode payload
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	// Parse as in-toto Statement first (payload is always a Statement wrapping a Collection)
	var statement struct {
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &statement); err != nil {
		return fmt.Errorf("parse statement: %w", err)
	}

	// Extract the collection from the statement predicate
	var collection struct {
		Name         string `json:"name"`
		Attestations []struct {
			Type        string          `json:"type"`
			Attestation json.RawMessage `json:"attestation"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(statement.Predicate, &collection); err != nil {
		return fmt.Errorf("parse collection from predicate: %w", err)
	}

	// Verify collection name matches step name
	if collection.Name != step.Name {
		return fmt.Errorf("collection name '%s' doesn't match step name '%s'", collection.Name, step.Name)
	}

	// Check required attestation types
	for _, required := range step.Attestations {
		found := false
		for _, att := range collection.Attestations {
			if att.Type == required.Type {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing required attestation type: %s", required.Type)
		}
	}

	// Verify signatures against functionaries
	// Allow keyless-only policies without explicit roots
	hasKeyless := false
	for _, f := range step.Functionaries {
		if f.Type == "keyless" {
			hasKeyless = true
			break
		}
	}

	if len(pol.Roots) == 0 && !hasKeyless {
		return fmt.Errorf("policy has no trusted roots: signature verification cannot be performed")
	}

	trustedCerts, err := loadRootCertificates(pol.Roots)
	if err != nil {
		return fmt.Errorf("load root certificates: %w", err)
	}

	// Add Fulcio public root CA if any functionary is keyless
	if hasKeyless {
		fulcioRoot, err := loadFulcioRoot()
		if err == nil {
			trustedCerts = append(trustedCerts, fulcioRoot)
		}
	}

	if len(trustedCerts) == 0 {
		return fmt.Errorf("no valid certificates loaded from policy roots: signature verification cannot be performed")
	}

	if err := verifyDSSESignatures(envelope.PayloadType, payload, envelope.Signatures, trustedCerts, step); err != nil {
		return fmt.Errorf("signature verification: %w", err)
	}

	return nil
}

// verifyDSSESignatures verifies DSSE envelope signatures against trusted certificates
// and checks that at least one signature is from an allowed functionary.
// trustedCerts are root/intermediate CA certificates used to validate leaf cert chains.
// Signatures are verified against leaf certificates (from the envelope or matched by KeyID),
// and the leaf certificate chain is validated up to a trusted root.
func verifyDSSESignatures(payloadType string, payload []byte, signatures []struct {
	KeyID       string `json:"keyid"`
	Sig         string `json:"sig"`
	Certificate string `json:"certificate,omitempty"`
}, trustedCerts []*x509.Certificate, step *aflock.Step) error {
	// Create PAE (Pre-Authentication Encoding) — both spec-compliant and legacy.
	paeBytes := createDSSEPAE(payloadType, payload)
	hash := sha256.Sum256(paeBytes)
	paeBytesLegacy := createDSSEPAELegacy(payloadType, payload)
	hashLegacy := sha256.Sum256(paeBytesLegacy)

	// Build a cert pool from trusted roots for chain validation
	rootPool := x509.NewCertPool()
	for _, cert := range trustedCerts {
		rootPool.AddCert(cert)
	}

	for _, sig := range signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			continue
		}

		// Collect candidate verification certs: trusted certs themselves (for self-signed/direct trust)
		// plus any leaf certs embedded in the signature
		candidates := make([]*x509.Certificate, len(trustedCerts))
		copy(candidates, trustedCerts)

		// Parse leaf certificate from the signature if present
		if sig.Certificate != "" {
			block, _ := pem.Decode([]byte(sig.Certificate))
			if block != nil {
				if leafCert, err := x509.ParseCertificate(block.Bytes); err == nil {
					candidates = append(candidates, leafCert)
				}
			}
		}

		// Verify the signature against each candidate cert (try both PAE formats)
		for _, cert := range candidates {
			if !verifySignatureWithCert(cert, paeBytes, hash[:], sigBytes) &&
				!verifySignatureWithCert(cert, paeBytesLegacy, hashLegacy[:], sigBytes) {
				continue
			}

			// Signature is cryptographically valid. Now validate the cert chain
			// against the trusted root pool for ALL certificates, including CAs.
			// This prevents an attacker from embedding a self-signed CA cert
			// in the signature to bypass chain validation.
			_, chainErr := cert.Verify(x509.VerifyOptions{
				Roots:     rootPool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			if chainErr != nil {
				continue // valid sig but untrusted cert chain
			}

			// Signature is valid and cert is trusted. Check functionary constraints.
			if matchesFunctionary(cert, sig.KeyID, step) {
				return nil
			}
		}
	}

	return fmt.Errorf("no valid signature from an allowed functionary")
}

// verifySignatureWithCert verifies a signature against a certificate's public key.
// paeBytes is the raw Pre-Authentication Encoding (used by Ed25519 which signs the raw message).
// hash is SHA256(paeBytes) (used by ECDSA and RSA which sign a digest).
func verifySignatureWithCert(cert *x509.Certificate, paeBytes, hash, sig []byte) bool {
	switch key := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, hash, sig)
	case *rsa.PublicKey:
		// Pinned to PKCS1v15 to match what the signer produces and prevent
		// padding-confusion attacks (issue #57 / L3).
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash, sig) == nil
	case ed25519PublicKey:
		// Ed25519 signs the raw message, not a hash. The rookery DSSE signer
		// calls ed25519.Sign(key, PAE) directly (unlike ECDSA/RSA which hash first),
		// so verification must use the raw PAE bytes, not SHA256(PAE).
		return ed25519Verify(key, paeBytes, sig)
	default:
		return false
	}
}

// createDSSEPAE creates Pre-Authentication Encoding per the DSSE v1 spec.
// Format: "DSSEv1" || LE64(len(payloadType)) || payloadType || LE64(len(payload)) || payload
func createDSSEPAE(payloadType string, payload []byte) []byte {
	typeBytes := []byte(payloadType)
	buf := make([]byte, 0, 6+8+len(typeBytes)+8+len(payload))
	buf = append(buf, "DSSEv1"...)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(len(typeBytes)))
	buf = append(buf, typeBytes...)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(len(payload)))
	buf = append(buf, payload...)
	return buf
}

// createDSSEPAELegacy reproduces the previous (non-spec-compliant) PAE encoding
// with ASCII decimal lengths for backward-compatible verification.
func createDSSEPAELegacy(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ",
		len(payloadType), payloadType, len(payload))
	result := make([]byte, 0, len(prefix)+len(payload))
	result = append(result, []byte(prefix)...)
	result = append(result, payload...)
	return result
}

// matchesFunctionary checks whether a signing certificate and key ID satisfy
// at least one functionary constraint in the step. If the step has no functionaries,
// any trusted signature is accepted.
func matchesFunctionary(cert *x509.Certificate, keyID string, step *aflock.Step) bool {
	if len(step.Functionaries) == 0 {
		return true
	}

	for _, f := range step.Functionaries {
		// PublicKeyID match: exact key ID comparison
		if f.PublicKeyID != "" && f.PublicKeyID == keyID {
			return true
		}

		// CertConstraint match: verify certificate attributes against constraints
		if f.CertConstraint != nil {
			if certMatchesConstraint(cert, f.CertConstraint) {
				return true
			}
		}

		// Keyless/Sigstore match: verify Fulcio certificate extensions against OIDC constraints
		if f.Type == "keyless" {
			if matchesKeylessFunctionary(cert, f) {
				return true
			}
		}
	}
	return false
}

// certMatchesConstraint checks whether a certificate satisfies the given constraint.
// All non-empty constraint fields must match (AND logic).
// An empty constraint (no CommonName, no URIs) never matches — at least one field must be set.
func certMatchesConstraint(cert *x509.Certificate, constraint *aflock.CertConstraint) bool {
	// Reject empty constraints — they would match any certificate
	if constraint.CommonName == "" && len(constraint.URIs) == 0 {
		return false
	}

	// Check CommonName if specified
	if constraint.CommonName != "" {
		if cert.Subject.CommonName != constraint.CommonName {
			return false
		}
	}

	// Check URI SANs if specified — at least one constraint URI must match a cert URI
	if len(constraint.URIs) > 0 {
		matched := false
		for _, pattern := range constraint.URIs {
			for _, certURI := range cert.URIs {
				if matchSPIFFEPattern(pattern, certURI.String()) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// matchSPIFFEPattern matches a SPIFFE ID against a glob pattern.
// Supports * as a wildcard for a single path segment.
func matchSPIFFEPattern(pattern, spiffeID string) bool {
	// Exact match
	if pattern == spiffeID {
		return true
	}
	// filepath.Match handles * globs correctly for path-like strings
	matched, err := filepath.Match(pattern, spiffeID)
	return err == nil && matched
}

// topoSortSteps returns step names in topological order based on ArtifactsFrom dependencies.
// Steps with no dependencies come first. Returns an error if cycles are detected.
func topoSortSteps(steps map[string]aflock.Step) ([]string, error) {
	// Build in-degree map and adjacency list
	inDegree := make(map[string]int)
	dependents := make(map[string][]string) // from -> list of steps that depend on it

	for name := range steps {
		inDegree[name] = 0
	}
	for name, step := range steps {
		for _, dep := range step.ArtifactsFrom {
			if _, exists := steps[dep]; exists {
				inDegree[name]++
				dependents[dep] = append(dependents[dep], name)
			}
		}
	}

	// Kahn's algorithm with sorted queue for determinism
	var queue []string
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}
	sort.Strings(queue)

	var sorted []string
	for len(queue) > 0 {
		// Pop first (alphabetically first among ready nodes)
		current := queue[0]
		queue = queue[1:]
		sorted = append(sorted, current)

		for _, dep := range dependents[current] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
				sort.Strings(queue)
			}
		}
	}

	// If there are cycles, return an error listing the cyclic steps
	if len(sorted) < len(steps) {
		var cyclic []string
		for name := range steps {
			found := false
			for _, s := range sorted {
				if s == name {
					found = true
					break
				}
			}
			if !found {
				cyclic = append(cyclic, name)
			}
		}
		sort.Strings(cyclic)
		return nil, fmt.Errorf("dependency cycle detected among steps: %s", strings.Join(cyclic, ", "))
	}

	return sorted, nil
}

// verifySublayouts checks child sessions against sublayout policies (Phase 6).
// For each sublayout defined in the parent policy, it:
//  1. Verifies attenuation (sub-limits ≤ parent limits)
//  2. Finds the matching child session
//  3. Recursively verifies the child session against the sublayout's policy
//  4. Accumulates child spend toward parent metrics
//
//nolint:gocognit // sublayout verification requires many checks
func (v *Verifier) verifySublayouts(parentState *aflock.SessionState, depth int) []string {
	if len(parentState.Policy.Sublayouts) == 0 {
		return nil
	}

	var errors []string

	for _, sub := range parentState.Policy.Sublayouts {
		// 1. Verify attenuation: sub-agent limits must be ≤ parent limits
		if attErrors := verifyAttenuation(parentState.Policy.Limits, sub.Limits); len(attErrors) > 0 {
			for _, msg := range attErrors {
				errors = append(errors, fmt.Sprintf("sublayout %q: attenuation violation: %s", sub.Name, msg))
			}
			continue // Don't verify child if attenuation is violated — policy itself is invalid
		}

		// 2. Find matching child session(s) for this sublayout
		childFound := false
		for _, childID := range parentState.ChildSessionIDs {
			childState, err := v.stateManager.Load(childID)
			if err != nil || childState == nil {
				continue
			}

			// Match child to sublayout by policy name or attestation prefix
			if !matchesSublayout(childState, &sub) {
				continue
			}

			childFound = true

			// 3. Recursively verify the child session
			childResult, err := v.verifySessionWithDepth(childID, depth+1)
			if err != nil {
				errors = append(errors, fmt.Sprintf("sublayout %q: verify child %s: %v", sub.Name, childID, err))
				continue
			}

			if !childResult.Success {
				for _, e := range childResult.Errors {
					errors = append(errors, fmt.Sprintf("sublayout %q [%s]: %s", sub.Name, childID, e))
				}
			}

			// 4. Accumulate child spend toward parent (for Rego cross-check)
			if childResult.Metrics != nil && parentState.Metrics != nil {
				parentState.Metrics.CostUSD += childResult.Metrics.TotalCostUSD
				parentState.Metrics.TokensIn += childResult.Metrics.TotalTokensIn
				parentState.Metrics.TokensOut += childResult.Metrics.TotalTokensOut
			}
		}

		if !childFound {
			errors = append(errors, fmt.Sprintf("sublayout %q: no matching child session found", sub.Name))
		}
	}

	return errors
}

// matchesSublayout checks if a child session matches a sublayout definition.
// Matches by policy name or attestation prefix.
func matchesSublayout(child *aflock.SessionState, sub *aflock.Sublayout) bool {
	if child.Policy == nil {
		return false
	}
	// Match by policy name
	if child.Policy.Name == sub.Name {
		return true
	}
	// Match by attestation prefix (if set)
	if sub.AttestationPrefix != "" && child.Policy.Name == sub.AttestationPrefix {
		return true
	}
	// Match by parent session reference
	if child.ParentSessionID != "" {
		return true // Child was spawned by this parent — assume it matches
	}
	return false
}

// verifyAttenuation checks that sub-agent limits are ≤ parent limits.
// This prevents privilege escalation: a sub-agent cannot have higher limits than its parent.
// Returns a list of violations. Empty list = attenuation is valid.
func verifyAttenuation(parent, child *aflock.LimitsPolicy) []string {
	if child == nil {
		return nil // No child limits = inherits parent (always valid)
	}
	if parent == nil {
		return nil // No parent limits = no constraints to violate
	}

	var violations []string

	checkLimit := func(name string, parentLimit, childLimit *aflock.Limit) {
		if childLimit == nil || parentLimit == nil {
			return // No limit set on one side = no violation
		}
		if childLimit.Value > parentLimit.Value {
			violations = append(violations, fmt.Sprintf(
				"%s: child %.2f > parent %.2f",
				name, childLimit.Value, parentLimit.Value))
		}
	}

	checkLimit("maxSpendUSD", parent.MaxSpendUSD, child.MaxSpendUSD)
	checkLimit("maxTokensIn", parent.MaxTokensIn, child.MaxTokensIn)
	checkLimit("maxTokensOut", parent.MaxTokensOut, child.MaxTokensOut)
	checkLimit("maxTurns", parent.MaxTurns, child.MaxTurns)
	checkLimit("maxWallTimeSeconds", parent.MaxWallTimeSeconds, child.MaxWallTimeSeconds)
	checkLimit("maxToolCalls", parent.MaxToolCalls, child.MaxToolCalls)

	return violations
}

// evaluateSessionAI runs AI evaluators against session data (Phase 5).
// The materials passed to the AI include session actions, metrics, and policy context.
func evaluateSessionAI(sessionState *aflock.SessionState) []string {
	if sessionState.Policy.Evaluators == nil || len(sessionState.Policy.Evaluators.AI) == 0 {
		return nil
	}

	// Build materials context for the AI evaluator
	materials := map[string]any{
		"policy":  sessionState.Policy,
		"actions": sessionState.Actions,
		"metrics": sessionState.Metrics,
	}

	materialsJSON, err := json.Marshal(materials)
	if err != nil {
		return []string{fmt.Sprintf("AI evaluation failed: marshal materials: %v", err)}
	}

	// Convert aflock evaluators to aieval.Policy
	policies := make([]aieval.Policy, len(sessionState.Policy.Evaluators.AI))
	for i, eval := range sessionState.Policy.Evaluators.AI {
		policies[i] = aieval.Policy{
			Name:     eval.Name,
			Prompt:   eval.Prompt,
			Model:    eval.Model,
			Backend:  eval.Backend,
			Endpoint: eval.Endpoint,
		}
	}

	ctx := context.Background()
	results, err := aieval.Evaluate(ctx, policies, materialsJSON)
	if err != nil {
		return []string{fmt.Sprintf("AI evaluation failed: %v", err)}
	}

	var errors []string
	for _, r := range results {
		if !r.Passed {
			errors = append(errors, fmt.Sprintf("AI evaluator %q: [%s] %s", r.Name, r.Status, r.Reason))
		}
	}
	return errors
}

// evaluateSessionRego runs top-level Rego evaluators against session data (Phase 4).
// The input to each Rego policy is:
//
//	{
//	  "policy": { ... policy fields ... },
//	  "actions": [ ... session actions ... ],
//	  "metrics": { ... session metrics ... }
//	}
//
// Each Rego module must define a `deny` rule returning denial reason strings.
func evaluateSessionRego(sessionState *aflock.SessionState) []string {
	if sessionState.Policy.Evaluators == nil || len(sessionState.Policy.Evaluators.Rego) == 0 {
		return nil
	}

	// Build the input for Rego evaluation
	input := map[string]any{
		"policy":  sessionState.Policy,
		"actions": sessionState.Actions,
		"metrics": sessionState.Metrics,
	}

	inputJSON, err := json.Marshal(input)
	if err != nil {
		return []string{fmt.Sprintf("Rego evaluation failed: marshal input: %v", err)}
	}

	// Convert aflock evaluators to rego.Policy
	policies := make([]aflockRego.Policy, len(sessionState.Policy.Evaluators.Rego))
	for i, eval := range sessionState.Policy.Evaluators.Rego {
		policies[i] = aflockRego.Policy{
			Name:   eval.Name,
			Module: eval.Policy,
		}
	}

	results, err := aflockRego.Evaluate(policies, inputJSON)
	if err != nil {
		return []string{fmt.Sprintf("Rego evaluation failed: %v", err)}
	}

	var errors []string
	for _, r := range results {
		if !r.Passed {
			for _, reason := range r.Reasons {
				errors = append(errors, fmt.Sprintf("Rego evaluator %q: %s", r.Name, reason))
			}
		}
	}
	return errors
}

// verifySessionMerkle checks the Merkle tree root over session actions (Phase 3).
// It serializes each ActionRecord to JSON, builds a Merkle tree using RFC 6962 hashing
// with JCS canonicalization, and compares the computed root against the expected root
// stored in policy.MaterialsFrom.Session.MerkleRoot.
func verifySessionMerkle(sessionState *aflock.SessionState) []string {
	if sessionState.Policy.MaterialsFrom == nil || sessionState.Policy.MaterialsFrom.Session == nil {
		return nil
	}

	expectedRoot := sessionState.Policy.MaterialsFrom.Session.MerkleRoot
	if expectedRoot == "" {
		return nil // No expected root — nothing to verify
	}

	if len(sessionState.Actions) == 0 {
		return []string{"Materials binding failed: no session actions to build Merkle tree"}
	}

	// Serialize each action record to JSON for Merkle leaf computation
	entries := make([][]byte, 0, len(sessionState.Actions))
	for i, action := range sessionState.Actions {
		data, err := json.Marshal(action)
		if err != nil {
			return []string{fmt.Sprintf("Materials binding failed: marshal action %d: %v", i, err)}
		}
		entries = append(entries, data)
	}

	if err := aflockMerkle.VerifyRoot(entries, expectedRoot); err != nil {
		return []string{fmt.Sprintf("Materials binding failed: %v", err)}
	}

	return nil
}

// IdentityFields holds the identity fields extracted from an attestation or session
// for verification against policy identity constraints.
type IdentityFields struct {
	Model       string
	Environment string
	Tools       []string // may be nil if not available (e.g., step-based verification)
}

// verifyIdentityConstraints checks identity fields against policy identity constraints.
// Returns a list of errors for each constraint that fails. Returns nil if all pass
// or if no identity policy is defined (no constraints = all identities allowed).
func verifyIdentityConstraints(id IdentityFields, identityPolicy *aflock.IdentityPolicy) []string {
	if identityPolicy == nil {
		return nil
	}

	var errors []string

	// Check allowedModels — model must match at least one glob pattern
	if len(identityPolicy.AllowedModels) > 0 && id.Model != "" {
		matched := false
		for _, pattern := range identityPolicy.AllowedModels {
			if matchIdentityGlob(pattern, id.Model) {
				matched = true
				break
			}
		}
		if !matched {
			errors = append(errors, fmt.Sprintf(
				"Identity mismatch: model %q does not match allowedModels %v",
				id.Model, identityPolicy.AllowedModels))
		}
	}

	// Check allowedEnvironments — environment must match at least one glob pattern
	if len(identityPolicy.AllowedEnvironments) > 0 && id.Environment != "" {
		matched := false
		for _, pattern := range identityPolicy.AllowedEnvironments {
			if matchIdentityGlob(pattern, id.Environment) {
				matched = true
				break
			}
		}
		if !matched {
			errors = append(errors, fmt.Sprintf(
				"Identity mismatch: environment %q does not match allowedEnvironments %v",
				id.Environment, identityPolicy.AllowedEnvironments))
		}
	}

	// Check requiredTools — each required tool must be present in the agent's tools
	if len(identityPolicy.RequiredTools) > 0 && id.Tools != nil {
		toolSet := make(map[string]bool, len(id.Tools))
		for _, t := range id.Tools {
			toolSet[t] = true
		}
		for _, required := range identityPolicy.RequiredTools {
			if !toolSet[required] {
				errors = append(errors, fmt.Sprintf(
					"Identity mismatch: required tool %q not available to agent",
					required))
			}
		}
	}

	return errors
}

// matchIdentityGlob performs glob matching for identity constraints.
// Supports * as wildcard for any characters (uses filepath.Match semantics).
func matchIdentityGlob(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	// filepath.Match handles * for single path segments. For identity matching
	// we want * to match any sequence, so use HasPrefix for trailing * patterns.
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	}
	matched, err := filepath.Match(pattern, value)
	return err == nil && matched
}

// extractIdentityFromAttestation extracts the TransitiveIdentity from an attestation
// envelope's predicate. Returns nil fields if identity is not present.
func extractIdentityFromAttestation(attestPath string) (*IdentityFields, error) {
	data, err := os.ReadFile(attestPath) //nolint:gosec // G304: attestation path from state directory
	if err != nil {
		return nil, fmt.Errorf("read attestation: %w", err)
	}

	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("parse envelope: %w", err)
	}

	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	// Parse statement → predicate → collection → attestations → find action attestation
	var statement struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, fmt.Errorf("parse statement: %w", err)
	}

	var collection struct {
		Attestations []struct {
			Type        string          `json:"type"`
			Attestation json.RawMessage `json:"attestation"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(statement.Predicate, &collection); err != nil {
		return nil, fmt.Errorf("parse collection: %w", err)
	}

	// Look for action attestation which contains the agent identity
	for _, att := range collection.Attestations {
		if att.Type != "https://aflock.ai/attestations/action/v0.1" {
			continue
		}

		var action struct {
			AgentIdentity *struct {
				Model       string `json:"model"`
				Environment string `json:"environment"`
			} `json:"agentIdentity"`
		}
		if err := json.Unmarshal(att.Attestation, &action); err != nil {
			continue
		}
		if action.AgentIdentity != nil {
			return &IdentityFields{
				Model:       action.AgentIdentity.Model,
				Environment: action.AgentIdentity.Environment,
			}, nil
		}
	}

	// No identity found — not an error, just no identity to verify
	return nil, nil
}

// VerifyTreeHash gets the current git tree hash and verifies all steps.
func (v *Verifier) VerifyTreeHash(pol *aflock.Policy, attestDir string) (*StepsResult, error) {
	treeHash, err := attestation.GetGitTreeHash("")
	if err != nil {
		return nil, fmt.Errorf("get git tree hash: %w", err)
	}
	return v.VerifySteps(pol, attestDir, treeHash)
}
