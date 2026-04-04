// Package verify implements attestation verification against policy.
package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/aflock/internal/attestation"
	"github.com/aflock-ai/aflock/internal/policy"
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
}

// NewVerifier creates a new verifier.
func NewVerifier() *Verifier {
	return &Verifier{
		stateManager: state.NewManager(""),
	}
}

// VerifySession verifies a session's attestations against its policy.
//
//nolint:gocognit,gocyclo,funlen // session verification requires many validation steps
func (v *Verifier) VerifySession(sessionID string) (*Result, error) {
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
		attestDir := v.stateManager.AttestationsDir(sessionID)
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

	// Verify statement type — accept both v1 (used by aflock signer) and v0.1 (used by witness workflow)
	if statement.Type != attestation.StatementType && statement.Type != "https://in-toto.io/Statement/v0.1" {
		return fmt.Errorf("invalid statement type: %s (expected %s or v0.1)", statement.Type, attestation.StatementType)
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

func (v *Verifier) findAttestation(dir, name string) bool {
	patterns := []string{
		filepath.Join(dir, name+".json"),
		filepath.Join(dir, name+".intoto.json"),
	}
	for _, p := range patterns {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	// Also check glob
	matches, _ := filepath.Glob(filepath.Join(dir, name+"*"))
	return len(matches) > 0
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
	sortedSteps := topoSortSteps(pol.Steps)

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
	if len(pol.Roots) == 0 {
		return fmt.Errorf("policy has no trusted roots: signature verification cannot be performed")
	}

	trustedCerts, err := loadRootCertificates(pol.Roots)
	if err != nil {
		return fmt.Errorf("load root certificates: %w", err)
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
	// Create PAE (Pre-Authentication Encoding)
	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	paeBytes := append([]byte(pae), payload...)
	hash := sha256.Sum256(paeBytes)

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

		// Verify the signature against each candidate cert
		for _, cert := range candidates {
			if !verifySignatureWithCert(cert, paeBytes, hash[:], sigBytes) {
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
		// Try PKCS1v15 first (more common), fall back to PSS
		if rsa.VerifyPKCS1v15(key, crypto.SHA256, hash, sig) == nil {
			return true
		}
		return rsa.VerifyPSS(key, crypto.SHA256, hash, sig, nil) == nil
	case ed25519PublicKey:
		// Ed25519 signs the raw message, not a hash. The rookery DSSE signer
		// calls ed25519.Sign(key, PAE) directly (unlike ECDSA/RSA which hash first),
		// so verification must use the raw PAE bytes, not SHA256(PAE).
		return ed25519Verify(key, paeBytes, sig)
	default:
		return false
	}
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
	}
	return false
}

// certMatchesConstraint checks whether a certificate satisfies the given constraint.
// All non-empty constraint fields must match (AND logic).
func certMatchesConstraint(cert *x509.Certificate, constraint *aflock.CertConstraint) bool {
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
// Steps with no dependencies come first. If there are cycles, the remaining steps are
// appended in sorted order (alphabetical) to ensure deterministic output.
//
//nolint:gocognit // topological sort is inherently complex
func topoSortSteps(steps map[string]aflock.Step) []string {
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

	// If there are cycles, append remaining steps in sorted order
	if len(sorted) < len(steps) {
		var remaining []string
		for name := range steps {
			found := false
			for _, s := range sorted {
				if s == name {
					found = true
					break
				}
			}
			if !found {
				remaining = append(remaining, name)
			}
		}
		sort.Strings(remaining)
		sorted = append(sorted, remaining...)
	}

	return sorted
}

// VerifyTreeHash gets the current git tree hash and verifies all steps.
func (v *Verifier) VerifyTreeHash(pol *aflock.Policy, attestDir string) (*StepsResult, error) {
	treeHash, err := attestation.GetGitTreeHash("")
	if err != nil {
		return nil, fmt.Errorf("get git tree hash: %w", err)
	}
	return v.VerifySteps(pol, attestDir, treeHash)
}
