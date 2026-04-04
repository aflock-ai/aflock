package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/internal/state"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// ---- Helpers for generating in-memory test keys and certificates ----

// generateTestCA creates a self-signed CA certificate and key for testing.
func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Aflock Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert, key
}

// generateTestLeafCert creates a leaf certificate signed by the given CA.
func generateTestLeafCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, uris ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	parsedURIs := make([]*url.URL, 0, len(uris))
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatalf("parse URI %q: %v", u, err)
		}
		parsedURIs = append(parsedURIs, parsed)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Aflock Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		URIs:                  parsedURIs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return cert, key
}

// certToPEM encodes a certificate to PEM format.
func certToPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// signDSSE creates a DSSE envelope with a valid ECDSA signature over the payload.
func signDSSE(t *testing.T, payloadType string, payload []byte, key *ecdsa.PrivateKey, keyID string) []byte {
	t.Helper()

	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	// PAE: "DSSEv1 <len(type)> <type> <len(body)> " + body
	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	paeBytes := append([]byte(pae), payload...)
	hash := sha256.Sum256(paeBytes)

	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("sign DSSE: %v", err)
	}

	envelope := map[string]interface{}{
		"payloadType": payloadType,
		"payload":     payloadB64,
		"signatures": []map[string]string{
			{
				"keyid": keyID,
				"sig":   base64.StdEncoding.EncodeToString(sig),
			},
		},
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal DSSE envelope: %v", err)
	}
	return data
}

// makeCollectionPayload builds an in-toto Statement wrapping a collection predicate.
func makeCollectionPayload(t *testing.T, stepName string, attestationTypes []string) []byte {
	t.Helper()

	attestations := make([]map[string]interface{}, 0, len(attestationTypes))
	for _, at := range attestationTypes {
		attestations = append(attestations, map[string]interface{}{
			"type":        at,
			"attestation": map[string]string{},
		})
	}

	predicate := map[string]interface{}{
		"name":         stepName,
		"attestations": attestations,
	}
	stmt := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://aflock.ai/attestations/collection/v0.1",
		"predicate":     predicate,
		"subject":       []map[string]interface{}{},
	}

	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal collection payload: %v", err)
	}
	return data
}

// makeArtifactPayload builds an in-toto Statement with materials and products attestors.
func makeArtifactPayload(t *testing.T, stepName string, materials, products map[string]map[string]string) []byte {
	t.Helper()

	var attestations []map[string]interface{}

	if materials != nil {
		matAttestation := make(map[string]interface{})
		for name, digests := range materials {
			matAttestation[name] = map[string]interface{}{"hash": digests}
		}
		attestations = append(attestations, map[string]interface{}{
			"type":        "https://aflock.ai/attestations/material/v0.1",
			"attestation": matAttestation,
		})
	}

	if products != nil {
		prodAttestation := make(map[string]interface{})
		for name, digests := range products {
			prodAttestation[name] = map[string]interface{}{"hash": digests}
		}
		attestations = append(attestations, map[string]interface{}{
			"type":        "https://aflock.ai/attestations/product/v0.1",
			"attestation": prodAttestation,
		})
	}

	predicate := map[string]interface{}{
		"name":         stepName,
		"attestations": attestations,
	}
	stmt := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://aflock.ai/attestations/collection/v0.1",
		"predicate":     predicate,
		"subject":       []map[string]interface{}{},
	}

	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal artifact payload: %v", err)
	}
	return data
}

// writeSessionState writes a session state JSON to the expected path under tmpDir.
func writeSessionState(t *testing.T, tmpDir, sessionID string, ss *aflock.SessionState) {
	t.Helper()
	dir := filepath.Join(tmpDir, sessionID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir session dir: %v", err)
	}
	data, err := json.Marshal(ss)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0644); err != nil {
		t.Fatalf("write state.json: %v", err)
	}
}

// newTestVerifier creates a Verifier backed by a temp directory for state storage.
func newTestVerifier(tmpDir string) *Verifier {
	return &Verifier{
		stateManager: state.NewManager(tmpDir),
	}
}

// ---- Tests ----

func TestNewVerifier(t *testing.T) {
	v := NewVerifier()
	if v == nil {
		t.Fatal("NewVerifier() returned nil")
	}
	if v.stateManager == nil {
		t.Fatal("stateManager is nil")
	}
}

//nolint:gocyclo // comprehensive verification test
func TestVerifySession_ValidSession(t *testing.T) {
	tmpDir := t.TempDir()

	sessionState := &aflock.SessionState{
		SessionID: "sess-001",
		StartedAt: time.Now().Add(-10 * time.Minute),
		Policy: &aflock.Policy{
			Name:    "test-policy",
			Version: "1.0",
		},
		Metrics: &aflock.SessionMetrics{
			Turns:     5,
			ToolCalls: 12,
			TokensIn:  1000,
			TokensOut: 500,
			CostUSD:   0.10,
			Tools:     map[string]int{"Read": 5, "Bash": 7},
		},
		Actions: []aflock.ActionRecord{
			{Timestamp: time.Now(), ToolName: "Read", ToolUseID: "tu_1", Decision: "allow"},
			{Timestamp: time.Now(), ToolName: "Bash", ToolUseID: "tu_2", Decision: "allow"},
		},
	}

	writeSessionState(t, tmpDir, "sess-001", sessionState)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-001")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	if !result.Success {
		t.Error("Expected success=true for valid session")
	}
	if result.SessionID != "sess-001" {
		t.Errorf("SessionID = %q, want %q", result.SessionID, "sess-001")
	}
	if result.PolicyName != "test-policy" {
		t.Errorf("PolicyName = %q, want %q", result.PolicyName, "test-policy")
	}
	if result.Metrics == nil {
		t.Fatal("Metrics should not be nil")
	}
	if result.Metrics.TotalTurns != 5 {
		t.Errorf("TotalTurns = %d, want 5", result.Metrics.TotalTurns)
	}
	if result.Metrics.TotalToolCalls != 12 {
		t.Errorf("TotalToolCalls = %d, want 12", result.Metrics.TotalToolCalls)
	}
	if result.Metrics.TotalTokensIn != 1000 {
		t.Errorf("TotalTokensIn = %d, want 1000", result.Metrics.TotalTokensIn)
	}
	if result.Metrics.TotalTokensOut != 500 {
		t.Errorf("TotalTokensOut = %d, want 500", result.Metrics.TotalTokensOut)
	}
	if result.Metrics.TotalCostUSD != 0.10 {
		t.Errorf("TotalCostUSD = %f, want 0.10", result.Metrics.TotalCostUSD)
	}

	// Actions check should be present and passing
	foundActions := false
	for _, check := range result.Checks {
		if check.Name == "actions" {
			foundActions = true
			if !check.Passed {
				t.Error("actions check should pass")
			}
			if !strings.Contains(check.Message, "2 total actions") {
				t.Errorf("actions message = %q, expected to contain '2 total actions'", check.Message)
			}
		}
	}
	if !foundActions {
		t.Error("Expected 'actions' check in results")
	}

	if len(result.Warnings) != 0 {
		t.Errorf("Expected no warnings, got %v", result.Warnings)
	}
}

func TestVerifySession_NonexistentSession(t *testing.T) {
	tmpDir := t.TempDir()
	v := newTestVerifier(tmpDir)

	_, err := v.VerifySession("no-such-session")
	if err == nil {
		t.Fatal("Expected error for nonexistent session")
	}
	if !strings.Contains(err.Error(), "session not found") {
		t.Errorf("Error = %q, expected to contain 'session not found'", err.Error())
	}
}

func TestVerifySession_WithDeniedActions(t *testing.T) {
	tmpDir := t.TempDir()

	sessionState := &aflock.SessionState{
		SessionID: "sess-denied",
		StartedAt: time.Now(),
		Policy: &aflock.Policy{
			Name:    "strict-policy",
			Version: "1.0",
		},
		Metrics: &aflock.SessionMetrics{
			Turns:     3,
			ToolCalls: 5,
			Tools:     map[string]int{"Bash": 3, "Write": 2},
		},
		Actions: []aflock.ActionRecord{
			{Timestamp: time.Now(), ToolName: "Bash", ToolUseID: "tu_1", Decision: "allow"},
			{Timestamp: time.Now(), ToolName: "Write", ToolUseID: "tu_2", Decision: "deny", Reason: "File not in allow list"},
			{Timestamp: time.Now(), ToolName: "Write", ToolUseID: "tu_3", Decision: "deny", Reason: "File not in allow list"},
		},
	}

	writeSessionState(t, tmpDir, "sess-denied", sessionState)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-denied")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	// Session should still succeed (denied actions are warnings, not failures)
	if !result.Success {
		t.Errorf("Expected success=true, denied actions should be warnings not failures. Errors: %v", result.Errors)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("Expected 1 warning, got %d: %v", len(result.Warnings), result.Warnings)
	}
	if !strings.Contains(result.Warnings[0], "2 actions were blocked") {
		t.Errorf("Warning = %q, expected '2 actions were blocked'", result.Warnings[0])
	}
}

func TestVerifySession_WithDataFlowViolation(t *testing.T) {
	tmpDir := t.TempDir()

	sessionState := &aflock.SessionState{
		SessionID: "sess-dataflow",
		StartedAt: time.Now(),
		Policy: &aflock.Policy{
			Name:    "dataflow-policy",
			Version: "1.0",
		},
		Metrics: &aflock.SessionMetrics{
			Turns:     2,
			ToolCalls: 3,
			Tools:     map[string]int{"Read": 1, "Write": 1, "WebFetch": 1},
		},
		Materials: []aflock.MaterialClassification{
			{Label: "internal", Source: "Read:/etc/secrets.json", Timestamp: time.Now()},
		},
		Actions: []aflock.ActionRecord{
			{Timestamp: time.Now(), ToolName: "Read", ToolUseID: "tu_1", Decision: "allow"},
			{Timestamp: time.Now(), ToolName: "WebFetch", ToolUseID: "tu_2", Decision: "deny", Reason: "Data flow violation: internal->public"},
			{Timestamp: time.Now(), ToolName: "Write", ToolUseID: "tu_3", Decision: "allow"},
		},
	}

	writeSessionState(t, tmpDir, "sess-dataflow", sessionState)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-dataflow")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	if result.Success {
		t.Error("Expected success=false due to data flow violation")
	}

	foundDataflow := false
	for _, check := range result.Checks {
		if strings.HasPrefix(check.Name, "dataflow:") {
			foundDataflow = true
			if check.Passed {
				t.Error("dataflow check should fail")
			}
			if !strings.Contains(check.Message, "Data flow") {
				t.Errorf("dataflow message = %q, expected to contain 'Data flow'", check.Message)
			}
		}
	}
	if !foundDataflow {
		t.Error("Expected dataflow check in results")
	}
}

func TestVerifySession_DataFlowNoViolation(t *testing.T) {
	tmpDir := t.TempDir()

	sessionState := &aflock.SessionState{
		SessionID: "sess-df-ok",
		StartedAt: time.Now(),
		Policy: &aflock.Policy{
			Name:    "df-ok-policy",
			Version: "1.0",
		},
		Metrics: &aflock.SessionMetrics{
			Turns:     2,
			ToolCalls: 2,
			Tools:     map[string]int{"Read": 1, "Write": 1},
		},
		Materials: []aflock.MaterialClassification{
			{Label: "internal", Source: "Read:/etc/config", Timestamp: time.Now()},
		},
		Actions: []aflock.ActionRecord{
			{Timestamp: time.Now(), ToolName: "Read", ToolUseID: "tu_1", Decision: "allow"},
			{Timestamp: time.Now(), ToolName: "Write", ToolUseID: "tu_2", Decision: "allow"},
		},
	}

	writeSessionState(t, tmpDir, "sess-df-ok", sessionState)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-df-ok")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success=true, no data flow violations. Errors: %v", result.Errors)
	}

	// Should have a passing dataflow check
	foundDataflow := false
	for _, check := range result.Checks {
		if check.Name == "dataflow" {
			foundDataflow = true
			if !check.Passed {
				t.Error("dataflow check should pass when no violations")
			}
		}
	}
	if !foundDataflow {
		t.Error("Expected 'dataflow' check when materials are present")
	}
}

func TestVerifySession_LimitsExceeded(t *testing.T) {
	tmpDir := t.TempDir()

	maxTurns := &aflock.Limit{Value: 3, Enforcement: "post-hoc"}
	sessionState := &aflock.SessionState{
		SessionID: "sess-limits",
		StartedAt: time.Now(),
		Policy: &aflock.Policy{
			Name:    "limits-policy",
			Version: "1.0",
			Limits: &aflock.LimitsPolicy{
				MaxTurns: maxTurns,
			},
		},
		Metrics: &aflock.SessionMetrics{
			Turns:     10, // exceeds limit of 3
			ToolCalls: 20,
			Tools:     map[string]int{"Read": 20},
		},
	}

	writeSessionState(t, tmpDir, "sess-limits", sessionState)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-limits")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	if result.Success {
		t.Error("Expected success=false due to exceeded limits")
	}

	foundLimitsCheck := false
	for _, check := range result.Checks {
		if strings.HasPrefix(check.Name, "limits:") {
			foundLimitsCheck = true
			if check.Passed {
				t.Error("limits check should fail")
			}
		}
	}
	if !foundLimitsCheck {
		t.Error("Expected limits check in results")
	}
	if len(result.Errors) == 0 {
		t.Error("Expected errors when limits exceeded")
	}
}

func TestVerifySession_LimitsNotExceeded(t *testing.T) {
	tmpDir := t.TempDir()

	maxTurns := &aflock.Limit{Value: 100, Enforcement: "post-hoc"}
	sessionState := &aflock.SessionState{
		SessionID: "sess-limits-ok",
		StartedAt: time.Now(),
		Policy: &aflock.Policy{
			Name:    "limits-policy",
			Version: "1.0",
			Limits: &aflock.LimitsPolicy{
				MaxTurns: maxTurns,
			},
		},
		Metrics: &aflock.SessionMetrics{
			Turns:     5,
			ToolCalls: 10,
			Tools:     map[string]int{"Read": 10},
		},
	}

	writeSessionState(t, tmpDir, "sess-limits-ok", sessionState)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-limits-ok")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success=true, limits not exceeded. Errors: %v", result.Errors)
	}

	foundPostHoc := false
	for _, check := range result.Checks {
		if check.Name == "limits:post-hoc" {
			foundPostHoc = true
			if !check.Passed {
				t.Error("limits:post-hoc check should pass")
			}
		}
	}
	if !foundPostHoc {
		t.Error("Expected 'limits:post-hoc' check in results")
	}
}

func TestVerifySession_LimitsFailFastNotCheckedPostHoc(t *testing.T) {
	tmpDir := t.TempDir()

	// fail-fast enforcement should NOT be checked in post-hoc verification
	maxTurns := &aflock.Limit{Value: 3, Enforcement: "fail-fast"}
	sessionState := &aflock.SessionState{
		SessionID: "sess-ff",
		StartedAt: time.Now(),
		Policy: &aflock.Policy{
			Name:    "ff-policy",
			Version: "1.0",
			Limits: &aflock.LimitsPolicy{
				MaxTurns: maxTurns,
			},
		},
		Metrics: &aflock.SessionMetrics{
			Turns:     100, // way over limit, but it's fail-fast, not post-hoc
			ToolCalls: 200,
			Tools:     map[string]int{"Read": 200},
		},
	}

	writeSessionState(t, tmpDir, "sess-ff", sessionState)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-ff")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	// fail-fast limits should not cause post-hoc verification failure
	if !result.Success {
		t.Errorf("Expected success=true, fail-fast limits not checked in post-hoc. Errors: %v", result.Errors)
	}
}

func TestVerifySession_RequiredAttestationsMissing(t *testing.T) {
	tmpDir := t.TempDir()

	sessionState := &aflock.SessionState{
		SessionID: "sess-attest",
		StartedAt: time.Now(),
		Policy: &aflock.Policy{
			Name:                 "attest-policy",
			Version:              "1.0",
			RequiredAttestations: []string{"build", "test"},
		},
		Metrics: &aflock.SessionMetrics{
			Turns:     1,
			ToolCalls: 1,
			Tools:     map[string]int{},
		},
	}

	writeSessionState(t, tmpDir, "sess-attest", sessionState)

	// Create attestation dir with one attestation present, one missing
	attestDir := filepath.Join(tmpDir, "sess-attest", "attestations")
	if err := os.MkdirAll(attestDir, 0755); err != nil {
		t.Fatalf("mkdir attestations: %v", err)
	}
	if err := os.WriteFile(filepath.Join(attestDir, "build.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("write build.json: %v", err)
	}
	// "test" attestation is missing

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-attest")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	if result.Success {
		t.Error("Expected success=false due to missing 'test' attestation")
	}

	buildPassed := false
	testFailed := false
	for _, check := range result.Checks {
		if check.Name == "attestation:build" && check.Passed {
			buildPassed = true
		}
		if check.Name == "attestation:test" && !check.Passed {
			testFailed = true
		}
	}
	if !buildPassed {
		t.Error("Expected 'attestation:build' check to pass (file exists)")
	}
	if !testFailed {
		t.Error("Expected 'attestation:test' check to fail (file missing)")
	}
}

func TestVerifySession_RequiredAttestationsAllPresent(t *testing.T) {
	tmpDir := t.TempDir()

	sessionState := &aflock.SessionState{
		SessionID: "sess-attest-ok",
		StartedAt: time.Now(),
		Policy: &aflock.Policy{
			Name:                 "attest-policy-ok",
			Version:              "1.0",
			RequiredAttestations: []string{"build", "test"},
		},
		Metrics: &aflock.SessionMetrics{
			Turns:     1,
			ToolCalls: 1,
			Tools:     map[string]int{},
		},
	}

	writeSessionState(t, tmpDir, "sess-attest-ok", sessionState)

	attestDir := filepath.Join(tmpDir, "sess-attest-ok", "attestations")
	os.MkdirAll(attestDir, 0755)
	os.WriteFile(filepath.Join(attestDir, "build.json"), []byte("{}"), 0644)
	os.WriteFile(filepath.Join(attestDir, "test.intoto.json"), []byte("{}"), 0644)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-attest-ok")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success=true, all attestations present. Errors: %v", result.Errors)
	}
}

// ---- findAttestation tests ----

func TestFindAttestation_ExactJSON(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "build.json"), []byte("{}"), 0644)

	v := NewVerifier()
	if !v.findAttestation(tmpDir, "build") {
		t.Error("Expected to find build.json")
	}
}

func TestFindAttestation_InTotoJSON(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "build.intoto.json"), []byte("{}"), 0644)

	v := NewVerifier()
	if !v.findAttestation(tmpDir, "build") {
		t.Error("Expected to find build.intoto.json")
	}
}

func TestFindAttestation_GlobMatch(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "build-abc123.json"), []byte("{}"), 0644)

	v := NewVerifier()
	if !v.findAttestation(tmpDir, "build") {
		t.Error("Expected to find via glob match build*")
	}
}

func TestFindAttestation_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	v := NewVerifier()
	if v.findAttestation(tmpDir, "nonexistent") {
		t.Error("Expected not to find nonexistent attestation")
	}
}

func TestFindAttestation_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	v := NewVerifier()
	if v.findAttestation(tmpDir, "anything") {
		t.Error("Expected not to find attestation in empty dir")
	}
}

func TestFindAttestation_NonexistentDir(t *testing.T) {
	v := NewVerifier()
	if v.findAttestation("/nonexistent/path/for/verify/test", "build") {
		t.Error("Expected not to find attestation in nonexistent dir")
	}
}

// ---- containsCheckPrefix tests ----

func TestContainsCheckPrefix(t *testing.T) {
	checks := []CheckResult{
		{Name: "limits:maxTurns", Passed: false},
		{Name: "attestation:build", Passed: true},
		{Name: "actions", Passed: true},
	}

	if !containsCheckPrefix(checks, "limits:") {
		t.Error("Expected to find 'limits:' prefix")
	}
	if !containsCheckPrefix(checks, "attestation:") {
		t.Error("Expected to find 'attestation:' prefix")
	}
	if containsCheckPrefix(checks, "dataflow:") {
		t.Error("Expected not to find 'dataflow:' prefix")
	}
	if !containsCheckPrefix(checks, "actions") {
		t.Error("Expected to find 'actions' prefix")
	}
	if containsCheckPrefix(nil, "anything:") {
		t.Error("Expected false for nil slice")
	}
	if containsCheckPrefix([]CheckResult{}, "anything:") {
		t.Error("Expected false for empty slice")
	}
}

// ---- topoSortSteps tests ----

func TestTopoSortSteps_NoDependencies(t *testing.T) {
	steps := map[string]aflock.Step{
		"build": {Name: "build"},
		"test":  {Name: "test"},
		"lint":  {Name: "lint"},
	}

	sorted := topoSortSteps(steps)

	if len(sorted) != 3 {
		t.Fatalf("Expected 3 steps, got %d", len(sorted))
	}

	// With no dependencies, all have in-degree 0, so output is alphabetical
	expected := []string{"build", "lint", "test"}
	for i, name := range expected {
		if sorted[i] != name {
			t.Errorf("sorted[%d] = %q, want %q", i, sorted[i], name)
		}
	}
}

func TestTopoSortSteps_LinearChain(t *testing.T) {
	steps := map[string]aflock.Step{
		"deploy": {Name: "deploy", ArtifactsFrom: []string{"build"}},
		"build":  {Name: "build"},
		"test":   {Name: "test", ArtifactsFrom: []string{"deploy"}},
	}

	sorted := topoSortSteps(steps)

	if len(sorted) != 3 {
		t.Fatalf("Expected 3 steps, got %d", len(sorted))
	}

	indexOf := make(map[string]int)
	for i, s := range sorted {
		indexOf[s] = i
	}

	if indexOf["build"] > indexOf["deploy"] {
		t.Errorf("build (idx=%d) should come before deploy (idx=%d)", indexOf["build"], indexOf["deploy"])
	}
	if indexOf["deploy"] > indexOf["test"] {
		t.Errorf("deploy (idx=%d) should come before test (idx=%d)", indexOf["deploy"], indexOf["test"])
	}
}

func TestTopoSortSteps_Diamond(t *testing.T) {
	steps := map[string]aflock.Step{
		"A": {Name: "A"},
		"B": {Name: "B", ArtifactsFrom: []string{"A"}},
		"C": {Name: "C", ArtifactsFrom: []string{"A"}},
		"D": {Name: "D", ArtifactsFrom: []string{"B", "C"}},
	}

	sorted := topoSortSteps(steps)

	if len(sorted) != 4 {
		t.Fatalf("Expected 4 steps, got %d", len(sorted))
	}

	indexOf := make(map[string]int)
	for i, s := range sorted {
		indexOf[s] = i
	}

	if indexOf["A"] > indexOf["B"] {
		t.Error("A should come before B")
	}
	if indexOf["A"] > indexOf["C"] {
		t.Error("A should come before C")
	}
	if indexOf["B"] > indexOf["D"] {
		t.Error("B should come before D")
	}
	if indexOf["C"] > indexOf["D"] {
		t.Error("C should come before D")
	}
}

func TestTopoSortSteps_Cycle(t *testing.T) {
	steps := map[string]aflock.Step{
		"A": {Name: "A", ArtifactsFrom: []string{"C"}},
		"B": {Name: "B", ArtifactsFrom: []string{"A"}},
		"C": {Name: "C", ArtifactsFrom: []string{"B"}},
	}

	sorted := topoSortSteps(steps)

	if len(sorted) != 3 {
		t.Fatalf("Expected 3 steps (cycle fallback), got %d: %v", len(sorted), sorted)
	}

	seen := make(map[string]bool)
	for _, s := range sorted {
		if seen[s] {
			t.Errorf("Duplicate step %q in output", s)
		}
		seen[s] = true
	}
	// Cycle: no nodes have in-degree 0, so all end up in the "remaining" fallback
	// remaining is sorted alphabetically
	expected := []string{"A", "B", "C"}
	for i, name := range expected {
		if sorted[i] != name {
			t.Errorf("sorted[%d] = %q, want %q (alphabetical cycle fallback)", i, sorted[i], name)
		}
	}
}

func TestTopoSortSteps_Empty(t *testing.T) {
	sorted := topoSortSteps(map[string]aflock.Step{})
	if len(sorted) != 0 {
		t.Errorf("Expected empty slice, got %v", sorted)
	}
}

func TestTopoSortSteps_SingleStep(t *testing.T) {
	steps := map[string]aflock.Step{
		"only": {Name: "only"},
	}
	sorted := topoSortSteps(steps)
	if len(sorted) != 1 || sorted[0] != "only" {
		t.Errorf("Expected [only], got %v", sorted)
	}
}

func TestTopoSortSteps_ExternalDependency(t *testing.T) {
	// Step references an ArtifactsFrom that doesn't exist in steps map
	steps := map[string]aflock.Step{
		"build":  {Name: "build"},
		"deploy": {Name: "deploy", ArtifactsFrom: []string{"external-step"}},
	}

	sorted := topoSortSteps(steps)
	if len(sorted) != 2 {
		t.Fatalf("Expected 2 steps, got %d: %v", len(sorted), sorted)
	}
	// Both should appear since external deps are ignored
	seen := map[string]bool{}
	for _, s := range sorted {
		seen[s] = true
	}
	if !seen["build"] || !seen["deploy"] {
		t.Errorf("Expected both build and deploy in sorted, got %v", sorted)
	}
}

func TestTopoSortSteps_PartialCycle(t *testing.T) {
	// A has no deps, B <-> C form a cycle, D depends on A
	steps := map[string]aflock.Step{
		"A": {Name: "A"},
		"B": {Name: "B", ArtifactsFrom: []string{"C"}},
		"C": {Name: "C", ArtifactsFrom: []string{"B"}},
		"D": {Name: "D", ArtifactsFrom: []string{"A"}},
	}

	sorted := topoSortSteps(steps)
	if len(sorted) != 4 {
		t.Fatalf("Expected 4 steps, got %d: %v", len(sorted), sorted)
	}

	indexOf := make(map[string]int)
	for i, s := range sorted {
		indexOf[s] = i
	}

	// A before D is guaranteed
	if indexOf["A"] > indexOf["D"] {
		t.Error("A should come before D")
	}
	// B and C are in cycle, appended after normal sort.
	// A and D should be sorted first, then B and C appended.
	// A comes first, D depends on A so D comes second,
	// then B,C are remaining (cycle) appended alphabetically.
}

// ---- loadRootCertificates tests ----

func TestLoadRootCertificates_InlinePEM(t *testing.T) {
	caCert, _ := generateTestCA(t)
	pemStr := certToPEM(caCert)

	roots := map[string]aflock.Root{
		"test-ca": {Certificate: pemStr},
	}

	certs, err := loadRootCertificates(roots)
	if err != nil {
		t.Fatalf("loadRootCertificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("Expected 1 cert, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "Test CA" {
		t.Errorf("CommonName = %q, want 'Test CA'", certs[0].Subject.CommonName)
	}
}

func TestLoadRootCertificates_Base64DER(t *testing.T) {
	caCert, _ := generateTestCA(t)
	b64 := base64.StdEncoding.EncodeToString(caCert.Raw)

	roots := map[string]aflock.Root{
		"test-ca": {Certificate: b64},
	}

	certs, err := loadRootCertificates(roots)
	if err != nil {
		t.Fatalf("loadRootCertificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("Expected 1 cert, got %d", len(certs))
	}
}

func TestLoadRootCertificates_FromFile(t *testing.T) {
	caCert, _ := generateTestCA(t)
	pemStr := certToPEM(caCert)

	tmpFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(tmpFile, []byte(pemStr), 0644)

	roots := map[string]aflock.Root{
		"test-ca": {Certificate: tmpFile},
	}

	certs, err := loadRootCertificates(roots)
	if err != nil {
		t.Fatalf("loadRootCertificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("Expected 1 cert, got %d", len(certs))
	}
}

func TestLoadRootCertificates_EmptyCertificate(t *testing.T) {
	roots := map[string]aflock.Root{
		"empty": {Certificate: ""},
	}

	certs, err := loadRootCertificates(roots)
	if err != nil {
		t.Fatalf("loadRootCertificates: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("Expected 0 certs for empty certificate, got %d", len(certs))
	}
}

func TestLoadRootCertificates_InvalidData(t *testing.T) {
	roots := map[string]aflock.Root{
		"bad": {Certificate: "not-valid-pem-or-base64-!!!"},
	}

	_, err := loadRootCertificates(roots)
	if err == nil {
		t.Fatal("Expected error for invalid certificate data")
	}
	if !strings.Contains(err.Error(), "cannot parse certificate") {
		t.Errorf("Error = %q, expected to contain 'cannot parse certificate'", err.Error())
	}
}

func TestLoadRootCertificates_MultipleCerts(t *testing.T) {
	ca1, _ := generateTestCA(t)
	ca2, _ := generateTestCA(t)

	roots := map[string]aflock.Root{
		"ca1": {Certificate: certToPEM(ca1)},
		"ca2": {Certificate: certToPEM(ca2)},
	}

	certs, err := loadRootCertificates(roots)
	if err != nil {
		t.Fatalf("loadRootCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("Expected 2 certs, got %d", len(certs))
	}
}

func TestLoadRootCertificates_NilMap(t *testing.T) {
	certs, err := loadRootCertificates(nil)
	if err != nil {
		t.Fatalf("loadRootCertificates(nil): %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("Expected 0 certs for nil map, got %d", len(certs))
	}
}

// ---- verifySignatureWithCert tests ----

func TestVerifySignatureWithCert_ECDSA_Valid(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	data := []byte("test message to sign")
	hash := sha256.Sum256(data)

	sig, err := ecdsa.SignASN1(rand.Reader, caKey, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !verifySignatureWithCert(caCert, data, hash[:], sig) {
		t.Error("Expected valid ECDSA signature to verify")
	}
}

func TestVerifySignatureWithCert_WrongKey(t *testing.T) {
	_, signingKey := generateTestCA(t)
	otherCert, _ := generateTestCA(t)

	data := []byte("test message")
	hash := sha256.Sum256(data)

	sig, err := ecdsa.SignASN1(rand.Reader, signingKey, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if verifySignatureWithCert(otherCert, data, hash[:], sig) {
		t.Error("Expected signature verification to fail with wrong key")
	}
}

func TestVerifySignatureWithCert_CorruptedSig(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	data := []byte("test message")
	hash := sha256.Sum256(data)

	sig, err := ecdsa.SignASN1(rand.Reader, caKey, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	corrupted := make([]byte, len(sig))
	copy(corrupted, sig)
	corrupted[len(corrupted)-1] ^= 0xFF

	if verifySignatureWithCert(caCert, data, hash[:], corrupted) {
		t.Error("Expected corrupted signature to fail verification")
	}
}

func TestVerifySignatureWithCert_WrongHash(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	data := []byte("correct message")
	hash := sha256.Sum256(data)

	sig, err := ecdsa.SignASN1(rand.Reader, caKey, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	wrongData := []byte("wrong message")
	wrongHash := sha256.Sum256(wrongData)
	if verifySignatureWithCert(caCert, wrongData, wrongHash[:], sig) {
		t.Error("Expected verification to fail with wrong hash")
	}
}

// ---- matchesFunctionary tests ----

func TestMatchesFunctionary_NoFunctionaries(t *testing.T) {
	caCert, _ := generateTestCA(t)
	step := &aflock.Step{
		Name:          "test-step",
		Functionaries: nil,
	}

	if !matchesFunctionary(caCert, "any-key-id", step) {
		t.Error("Expected match when step has no functionaries")
	}
}

func TestMatchesFunctionary_EmptyFunctionaries(t *testing.T) {
	caCert, _ := generateTestCA(t)
	step := &aflock.Step{
		Name:          "test-step",
		Functionaries: []aflock.StepFunctionary{},
	}

	if !matchesFunctionary(caCert, "any-key-id", step) {
		t.Error("Expected match when step has empty functionaries slice")
	}
}

func TestMatchesFunctionary_PublicKeyID_Match(t *testing.T) {
	caCert, _ := generateTestCA(t)
	step := &aflock.Step{
		Name: "test-step",
		Functionaries: []aflock.StepFunctionary{
			{Type: "publickey", PublicKeyID: "spiffe://aflock.ai/agent/test"},
		},
	}

	if !matchesFunctionary(caCert, "spiffe://aflock.ai/agent/test", step) {
		t.Error("Expected match on PublicKeyID")
	}
}

func TestMatchesFunctionary_PublicKeyID_Mismatch(t *testing.T) {
	caCert, _ := generateTestCA(t)
	step := &aflock.Step{
		Name: "test-step",
		Functionaries: []aflock.StepFunctionary{
			{Type: "publickey", PublicKeyID: "spiffe://aflock.ai/agent/expected"},
		},
	}

	if matchesFunctionary(caCert, "spiffe://aflock.ai/agent/other", step) {
		t.Error("Expected no match on wrong PublicKeyID")
	}
}

func TestMatchesFunctionary_CertConstraint_CommonName(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leafCert, _ := generateTestLeafCert(t, caCert, caKey, "my-agent")

	step := &aflock.Step{
		Name: "test-step",
		Functionaries: []aflock.StepFunctionary{
			{
				Type: "root",
				CertConstraint: &aflock.CertConstraint{
					CommonName: "my-agent",
				},
			},
		},
	}

	if !matchesFunctionary(leafCert, "", step) {
		t.Error("Expected match on CommonName constraint")
	}

	wrongCert, _ := generateTestLeafCert(t, caCert, caKey, "other-agent")
	if matchesFunctionary(wrongCert, "", step) {
		t.Error("Expected no match for wrong CommonName")
	}
}

func TestMatchesFunctionary_CertConstraint_URIs(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leafCert, _ := generateTestLeafCert(t, caCert, caKey, "agent",
		"spiffe://aflock.ai/agent/claude-opus/4.5/abc123")

	step := &aflock.Step{
		Name: "test-step",
		Functionaries: []aflock.StepFunctionary{
			{
				Type: "root",
				CertConstraint: &aflock.CertConstraint{
					URIs: []string{"spiffe://aflock.ai/agent/claude-opus/4.5/*"},
				},
			},
		},
	}

	if !matchesFunctionary(leafCert, "", step) {
		t.Error("Expected match on URI SAN pattern")
	}
}

func TestMatchesFunctionary_CertConstraint_URIs_NoMatch(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leafCert, _ := generateTestLeafCert(t, caCert, caKey, "agent",
		"spiffe://aflock.ai/agent/claude-haiku/3.5/xyz")

	step := &aflock.Step{
		Name: "test-step",
		Functionaries: []aflock.StepFunctionary{
			{
				Type: "root",
				CertConstraint: &aflock.CertConstraint{
					URIs: []string{"spiffe://aflock.ai/agent/claude-opus/*"},
				},
			},
		},
	}

	if matchesFunctionary(leafCert, "", step) {
		t.Error("Expected no match for non-matching URI")
	}
}

func TestMatchesFunctionary_MultipleFunctionaries_OneMatches(t *testing.T) {
	caCert, _ := generateTestCA(t)
	step := &aflock.Step{
		Name: "test-step",
		Functionaries: []aflock.StepFunctionary{
			{Type: "publickey", PublicKeyID: "wrong-key"},
			{Type: "publickey", PublicKeyID: "correct-key"},
		},
	}

	if !matchesFunctionary(caCert, "correct-key", step) {
		t.Error("Expected match when one of multiple functionaries matches")
	}
}

// ---- matchSPIFFEPattern tests ----

func TestMatchSPIFFEPattern_ExactMatch(t *testing.T) {
	if !matchSPIFFEPattern("spiffe://a.b/c", "spiffe://a.b/c") {
		t.Error("Expected exact match")
	}
}

func TestMatchSPIFFEPattern_GlobWildcard(t *testing.T) {
	if !matchSPIFFEPattern("spiffe://a.b/*", "spiffe://a.b/anything") {
		t.Error("Expected glob wildcard match")
	}
}

func TestMatchSPIFFEPattern_NoMatch(t *testing.T) {
	if matchSPIFFEPattern("spiffe://a.b/c", "spiffe://x.y/z") {
		t.Error("Expected no match")
	}
}

func TestMatchSPIFFEPattern_MultiSegmentNoMatch(t *testing.T) {
	// * only matches a single path segment with filepath.Match
	if matchSPIFFEPattern("spiffe://a.b/*", "spiffe://a.b/c/d") {
		t.Error("Expected * not to match multiple path segments")
	}
}

func TestMatchSPIFFEPattern_EmptyStrings(t *testing.T) {
	if !matchSPIFFEPattern("", "") {
		t.Error("Expected empty strings to match")
	}
	if matchSPIFFEPattern("something", "") {
		t.Error("Expected no match for empty spiffeID against non-empty pattern")
	}
}

// ---- certMatchesConstraint tests ----

func TestCertMatchesConstraint_EmptyConstraint(t *testing.T) {
	caCert, _ := generateTestCA(t)
	constraint := &aflock.CertConstraint{}

	if !certMatchesConstraint(caCert, constraint) {
		t.Error("Expected empty constraint to match any cert")
	}
}

func TestCertMatchesConstraint_CommonNameOnly(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leafCert, _ := generateTestLeafCert(t, caCert, caKey, "specific-cn")

	constraint := &aflock.CertConstraint{CommonName: "specific-cn"}
	if !certMatchesConstraint(leafCert, constraint) {
		t.Error("Expected CN match")
	}

	constraint2 := &aflock.CertConstraint{CommonName: "wrong-cn"}
	if certMatchesConstraint(leafCert, constraint2) {
		t.Error("Expected CN mismatch")
	}
}

func TestCertMatchesConstraint_URIsOnly(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leafCert, _ := generateTestLeafCert(t, caCert, caKey, "agent",
		"spiffe://aflock.ai/agent/test")

	constraint := &aflock.CertConstraint{
		URIs: []string{"spiffe://aflock.ai/agent/test"},
	}
	if !certMatchesConstraint(leafCert, constraint) {
		t.Error("Expected URI match")
	}
}

func TestCertMatchesConstraint_BothCommonNameAndURIs(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leafCert, _ := generateTestLeafCert(t, caCert, caKey, "my-agent",
		"spiffe://aflock.ai/agent/test")

	// Both match
	constraint := &aflock.CertConstraint{
		CommonName: "my-agent",
		URIs:       []string{"spiffe://aflock.ai/agent/test"},
	}
	if !certMatchesConstraint(leafCert, constraint) {
		t.Error("Expected both CN and URI to match")
	}

	// CN matches, URI doesn't
	constraint2 := &aflock.CertConstraint{
		CommonName: "my-agent",
		URIs:       []string{"spiffe://other.ai/agent/test"},
	}
	if certMatchesConstraint(leafCert, constraint2) {
		t.Error("Expected failure when URI doesn't match")
	}

	// URI matches, CN doesn't
	constraint3 := &aflock.CertConstraint{
		CommonName: "wrong-agent",
		URIs:       []string{"spiffe://aflock.ai/agent/test"},
	}
	if certMatchesConstraint(leafCert, constraint3) {
		t.Error("Expected failure when CN doesn't match")
	}
}

func TestCertMatchesConstraint_CertWithNoURIs(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leafCert, _ := generateTestLeafCert(t, caCert, caKey, "agent") // no URIs

	constraint := &aflock.CertConstraint{
		URIs: []string{"spiffe://aflock.ai/agent/*"},
	}
	if certMatchesConstraint(leafCert, constraint) {
		t.Error("Expected failure when cert has no URIs but constraint requires them")
	}
}

// ---- VerifyAttestation tests (DSSE envelope verification) ----

func TestVerifyAttestation_ValidEnvelope(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	statement := map[string]interface{}{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]interface{}{
			{
				"name":   "test-subject",
				"digest": map[string]string{"sha256": "abc123"},
			},
		},
		"predicateType": "https://aflock.ai/attestations/action/v0.1",
		"predicate":     map[string]string{"action": "test"},
	}
	payload, _ := json.Marshal(statement)

	envelopeData := signDSSE(t, "application/vnd.in-toto+json", payload, caKey, "test-key")

	envelopePath := filepath.Join(t.TempDir(), "test.intoto.json")
	os.WriteFile(envelopePath, envelopeData, 0644)

	pol := &aflock.Policy{
		Roots: map[string]aflock.Root{
			"test-ca": {Certificate: certToPEM(caCert)},
		},
	}

	v := NewVerifier()
	err := v.VerifyAttestation(envelopePath, pol)
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
}

func TestVerifyAttestation_WrongPayloadType(t *testing.T) {
	_, caKey := generateTestCA(t)

	payload, _ := json.Marshal(map[string]string{"test": "data"})
	envelopeData := signDSSE(t, "wrong/type", payload, caKey, "test-key")

	envelopePath := filepath.Join(t.TempDir(), "wrong-type.json")
	os.WriteFile(envelopePath, envelopeData, 0644)

	pol := &aflock.Policy{
		Roots: map[string]aflock.Root{
			"test-ca": {Certificate: "unused"},
		},
	}

	v := NewVerifier()
	err := v.VerifyAttestation(envelopePath, pol)
	if err == nil {
		t.Fatal("Expected error for wrong payload type")
	}
	if !strings.Contains(err.Error(), "invalid payload type") {
		t.Errorf("Error = %q, expected 'invalid payload type'", err.Error())
	}
}

func TestVerifyAttestation_WrongStatementType(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	statement := map[string]interface{}{
		"_type":         "https://example.com/Wrong/v1",
		"predicateType": "test",
		"predicate":     map[string]string{},
		"subject":       []map[string]interface{}{},
	}
	payload, _ := json.Marshal(statement)

	envelopeData := signDSSE(t, "application/vnd.in-toto+json", payload, caKey, "k")
	envelopePath := filepath.Join(t.TempDir(), "wrong-stmt.json")
	os.WriteFile(envelopePath, envelopeData, 0644)

	pol := &aflock.Policy{
		Roots: map[string]aflock.Root{
			"ca": {Certificate: certToPEM(caCert)},
		},
	}

	v := NewVerifier()
	err := v.VerifyAttestation(envelopePath, pol)
	if err == nil {
		t.Fatal("Expected error for wrong statement type")
	}
	if !strings.Contains(err.Error(), "invalid statement type") {
		t.Errorf("Error = %q, expected 'invalid statement type'", err.Error())
	}
}

func TestVerifyAttestation_V01StatementTypeRejected(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	statement := map[string]interface{}{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": []map[string]interface{}{
			{
				"name":   "test",
				"digest": map[string]string{"sha256": "abc"},
			},
		},
		"predicateType": "test",
		"predicate":     map[string]string{},
	}
	payload, _ := json.Marshal(statement)

	envelopeData := signDSSE(t, "application/vnd.in-toto+json", payload, caKey, "k")
	envelopePath := filepath.Join(t.TempDir(), "v01.json")
	os.WriteFile(envelopePath, envelopeData, 0644)

	pol := &aflock.Policy{
		Roots: map[string]aflock.Root{
			"ca": {Certificate: certToPEM(caCert)},
		},
	}

	v := NewVerifier()
	err := v.VerifyAttestation(envelopePath, pol)
	if err == nil {
		t.Fatal("Expected error for deprecated v0.1 statement type")
	}
	if !strings.Contains(err.Error(), "invalid statement type") {
		t.Errorf("Error = %q, expected 'invalid statement type'", err.Error())
	}
	if !strings.Contains(err.Error(), "v0.1") {
		t.Errorf("Error = %q, expected it to mention the v0.1 type", err.Error())
	}
}

func TestVerifyAttestation_NoRoots(t *testing.T) {
	_, caKey := generateTestCA(t)

	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "test",
		"predicate":     map[string]string{},
		"subject":       []map[string]interface{}{},
	}
	payload, _ := json.Marshal(statement)

	envelopeData := signDSSE(t, "application/vnd.in-toto+json", payload, caKey, "k")
	envelopePath := filepath.Join(t.TempDir(), "no-roots.json")
	os.WriteFile(envelopePath, envelopeData, 0644)

	pol := &aflock.Policy{}

	v := NewVerifier()
	err := v.VerifyAttestation(envelopePath, pol)
	if err == nil {
		t.Fatal("Expected error when no roots configured")
	}
	if !strings.Contains(err.Error(), "no policy roots configured") {
		t.Errorf("Error = %q, expected 'no policy roots configured'", err.Error())
	}
}

func TestVerifyAttestation_NilPolicy(t *testing.T) {
	_, caKey := generateTestCA(t)

	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "test",
		"predicate":     map[string]string{},
		"subject":       []map[string]interface{}{},
	}
	payload, _ := json.Marshal(statement)

	envelopeData := signDSSE(t, "application/vnd.in-toto+json", payload, caKey, "k")
	envelopePath := filepath.Join(t.TempDir(), "nil-pol.json")
	os.WriteFile(envelopePath, envelopeData, 0644)

	v := NewVerifier()
	err := v.VerifyAttestation(envelopePath, nil)
	if err == nil {
		t.Fatal("Expected error for nil policy")
	}
	if !strings.Contains(err.Error(), "no policy roots configured") {
		t.Errorf("Error = %q, expected 'no policy roots configured'", err.Error())
	}
}

func TestVerifyAttestation_InvalidSignature(t *testing.T) {
	caCert, _ := generateTestCA(t)
	_, wrongKey := generateTestCA(t)

	statement := map[string]interface{}{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]interface{}{
			{
				"name":   "test",
				"digest": map[string]string{"sha256": "abc"},
			},
		},
		"predicateType": "test",
		"predicate":     map[string]string{},
	}
	payload, _ := json.Marshal(statement)

	envelopeData := signDSSE(t, "application/vnd.in-toto+json", payload, wrongKey, "k")
	envelopePath := filepath.Join(t.TempDir(), "bad-sig.json")
	os.WriteFile(envelopePath, envelopeData, 0644)

	pol := &aflock.Policy{
		Roots: map[string]aflock.Root{
			"ca": {Certificate: certToPEM(caCert)},
		},
	}

	v := NewVerifier()
	err := v.VerifyAttestation(envelopePath, pol)
	if err == nil {
		t.Fatal("Expected error for invalid signature")
	}
	if !strings.Contains(err.Error(), "signature verification") {
		t.Errorf("Error = %q, expected to contain 'signature verification'", err.Error())
	}
}

func TestVerifyAttestation_MalformedJSON(t *testing.T) {
	envelopePath := filepath.Join(t.TempDir(), "malformed.json")
	os.WriteFile(envelopePath, []byte("not json at all{{{"), 0644)

	v := NewVerifier()
	err := v.VerifyAttestation(envelopePath, &aflock.Policy{})
	if err == nil {
		t.Fatal("Expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "parse envelope") {
		t.Errorf("Error = %q, expected 'parse envelope'", err.Error())
	}
}

func TestVerifyAttestation_MalformedPayloadBase64(t *testing.T) {
	envelope := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     "!!!not-base64!!!",
		"signatures":  []map[string]string{{"keyid": "k", "sig": "s"}},
	}
	data, _ := json.Marshal(envelope)

	envelopePath := filepath.Join(t.TempDir(), "bad-b64.json")
	os.WriteFile(envelopePath, data, 0644)

	pol := &aflock.Policy{
		Roots: map[string]aflock.Root{
			"ca": {Certificate: "anything"},
		},
	}

	v := NewVerifier()
	err := v.VerifyAttestation(envelopePath, pol)
	if err == nil {
		t.Fatal("Expected error for malformed base64 payload")
	}
}

func TestVerifyAttestation_NonexistentFile(t *testing.T) {
	v := NewVerifier()
	err := v.VerifyAttestation("/nonexistent/path/to/envelope.json", &aflock.Policy{})
	if err == nil {
		t.Fatal("Expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "read envelope") {
		t.Errorf("Error = %q, expected 'read envelope'", err.Error())
	}
}

func TestVerifyAttestation_EmptyPayload(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	// Empty payload that is valid base64 but not valid JSON for Statement
	emptyPayload := []byte("")
	envelopeData := signDSSE(t, "application/vnd.in-toto+json", emptyPayload, caKey, "k")

	envelopePath := filepath.Join(t.TempDir(), "empty-payload.json")
	os.WriteFile(envelopePath, envelopeData, 0644)

	pol := &aflock.Policy{
		Roots: map[string]aflock.Root{
			"ca": {Certificate: certToPEM(caCert)},
		},
	}

	v := NewVerifier()
	err := v.VerifyAttestation(envelopePath, pol)
	if err == nil {
		t.Fatal("Expected error for empty payload (cannot parse as Statement)")
	}
}

func TestVerifyAttestation_NoSignatures(t *testing.T) {
	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "test",
		"predicate":     map[string]string{},
		"subject":       []map[string]interface{}{},
	}
	payload, _ := json.Marshal(statement)

	envelope := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures":  []map[string]string{},
	}
	data, _ := json.Marshal(envelope)

	envelopePath := filepath.Join(t.TempDir(), "no-sigs.json")
	os.WriteFile(envelopePath, data, 0644)

	caCert, _ := generateTestCA(t)
	pol := &aflock.Policy{
		Roots: map[string]aflock.Root{
			"ca": {Certificate: certToPEM(caCert)},
		},
	}

	v := NewVerifier()
	err := v.VerifyAttestation(envelopePath, pol)
	if err == nil {
		t.Fatal("Expected error for envelope with no signatures")
	}
}

// ---- VerifySteps tests ----

func TestVerifySteps_NoSteps(t *testing.T) {
	pol := &aflock.Policy{
		Name:    "empty-steps",
		Version: "1.0",
	}

	v := NewVerifier()
	result, err := v.VerifySteps(pol, t.TempDir(), "abc123")
	if err != nil {
		t.Fatalf("VerifySteps: %v", err)
	}

	if !result.Success {
		t.Error("Expected success=true for policy with no steps")
	}
	if result.TreeHash != "abc123" {
		t.Errorf("TreeHash = %q, want 'abc123'", result.TreeHash)
	}
	if result.PolicyName != "empty-steps" {
		t.Errorf("PolicyName = %q, want 'empty-steps'", result.PolicyName)
	}
	if len(result.Steps) != 0 {
		t.Errorf("Expected 0 step results, got %d", len(result.Steps))
	}
}

func TestVerifySteps_ExpiredPolicy(t *testing.T) {
	expired := time.Now().Add(-1 * time.Hour)
	pol := &aflock.Policy{
		Name:    "expired-policy",
		Version: "1.0",
		Expires: &expired,
		Steps: map[string]aflock.Step{
			"build": {Name: "build"},
		},
	}

	v := NewVerifier()
	result, err := v.VerifySteps(pol, t.TempDir(), "abc123")
	if err != nil {
		t.Fatalf("VerifySteps: %v", err)
	}

	if result.Success {
		t.Error("Expected success=false for expired policy")
	}
	if len(result.Errors) == 0 {
		t.Error("Expected errors for expired policy")
	}
	foundExpiredMsg := false
	for _, e := range result.Errors {
		if strings.Contains(e, "expired") || strings.Contains(e, "Policy expired") {
			foundExpiredMsg = true
		}
	}
	if !foundExpiredMsg {
		t.Errorf("Expected expiration error, got: %v", result.Errors)
	}
}

func TestVerifySteps_NotExpired(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	pol := &aflock.Policy{
		Name:    "valid-policy",
		Version: "1.0",
		Expires: &future,
		// No steps, so nothing to fail
	}

	v := NewVerifier()
	result, err := v.VerifySteps(pol, t.TempDir(), "abc")
	if err != nil {
		t.Fatalf("VerifySteps: %v", err)
	}
	if !result.Success {
		t.Error("Expected success=true for non-expired policy with no steps")
	}
}

func TestVerifySteps_MissingAttestation(t *testing.T) {
	pol := &aflock.Policy{
		Name:    "step-policy",
		Version: "1.0",
		Steps: map[string]aflock.Step{
			"build": {
				Name: "build",
				Functionaries: []aflock.StepFunctionary{
					{Type: "root"},
				},
			},
		},
		Roots: map[string]aflock.Root{
			"ca": {Certificate: "unused"},
		},
	}

	attestDir := t.TempDir()

	v := NewVerifier()
	result, err := v.VerifySteps(pol, attestDir, "abc123")
	if err != nil {
		t.Fatalf("VerifySteps: %v", err)
	}

	if result.Success {
		t.Error("Expected success=false for missing attestation")
	}

	buildResult, ok := result.Steps["build"]
	if !ok {
		t.Fatal("Expected 'build' step in results")
	}
	if buildResult.Found {
		t.Error("Expected Found=false for missing attestation")
	}
}

func TestVerifySteps_ValidStepAttestation(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	pol := &aflock.Policy{
		Name:    "valid-step-policy",
		Version: "1.0",
		Steps: map[string]aflock.Step{
			"build": {
				Name: "build",
				Attestations: []aflock.StepAttestation{
					{Type: "https://aflock.ai/attestations/material/v0.1"},
				},
			},
		},
		Roots: map[string]aflock.Root{
			"ca": {Certificate: certToPEM(caCert)},
		},
	}

	payload := makeCollectionPayload(t, "build", []string{
		"https://aflock.ai/attestations/material/v0.1",
	})
	envelopeData := signDSSE(t, "application/vnd.in-toto+json", payload, caKey, "test-key")

	attestDir := t.TempDir()
	treeHash := "deadbeef"
	hashDir := filepath.Join(attestDir, treeHash)
	os.MkdirAll(hashDir, 0755)
	os.WriteFile(filepath.Join(hashDir, "build.intoto.json"), envelopeData, 0644)

	v := NewVerifier()
	result, err := v.VerifySteps(pol, attestDir, treeHash)
	if err != nil {
		t.Fatalf("VerifySteps: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success=true. Errors: %v", result.Errors)
	}

	buildResult := result.Steps["build"]
	if !buildResult.Found {
		t.Error("Expected Found=true")
	}
	if !buildResult.SignatureValid {
		t.Error("Expected SignatureValid=true")
	}
}

func TestVerifySteps_StepNameMismatch(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	pol := &aflock.Policy{
		Name:    "mismatch-policy",
		Version: "1.0",
		Steps: map[string]aflock.Step{
			"build": {
				Name: "build",
			},
		},
		Roots: map[string]aflock.Root{
			"ca": {Certificate: certToPEM(caCert)},
		},
	}

	payload := makeCollectionPayload(t, "wrong-step-name", nil)
	envelopeData := signDSSE(t, "application/vnd.in-toto+json", payload, caKey, "k")

	attestDir := t.TempDir()
	treeHash := "abc123"
	hashDir := filepath.Join(attestDir, treeHash)
	os.MkdirAll(hashDir, 0755)
	os.WriteFile(filepath.Join(hashDir, "build.intoto.json"), envelopeData, 0644)

	v := NewVerifier()
	result, err := v.VerifySteps(pol, attestDir, treeHash)
	if err != nil {
		t.Fatalf("VerifySteps: %v", err)
	}

	if result.Success {
		t.Error("Expected failure due to step name mismatch")
	}

	buildResult := result.Steps["build"]
	if buildResult.SignatureValid {
		t.Error("Expected SignatureValid=false due to step name mismatch")
	}
}

func TestVerifySteps_MissingRequiredAttestationType(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	pol := &aflock.Policy{
		Name:    "missing-type-policy",
		Version: "1.0",
		Steps: map[string]aflock.Step{
			"build": {
				Name: "build",
				Attestations: []aflock.StepAttestation{
					{Type: "https://aflock.ai/attestations/product/v0.1"},
				},
			},
		},
		Roots: map[string]aflock.Root{
			"ca": {Certificate: certToPEM(caCert)},
		},
	}

	// Only has material, missing product
	payload := makeCollectionPayload(t, "build", []string{
		"https://aflock.ai/attestations/material/v0.1",
	})
	envelopeData := signDSSE(t, "application/vnd.in-toto+json", payload, caKey, "k")

	attestDir := t.TempDir()
	treeHash := "abc"
	hashDir := filepath.Join(attestDir, treeHash)
	os.MkdirAll(hashDir, 0755)
	os.WriteFile(filepath.Join(hashDir, "build.intoto.json"), envelopeData, 0644)

	v := NewVerifier()
	result, err := v.VerifySteps(pol, attestDir, treeHash)
	if err != nil {
		t.Fatalf("VerifySteps: %v", err)
	}

	if result.Success {
		t.Error("Expected failure due to missing required attestation type")
	}
}

func TestVerifySteps_ArtifactChainValid(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	pol := &aflock.Policy{
		Name:    "chain-policy",
		Version: "1.0",
		Steps: map[string]aflock.Step{
			"build": {
				Name: "build",
			},
			"test": {
				Name:          "test",
				ArtifactsFrom: []string{"build"},
			},
		},
		Roots: map[string]aflock.Root{
			"ca": {Certificate: certToPEM(caCert)},
		},
	}

	buildPayload := makeArtifactPayload(t, "build",
		nil,
		map[string]map[string]string{
			"binary.exe": {"sha256": "deadbeefdeadbeef"},
		},
	)
	buildEnvelope := signDSSE(t, "application/vnd.in-toto+json", buildPayload, caKey, "k")

	testPayload := makeArtifactPayload(t, "test",
		map[string]map[string]string{
			"binary.exe": {"sha256": "deadbeefdeadbeef"},
		},
		nil,
	)
	testEnvelope := signDSSE(t, "application/vnd.in-toto+json", testPayload, caKey, "k")

	attestDir := t.TempDir()
	treeHash := "chaintest"
	hashDir := filepath.Join(attestDir, treeHash)
	os.MkdirAll(hashDir, 0755)
	os.WriteFile(filepath.Join(hashDir, "build.intoto.json"), buildEnvelope, 0644)
	os.WriteFile(filepath.Join(hashDir, "test.intoto.json"), testEnvelope, 0644)

	v := NewVerifier()
	result, err := v.VerifySteps(pol, attestDir, treeHash)
	if err != nil {
		t.Fatalf("VerifySteps: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success=true for valid artifact chain. Errors: %v", result.Errors)
	}

	testResult := result.Steps["test"]
	if !testResult.ArtifactsMatch {
		t.Error("Expected ArtifactsMatch=true")
	}
}

func TestVerifySteps_ArtifactChainMismatch(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	pol := &aflock.Policy{
		Name:    "chain-mismatch-policy",
		Version: "1.0",
		Steps: map[string]aflock.Step{
			"build": {
				Name: "build",
			},
			"test": {
				Name:          "test",
				ArtifactsFrom: []string{"build"},
			},
		},
		Roots: map[string]aflock.Root{
			"ca": {Certificate: certToPEM(caCert)},
		},
	}

	buildPayload := makeArtifactPayload(t, "build",
		nil,
		map[string]map[string]string{
			"binary.exe": {"sha256": "aaaaaa"},
		},
	)
	buildEnvelope := signDSSE(t, "application/vnd.in-toto+json", buildPayload, caKey, "k")

	testPayload := makeArtifactPayload(t, "test",
		map[string]map[string]string{
			"binary.exe": {"sha256": "bbbbbb"},
		},
		nil,
	)
	testEnvelope := signDSSE(t, "application/vnd.in-toto+json", testPayload, caKey, "k")

	attestDir := t.TempDir()
	treeHash := "chainmismatch"
	hashDir := filepath.Join(attestDir, treeHash)
	os.MkdirAll(hashDir, 0755)
	os.WriteFile(filepath.Join(hashDir, "build.intoto.json"), buildEnvelope, 0644)
	os.WriteFile(filepath.Join(hashDir, "test.intoto.json"), testEnvelope, 0644)

	v := NewVerifier()
	result, err := v.VerifySteps(pol, attestDir, treeHash)
	if err != nil {
		t.Fatalf("VerifySteps: %v", err)
	}

	if result.Success {
		t.Error("Expected failure due to artifact chain mismatch")
	}

	testResult := result.Steps["test"]
	if testResult.ArtifactsMatch {
		t.Error("Expected ArtifactsMatch=false for digest mismatch")
	}
}

func TestVerifySteps_ArtifactFromMissingStep(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	pol := &aflock.Policy{
		Name:    "missing-from-policy",
		Version: "1.0",
		Steps: map[string]aflock.Step{
			"test": {
				Name:          "test",
				ArtifactsFrom: []string{"build"}, // "build" step exists in policy but has no attestation
			},
			"build": {
				Name: "build",
			},
		},
		Roots: map[string]aflock.Root{
			"ca": {Certificate: certToPEM(caCert)},
		},
	}

	// Only create test attestation, no build attestation
	testPayload := makeArtifactPayload(t, "test", nil, nil)
	testEnvelope := signDSSE(t, "application/vnd.in-toto+json", testPayload, caKey, "k")

	attestDir := t.TempDir()
	treeHash := "missingfrom"
	hashDir := filepath.Join(attestDir, treeHash)
	os.MkdirAll(hashDir, 0755)
	os.WriteFile(filepath.Join(hashDir, "test.intoto.json"), testEnvelope, 0644)
	// build.intoto.json deliberately missing

	v := NewVerifier()
	result, err := v.VerifySteps(pol, attestDir, treeHash)
	if err != nil {
		t.Fatalf("VerifySteps: %v", err)
	}

	if result.Success {
		t.Error("Expected failure: build attestation missing and test depends on it")
	}
}

func TestVerifySteps_MultipleStepsNoChain(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	pol := &aflock.Policy{
		Name:    "multi-independent",
		Version: "1.0",
		Steps: map[string]aflock.Step{
			"lint": {
				Name: "lint",
			},
			"test": {
				Name: "test",
			},
		},
		Roots: map[string]aflock.Root{
			"ca": {Certificate: certToPEM(caCert)},
		},
	}

	lintPayload := makeCollectionPayload(t, "lint", nil)
	lintEnvelope := signDSSE(t, "application/vnd.in-toto+json", lintPayload, caKey, "k")

	testPayload := makeCollectionPayload(t, "test", nil)
	testEnvelope := signDSSE(t, "application/vnd.in-toto+json", testPayload, caKey, "k")

	attestDir := t.TempDir()
	treeHash := "multi"
	hashDir := filepath.Join(attestDir, treeHash)
	os.MkdirAll(hashDir, 0755)
	os.WriteFile(filepath.Join(hashDir, "lint.intoto.json"), lintEnvelope, 0644)
	os.WriteFile(filepath.Join(hashDir, "test.intoto.json"), testEnvelope, 0644)

	v := NewVerifier()
	result, err := v.VerifySteps(pol, attestDir, treeHash)
	if err != nil {
		t.Fatalf("VerifySteps: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success=true for independent steps. Errors: %v", result.Errors)
	}
	if len(result.Steps) != 2 {
		t.Errorf("Expected 2 step results, got %d", len(result.Steps))
	}
}

// ---- verifyDSSESignatures tests ----

func TestVerifyDSSESignatures_ValidSig_NoFunctionaries(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	payload := []byte(`{"test":"data"}`)
	payloadType := "application/vnd.in-toto+json"

	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	paeBytes := append([]byte(pae), payload...)
	hash := sha256.Sum256(paeBytes)

	sig, err := ecdsa.SignASN1(rand.Reader, caKey, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	sigs := []struct {
		KeyID       string `json:"keyid"`
		Sig         string `json:"sig"`
		Certificate string `json:"certificate,omitempty"`
	}{
		{KeyID: "test-key", Sig: base64.StdEncoding.EncodeToString(sig)},
	}

	step := &aflock.Step{
		Name: "test",
	}

	err = verifyDSSESignatures(payloadType, payload, sigs, []*x509.Certificate{caCert}, step)
	if err != nil {
		t.Fatalf("verifyDSSESignatures: %v", err)
	}
}

func TestVerifyDSSESignatures_InvalidSig(t *testing.T) {
	caCert, _ := generateTestCA(t)
	_, wrongKey := generateTestCA(t)

	payload := []byte(`{"test":"data"}`)
	payloadType := "application/vnd.in-toto+json"

	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	paeBytes := append([]byte(pae), payload...)
	hash := sha256.Sum256(paeBytes)

	sig, _ := ecdsa.SignASN1(rand.Reader, wrongKey, hash[:])

	sigs := []struct {
		KeyID       string `json:"keyid"`
		Sig         string `json:"sig"`
		Certificate string `json:"certificate,omitempty"`
	}{
		{KeyID: "wrong-key", Sig: base64.StdEncoding.EncodeToString(sig)},
	}

	step := &aflock.Step{Name: "test"}

	err := verifyDSSESignatures(payloadType, payload, sigs, []*x509.Certificate{caCert}, step)
	if err == nil {
		t.Fatal("Expected error for invalid signature")
	}
	if !strings.Contains(err.Error(), "no valid signature") {
		t.Errorf("Error = %q, expected 'no valid signature'", err.Error())
	}
}

func TestVerifyDSSESignatures_FunctionaryKeyID_Match(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	payload := []byte(`{"test":"functionary"}`)
	payloadType := "application/vnd.in-toto+json"

	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	paeBytes := append([]byte(pae), payload...)
	hash := sha256.Sum256(paeBytes)

	sig, _ := ecdsa.SignASN1(rand.Reader, caKey, hash[:])

	sigs := []struct {
		KeyID       string `json:"keyid"`
		Sig         string `json:"sig"`
		Certificate string `json:"certificate,omitempty"`
	}{
		{KeyID: "spiffe://aflock.ai/agent/test", Sig: base64.StdEncoding.EncodeToString(sig)},
	}

	step := &aflock.Step{
		Name: "test",
		Functionaries: []aflock.StepFunctionary{
			{Type: "publickey", PublicKeyID: "spiffe://aflock.ai/agent/test"},
		},
	}

	err := verifyDSSESignatures(payloadType, payload, sigs, []*x509.Certificate{caCert}, step)
	if err != nil {
		t.Fatalf("verifyDSSESignatures: %v", err)
	}
}

func TestVerifyDSSESignatures_FunctionaryKeyID_Mismatch(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	payload := []byte(`{"test":"functionary-mismatch"}`)
	payloadType := "application/vnd.in-toto+json"

	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	paeBytes := append([]byte(pae), payload...)
	hash := sha256.Sum256(paeBytes)

	sig, _ := ecdsa.SignASN1(rand.Reader, caKey, hash[:])

	sigs := []struct {
		KeyID       string `json:"keyid"`
		Sig         string `json:"sig"`
		Certificate string `json:"certificate,omitempty"`
	}{
		{KeyID: "spiffe://aflock.ai/agent/actual", Sig: base64.StdEncoding.EncodeToString(sig)},
	}

	step := &aflock.Step{
		Name: "test",
		Functionaries: []aflock.StepFunctionary{
			{Type: "publickey", PublicKeyID: "spiffe://aflock.ai/agent/expected"},
		},
	}

	err := verifyDSSESignatures(payloadType, payload, sigs, []*x509.Certificate{caCert}, step)
	if err == nil {
		t.Fatal("Expected error for functionary key ID mismatch")
	}
}

func TestVerifyDSSESignatures_BadBase64Sig(t *testing.T) {
	caCert, _ := generateTestCA(t)

	payload := []byte(`{"test":"bad-b64"}`)
	payloadType := "test/type"

	sigs := []struct {
		KeyID       string `json:"keyid"`
		Sig         string `json:"sig"`
		Certificate string `json:"certificate,omitempty"`
	}{
		{KeyID: "k", Sig: "!!!not-base64!!!"},
	}

	step := &aflock.Step{Name: "test"}

	err := verifyDSSESignatures(payloadType, payload, sigs, []*x509.Certificate{caCert}, step)
	if err == nil {
		t.Fatal("Expected error for bad base64 signature")
	}
}

func TestVerifyDSSESignatures_EmptySigs(t *testing.T) {
	caCert, _ := generateTestCA(t)

	sigs := []struct {
		KeyID       string `json:"keyid"`
		Sig         string `json:"sig"`
		Certificate string `json:"certificate,omitempty"`
	}{}

	step := &aflock.Step{Name: "test"}

	err := verifyDSSESignatures("type", []byte("payload"), sigs, []*x509.Certificate{caCert}, step)
	if err == nil {
		t.Fatal("Expected error for empty signatures")
	}
}

// ---- extractDigests tests ----

func TestExtractDigests_Products(t *testing.T) {
	payload := makeArtifactPayload(t, "build",
		nil,
		map[string]map[string]string{
			"output.bin": {"sha256": "abc123"},
			"output.txt": {"sha256": "def456"},
		},
	)

	envelope := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures":  []map[string]string{},
	}
	data, _ := json.Marshal(envelope)

	tmpFile := filepath.Join(t.TempDir(), "test.json")
	os.WriteFile(tmpFile, data, 0644)

	digests, err := extractDigests(tmpFile, "products")
	if err != nil {
		t.Fatalf("extractDigests: %v", err)
	}

	if len(digests) != 2 {
		t.Fatalf("Expected 2 product digests, got %d", len(digests))
	}
	if digests["output.bin"]["sha256"] != "abc123" {
		t.Errorf("output.bin sha256 = %q, want 'abc123'", digests["output.bin"]["sha256"])
	}
	if digests["output.txt"]["sha256"] != "def456" {
		t.Errorf("output.txt sha256 = %q, want 'def456'", digests["output.txt"]["sha256"])
	}
}

func TestExtractDigests_Materials(t *testing.T) {
	payload := makeArtifactPayload(t, "test",
		map[string]map[string]string{
			"input.bin": {"sha256": "aaa"},
		},
		nil,
	)

	envelope := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures":  []map[string]string{},
	}
	data, _ := json.Marshal(envelope)

	tmpFile := filepath.Join(t.TempDir(), "test.json")
	os.WriteFile(tmpFile, data, 0644)

	digests, err := extractDigests(tmpFile, "materials")
	if err != nil {
		t.Fatalf("extractDigests: %v", err)
	}

	if len(digests) != 1 {
		t.Fatalf("Expected 1 material digest, got %d", len(digests))
	}
	if digests["input.bin"]["sha256"] != "aaa" {
		t.Errorf("input.bin sha256 = %q, want 'aaa'", digests["input.bin"]["sha256"])
	}
}

func TestExtractDigests_NoMatchingType(t *testing.T) {
	payload := makeArtifactPayload(t, "step",
		map[string]map[string]string{"file": {"sha256": "x"}},
		nil,
	)

	envelope := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures":  []map[string]string{},
	}
	data, _ := json.Marshal(envelope)

	tmpFile := filepath.Join(t.TempDir(), "test.json")
	os.WriteFile(tmpFile, data, 0644)

	digests, err := extractDigests(tmpFile, "products")
	if err != nil {
		t.Fatalf("extractDigests: %v", err)
	}
	if len(digests) != 0 {
		t.Errorf("Expected 0 product digests when only materials exist, got %d", len(digests))
	}
}

func TestExtractDigests_NonexistentFile(t *testing.T) {
	_, err := extractDigests("/nonexistent/path.json", "products")
	if err == nil {
		t.Fatal("Expected error for nonexistent file")
	}
}

func TestExtractDigests_MalformedJSON(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(tmpFile, []byte("not json"), 0644)

	_, err := extractDigests(tmpFile, "products")
	if err == nil {
		t.Fatal("Expected error for malformed JSON")
	}
}

// ---- compareArtifacts tests ----

func TestCompareArtifacts_Matching(t *testing.T) {
	fromPayload := makeArtifactPayload(t, "source",
		nil,
		map[string]map[string]string{"file.bin": {"sha256": "match"}},
	)
	fromEnv := map[string]interface{}{
		"payload":    base64.StdEncoding.EncodeToString(fromPayload),
		"signatures": []map[string]string{},
	}
	fromData, _ := json.Marshal(fromEnv)
	fromFile := filepath.Join(t.TempDir(), "from.json")
	os.WriteFile(fromFile, fromData, 0644)

	toPayload := makeArtifactPayload(t, "target",
		map[string]map[string]string{"file.bin": {"sha256": "match"}},
		nil,
	)
	toEnv := map[string]interface{}{
		"payload":    base64.StdEncoding.EncodeToString(toPayload),
		"signatures": []map[string]string{},
	}
	toData, _ := json.Marshal(toEnv)
	toFile := filepath.Join(t.TempDir(), "to.json")
	os.WriteFile(toFile, toData, 0644)

	v := NewVerifier()
	err := v.compareArtifacts(fromFile, toFile)
	if err != nil {
		t.Errorf("compareArtifacts should succeed for matching hashes: %v", err)
	}
}

func TestCompareArtifacts_Mismatched(t *testing.T) {
	fromPayload := makeArtifactPayload(t, "source",
		nil,
		map[string]map[string]string{"file.bin": {"sha256": "hashA"}},
	)
	fromEnv := map[string]interface{}{
		"payload":    base64.StdEncoding.EncodeToString(fromPayload),
		"signatures": []map[string]string{},
	}
	fromData, _ := json.Marshal(fromEnv)
	fromFile := filepath.Join(t.TempDir(), "from.json")
	os.WriteFile(fromFile, fromData, 0644)

	toPayload := makeArtifactPayload(t, "target",
		map[string]map[string]string{"file.bin": {"sha256": "hashB"}},
		nil,
	)
	toEnv := map[string]interface{}{
		"payload":    base64.StdEncoding.EncodeToString(toPayload),
		"signatures": []map[string]string{},
	}
	toData, _ := json.Marshal(toEnv)
	toFile := filepath.Join(t.TempDir(), "to.json")
	os.WriteFile(toFile, toData, 0644)

	v := NewVerifier()
	err := v.compareArtifacts(fromFile, toFile)
	if err == nil {
		t.Fatal("Expected error for mismatched artifact hashes")
	}
	if !strings.Contains(err.Error(), "products not found in materials") {
		t.Errorf("Error = %q, expected 'products not found in materials'", err.Error())
	}
}

func TestCompareArtifacts_NoProducts(t *testing.T) {
	fromPayload := makeArtifactPayload(t, "source", nil, nil)
	fromEnv := map[string]interface{}{
		"payload":    base64.StdEncoding.EncodeToString(fromPayload),
		"signatures": []map[string]string{},
	}
	fromData, _ := json.Marshal(fromEnv)
	fromFile := filepath.Join(t.TempDir(), "from.json")
	os.WriteFile(fromFile, fromData, 0644)

	toPayload := makeArtifactPayload(t, "target", nil, nil)
	toEnv := map[string]interface{}{
		"payload":    base64.StdEncoding.EncodeToString(toPayload),
		"signatures": []map[string]string{},
	}
	toData, _ := json.Marshal(toEnv)
	toFile := filepath.Join(t.TempDir(), "to.json")
	os.WriteFile(toFile, toData, 0644)

	v := NewVerifier()
	err := v.compareArtifacts(fromFile, toFile)
	if err != nil {
		t.Errorf("compareArtifacts should succeed when source has no products: %v", err)
	}
}

func TestCompareArtifacts_MissingProductName(t *testing.T) {
	// Source produces "a.bin", target materials have "b.bin" (different name)
	fromPayload := makeArtifactPayload(t, "source",
		nil,
		map[string]map[string]string{"a.bin": {"sha256": "hash"}},
	)
	fromEnv := map[string]interface{}{
		"payload":    base64.StdEncoding.EncodeToString(fromPayload),
		"signatures": []map[string]string{},
	}
	fromData, _ := json.Marshal(fromEnv)
	fromFile := filepath.Join(t.TempDir(), "from.json")
	os.WriteFile(fromFile, fromData, 0644)

	toPayload := makeArtifactPayload(t, "target",
		map[string]map[string]string{"b.bin": {"sha256": "hash"}},
		nil,
	)
	toEnv := map[string]interface{}{
		"payload":    base64.StdEncoding.EncodeToString(toPayload),
		"signatures": []map[string]string{},
	}
	toData, _ := json.Marshal(toEnv)
	toFile := filepath.Join(t.TempDir(), "to.json")
	os.WriteFile(toFile, toData, 0644)

	v := NewVerifier()
	err := v.compareArtifacts(fromFile, toFile)
	if err == nil {
		t.Fatal("Expected error when product name not found in materials")
	}
}

// ---- Integration test: full VerifySession ----

func TestVerifySession_FullIntegration(t *testing.T) {
	tmpDir := t.TempDir()

	maxCost := &aflock.Limit{Value: 100.0, Enforcement: "post-hoc"}
	sessionState := &aflock.SessionState{
		SessionID: "sess-full",
		StartedAt: time.Now().Add(-5 * time.Minute),
		Policy: &aflock.Policy{
			Name:                 "full-policy",
			Version:              "2.0",
			RequiredAttestations: []string{"session-summary"},
			Limits: &aflock.LimitsPolicy{
				MaxSpendUSD: maxCost,
			},
		},
		Metrics: &aflock.SessionMetrics{
			Turns:     8,
			ToolCalls: 15,
			TokensIn:  5000,
			TokensOut: 2500,
			CostUSD:   0.50,
			Tools:     map[string]int{"Read": 8, "Bash": 5, "Write": 2},
		},
		Materials: []aflock.MaterialClassification{
			{Label: "internal", Source: "Read:/etc/config", Timestamp: time.Now()},
		},
		Actions: []aflock.ActionRecord{
			{Timestamp: time.Now(), ToolName: "Read", ToolUseID: "tu_1", Decision: "allow"},
			{Timestamp: time.Now(), ToolName: "Bash", ToolUseID: "tu_2", Decision: "allow"},
			{Timestamp: time.Now(), ToolName: "Write", ToolUseID: "tu_3", Decision: "deny", Reason: "File not in allow list"},
		},
	}

	writeSessionState(t, tmpDir, "sess-full", sessionState)

	attestDir := filepath.Join(tmpDir, "sess-full", "attestations")
	os.MkdirAll(attestDir, 0755)
	os.WriteFile(filepath.Join(attestDir, "session-summary.json"), []byte("{}"), 0644)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-full")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success=true. Errors: %v", result.Errors)
	}

	if result.Metrics == nil {
		t.Fatal("Expected metrics to be populated")
	}
	if result.Metrics.TotalCostUSD != 0.50 {
		t.Errorf("TotalCostUSD = %f, want 0.50", result.Metrics.TotalCostUSD)
	}
	if result.Metrics.TotalTokensIn != 5000 {
		t.Errorf("TotalTokensIn = %d, want 5000", result.Metrics.TotalTokensIn)
	}

	if len(result.Warnings) != 1 {
		t.Errorf("Expected 1 warning, got %d: %v", len(result.Warnings), result.Warnings)
	}
}

func TestVerifySession_EmptySession(t *testing.T) {
	tmpDir := t.TempDir()

	sessionState := &aflock.SessionState{
		SessionID: "sess-empty",
		StartedAt: time.Now(),
		Policy: &aflock.Policy{
			Name:    "minimal",
			Version: "1.0",
		},
		Metrics: &aflock.SessionMetrics{
			Tools: map[string]int{},
		},
		Actions: []aflock.ActionRecord{},
	}

	writeSessionState(t, tmpDir, "sess-empty", sessionState)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-empty")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success=true for empty session. Errors: %v", result.Errors)
	}
	if len(result.Warnings) != 0 {
		t.Errorf("Expected no warnings for empty session, got: %v", result.Warnings)
	}

	foundActions := false
	for _, check := range result.Checks {
		if check.Name == "actions" {
			foundActions = true
			if !strings.Contains(check.Message, "0 total actions") {
				t.Errorf("actions message = %q, expected '0 total actions'", check.Message)
			}
		}
	}
	if !foundActions {
		t.Error("Expected 'actions' check")
	}
}

func TestVerifySession_NilMetrics(t *testing.T) {
	tmpDir := t.TempDir()

	sessionState := &aflock.SessionState{
		SessionID: "sess-nometrics",
		StartedAt: time.Now(),
		Policy: &aflock.Policy{
			Name:    "minimal",
			Version: "1.0",
		},
		Metrics: nil, // intentionally nil
	}

	writeSessionState(t, tmpDir, "sess-nometrics", sessionState)

	v := newTestVerifier(tmpDir)
	result, err := v.VerifySession("sess-nometrics")
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	if result.Metrics != nil {
		t.Error("Expected nil metrics in result when session has nil metrics")
	}
}

// ---- Result and StepsResult struct tests ----

func TestResult_Defaults(t *testing.T) {
	r := &Result{
		Success:    true,
		SessionID:  "test",
		PolicyName: "pol",
		VerifiedAt: time.Now(),
	}

	if !r.Success {
		t.Error("Expected success=true")
	}
	if r.Metrics != nil {
		t.Error("Expected nil metrics by default")
	}
	if len(r.Errors) != 0 {
		t.Error("Expected no errors by default")
	}
	if len(r.Warnings) != 0 {
		t.Error("Expected no warnings by default")
	}
	if len(r.Checks) != 0 {
		t.Error("Expected no checks by default")
	}
}

func TestStepsResult_Defaults(t *testing.T) {
	r := &StepsResult{
		Success:    true,
		TreeHash:   "abc",
		PolicyName: "pol",
		Steps:      make(map[string]StepResult),
	}

	if !r.Success {
		t.Error("Expected success=true")
	}
	if len(r.Steps) != 0 {
		t.Error("Expected empty steps map")
	}
	if len(r.Errors) != 0 {
		t.Error("Expected no errors")
	}
}

func TestStepResult_Defaults(t *testing.T) {
	r := StepResult{
		Name:           "test",
		Found:          true,
		SignatureValid: true,
		ArtifactsMatch: true,
	}

	if r.Name != "test" {
		t.Errorf("Name = %q, want 'test'", r.Name)
	}
	if !r.Found {
		t.Error("Expected Found=true")
	}
	if !r.SignatureValid {
		t.Error("Expected SignatureValid=true")
	}
	if !r.ArtifactsMatch {
		t.Error("Expected ArtifactsMatch=true")
	}
	if r.AttestationPath != "" {
		t.Error("Expected empty AttestationPath")
	}
}

func TestSessionInfo_Struct(t *testing.T) {
	info := SessionInfo{
		SessionID:  "sess-1",
		PolicyName: "my-policy",
		StartedAt:  time.Now(),
		Turns:      5,
		ToolCalls:  10,
	}

	if info.SessionID != "sess-1" {
		t.Errorf("SessionID = %q", info.SessionID)
	}
	if info.Turns != 5 {
		t.Errorf("Turns = %d", info.Turns)
	}
}

func TestMetricsSummary_Struct(t *testing.T) {
	ms := MetricsSummary{
		TotalTurns:     10,
		TotalToolCalls: 25,
		TotalTokensIn:  5000,
		TotalTokensOut: 2500,
		TotalCostUSD:   1.23,
		Duration:       "5m30s",
	}

	if ms.TotalTurns != 10 {
		t.Errorf("TotalTurns = %d", ms.TotalTurns)
	}
	if ms.Duration != "5m30s" {
		t.Errorf("Duration = %q", ms.Duration)
	}
}

func TestCheckResult_Struct(t *testing.T) {
	cr := CheckResult{
		Name:    "limits:maxTurns",
		Passed:  false,
		Message: "exceeded",
	}

	if cr.Passed {
		t.Error("Expected Passed=false")
	}
	if cr.Message != "exceeded" {
		t.Errorf("Message = %q", cr.Message)
	}
}

// ---- Embedded certificate verification tests ----

// TestVerifyDSSESignatures_EmbeddedCert_ValidChain verifies that a signature
// with an embedded leaf cert that chains to a trusted root passes verification.
func TestVerifyDSSESignatures_EmbeddedCert_ValidChain(t *testing.T) {
	// Create a trusted CA and a leaf cert signed by that CA.
	caCert, caKey := generateTestCA(t)

	// Generate a leaf cert with ExtKeyUsageAny so that x509.Verify (which
	// defaults to checking for ExtKeyUsageServerAuth) accepts it.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject: pkix.Name{
			CommonName:   "leaf-signer",
			Organization: []string{"Aflock Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	payload := []byte(`{"test":"embedded-cert-valid"}`)
	payloadType := "application/vnd.in-toto+json"

	// Build PAE and sign with the leaf key.
	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	paeBytes := append([]byte(pae), payload...)
	hash := sha256.Sum256(paeBytes)

	sig, err := ecdsa.SignASN1(rand.Reader, leafKey, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Embed the leaf cert PEM in the signature's Certificate field.
	sigs := []struct {
		KeyID       string `json:"keyid"`
		Sig         string `json:"sig"`
		Certificate string `json:"certificate,omitempty"`
	}{
		{
			KeyID:       "leaf-key",
			Sig:         base64.StdEncoding.EncodeToString(sig),
			Certificate: certToPEM(leafCert),
		},
	}

	// The trusted pool contains only the CA. The leaf is embedded in the signature.
	step := &aflock.Step{Name: "test"}
	err = verifyDSSESignatures(payloadType, payload, sigs, []*x509.Certificate{caCert}, step)
	if err != nil {
		t.Fatalf("expected valid embedded cert chain to pass, got: %v", err)
	}
}

// TestVerifyDSSESignatures_EmbeddedCert_SelfSignedCA_Rejected verifies that an
// attacker who crafts a self-signed CA cert (IsCA=true), embeds it in the
// signature's Certificate field, and signs with their own key is REJECTED
// because the cert does not chain to any trusted root in the pool.
func TestVerifyDSSESignatures_EmbeddedCert_SelfSignedCA_Rejected(t *testing.T) {
	// Create the legitimate trusted CA (this is the only root in the pool).
	trustedCACert, _ := generateTestCA(t)

	// Create an attacker-controlled self-signed CA cert.
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}

	attackerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject: pkix.Name{
			CommonName:   "Attacker CA",
			Organization: []string{"Evil Corp"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	attackerCertDER, err := x509.CreateCertificate(rand.Reader, attackerTemplate, attackerTemplate, &attackerKey.PublicKey, attackerKey)
	if err != nil {
		t.Fatalf("create attacker CA cert: %v", err)
	}
	attackerCert, err := x509.ParseCertificate(attackerCertDER)
	if err != nil {
		t.Fatalf("parse attacker CA cert: %v", err)
	}

	payload := []byte(`{"test":"self-signed-ca-attack"}`)
	payloadType := "application/vnd.in-toto+json"

	// Sign with the attacker's key.
	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	paeBytes := append([]byte(pae), payload...)
	hash := sha256.Sum256(paeBytes)

	sig, err := ecdsa.SignASN1(rand.Reader, attackerKey, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Embed the attacker's self-signed CA cert in the signature.
	sigs := []struct {
		KeyID       string `json:"keyid"`
		Sig         string `json:"sig"`
		Certificate string `json:"certificate,omitempty"`
	}{
		{
			KeyID:       "attacker-key",
			Sig:         base64.StdEncoding.EncodeToString(sig),
			Certificate: certToPEM(attackerCert),
		},
	}

	// Trusted pool only contains the legitimate CA, NOT the attacker's cert.
	step := &aflock.Step{Name: "test"}
	err = verifyDSSESignatures(payloadType, payload, sigs, []*x509.Certificate{trustedCACert}, step)
	if err == nil {
		t.Fatal("SECURITY: self-signed CA cert embedded in signature was accepted; it MUST be rejected")
	}
	if !strings.Contains(err.Error(), "no valid signature") {
		t.Errorf("Error = %q, expected to contain 'no valid signature'", err.Error())
	}
}

// TestVerifyDSSESignatures_EmbeddedCert_UntrustedLeaf_Rejected verifies that a
// signature with an embedded leaf cert that does NOT chain to the trusted root
// pool is rejected.
func TestVerifyDSSESignatures_EmbeddedCert_UntrustedLeaf_Rejected(t *testing.T) {
	// Create the legitimate trusted CA.
	trustedCACert, _ := generateTestCA(t)

	// Create a separate, untrusted CA and issue a leaf from it.
	untrustedCACert, untrustedCAKey := generateTestCA(t)
	_ = untrustedCACert // not added to the trusted pool
	leafCert, leafKey := generateTestLeafCert(t, untrustedCACert, untrustedCAKey, "untrusted-leaf")

	payload := []byte(`{"test":"untrusted-leaf"}`)
	payloadType := "application/vnd.in-toto+json"

	// Sign with the leaf key from the untrusted CA.
	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	paeBytes := append([]byte(pae), payload...)
	hash := sha256.Sum256(paeBytes)

	sig, err := ecdsa.SignASN1(rand.Reader, leafKey, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Embed the leaf cert in the signature.
	sigs := []struct {
		KeyID       string `json:"keyid"`
		Sig         string `json:"sig"`
		Certificate string `json:"certificate,omitempty"`
	}{
		{
			KeyID:       "untrusted-leaf-key",
			Sig:         base64.StdEncoding.EncodeToString(sig),
			Certificate: certToPEM(leafCert),
		},
	}

	// Trusted pool contains only the legitimate CA, not the one that issued this leaf.
	step := &aflock.Step{Name: "test"}
	err = verifyDSSESignatures(payloadType, payload, sigs, []*x509.Certificate{trustedCACert}, step)
	if err == nil {
		t.Fatal("Expected embedded leaf cert from untrusted CA to be rejected")
	}
	if !strings.Contains(err.Error(), "no valid signature") {
		t.Errorf("Error = %q, expected to contain 'no valid signature'", err.Error())
	}
}
