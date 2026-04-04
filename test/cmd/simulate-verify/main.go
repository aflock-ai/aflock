// simulate-verify generates signed test attestations with identity data
// and runs Phase 2 identity verification against a policy.
//
// Usage:
//
//	go run ./test/cmd/simulate-verify/
//
// This creates a temp directory with:
//   - A self-signed CA certificate
//   - A policy with steps + identity constraints + roots
//   - Signed DSSE attestation envelopes containing agent identity
//
// Then runs aflock verify to demonstrate Phase 2 identity verification.
package main

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
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Create temp workspace
	tmpDir, err := os.MkdirTemp("", "aflock-simulate-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	fmt.Printf("Working directory: %s\n\n", tmpDir)

	// Step 1: Generate CA key and certificate
	fmt.Println("=== Step 1: Generate test CA ===")
	caKey, caCert, caPEM, err := generateCA()
	if err != nil {
		return fmt.Errorf("generate CA: %w", err)
	}
	fmt.Printf("  CA CN: %s\n", caCert.Subject.CommonName)

	// Step 2: Get current git tree hash (or use a fake one)
	treeHash := getTreeHash()
	fmt.Printf("  Tree hash: %s\n\n", treeHash)

	// Step 3: Create attestation directory
	attestDir := filepath.Join(tmpDir, "attestations")
	stepDir := filepath.Join(attestDir, treeHash)
	if err := os.MkdirAll(stepDir, 0755); err != nil {
		return err
	}

	// ============================================================
	// Scenario 1: Identity matches policy — should PASS
	// ============================================================
	fmt.Println("=== Scenario 1: Identity MATCHES policy (expect PASS) ===")

	policy1 := createPolicy("pass-test", caPEM, map[string]any{
		"allowedModels":       []string{"claude-opus-*", "claude-sonnet-*"},
		"allowedEnvironments": []string{"local", "container:ghcr.io/*"},
	})
	policyPath1 := filepath.Join(tmpDir, "policy-pass.aflock")
	if err := writeJSON(policyPath1, policy1); err != nil {
		return err
	}

	// Create signed attestation with matching identity
	if err := createSignedAttestation(stepDir, "build", caKey, caCert,
		"claude-opus-4-5-20251101", "local"); err != nil {
		return err
	}
	fmt.Printf("  Created attestation: build.intoto.json\n")
	fmt.Printf("  Agent model: claude-opus-4-5-20251101\n")
	fmt.Printf("  Agent environment: local\n")

	runVerify(policyPath1, attestDir, treeHash)

	// ============================================================
	// Scenario 2: Identity does NOT match — should FAIL
	// ============================================================
	fmt.Println("\n=== Scenario 2: Identity MISMATCH (expect FAIL) ===")

	policy2 := createPolicy("fail-test", caPEM, map[string]any{
		"allowedModels":       []string{"claude-opus-*"},
		"allowedEnvironments": []string{"container:ghcr.io/org/*"},
	})
	policyPath2 := filepath.Join(tmpDir, "policy-fail.aflock")
	if err := writeJSON(policyPath2, policy2); err != nil {
		return err
	}

	// Reuse the same attestation — identity is "claude-opus-*" + "local"
	// Policy requires "container:ghcr.io/org/*" — environment will FAIL
	fmt.Printf("  Agent model: claude-opus-4-5-20251101 (matches claude-opus-*)\n")
	fmt.Printf("  Agent environment: local (does NOT match container:ghcr.io/org/*)\n")

	runVerify(policyPath2, attestDir, treeHash)

	// ============================================================
	// Scenario 3: Wrong model — should FAIL
	// ============================================================
	fmt.Println("\n=== Scenario 3: Wrong MODEL (expect FAIL) ===")

	// Create attestation with haiku model
	stepDir3 := filepath.Join(tmpDir, "attestations3", treeHash)
	if err := os.MkdirAll(stepDir3, 0755); err != nil {
		return err
	}
	if err := createSignedAttestation(stepDir3, "build", caKey, caCert,
		"claude-haiku-4-5-20251001", "local"); err != nil {
		return err
	}

	policy3 := createPolicy("model-fail-test", caPEM, map[string]any{
		"allowedModels": []string{"claude-opus-*", "claude-sonnet-*"},
	})
	policyPath3 := filepath.Join(tmpDir, "policy-model-fail.aflock")
	if err := writeJSON(policyPath3, policy3); err != nil {
		return err
	}

	fmt.Printf("  Agent model: claude-haiku-4-5-20251001 (does NOT match claude-opus-* or claude-sonnet-*)\n")

	runVerify(policyPath3, filepath.Join(tmpDir, "attestations3"), treeHash)

	return nil
}

func generateCA() (*ecdsa.PrivateKey, *x509.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Aflock Test CA",
			Organization: []string{"Aflock Simulation"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, "", err
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return key, cert, string(pemBlock), nil
}

func getTreeHash() string {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "simulation-tree-hash-abc123"
	}
	hash := string(out)
	if len(hash) > 40 {
		hash = hash[:40]
	}
	return hash
}

func createPolicy(name, caPEM string, identity map[string]any) map[string]any {
	return map[string]any{
		"version": "1.0",
		"name":    name,
		"roots": map[string]any{
			"test-ca": map[string]any{
				"certificate": caPEM,
			},
		},
		"identity": identity,
		"steps": map[string]any{
			"build": map[string]any{
				"name": "build",
				"functionaries": []map[string]any{
					{"type": "publickey", "publickeyid": "test-ca"},
				},
				"attestations": []map[string]any{
					{"type": "https://aflock.ai/attestations/action/v0.1"},
				},
			},
		},
	}
}

func createSignedAttestation(dir, stepName string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, model, environment string) error {
	// Build action attestation with agent identity
	action := map[string]any{
		"action":    "tool_call",
		"sessionId": "sim-session-001",
		"toolName":  "Read",
		"toolUseId": "tu_sim_001",
		"decision":  "allow",
		"timestamp": time.Now().Format(time.RFC3339),
		"agentIdentity": map[string]any{
			"model":        model,
			"modelVersion": "4.5.20251101",
			"environment":  environment,
			"identityHash": "sim-hash-abc123def456",
		},
	}

	// Wrap in collection predicate
	predicate := map[string]any{
		"name": stepName,
		"attestations": []map[string]any{
			{
				"type":        "https://aflock.ai/attestations/action/v0.1",
				"attestation": action,
			},
		},
	}

	// Wrap in in-toto Statement
	statement := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://aflock.ai/attestations/collection/v0.1",
		"predicate":     predicate,
		"subject":       []map[string]any{},
	}

	payload, err := json.Marshal(statement)
	if err != nil {
		return err
	}

	// Sign with DSSE
	payloadType := "application/vnd.in-toto+json"
	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	paeBytes := append([]byte(pae), payload...)
	hash := sha256.Sum256(paeBytes)

	sig, err := ecdsa.SignASN1(rand.Reader, caKey, hash[:])
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	// Build DSSE envelope with embedded certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	envelope := map[string]any{
		"payloadType": payloadType,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures": []map[string]string{
			{
				"keyid":       "test-ca",
				"sig":         base64.StdEncoding.EncodeToString(sig),
				"certificate": string(certPEM),
			},
		},
	}

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, stepName+".intoto.json"), data, 0644)
}

func runVerify(policyPath, attestDir, treeHash string) {
	// Try to find the aflock binary
	binary := "./bin/aflock"
	if _, err := os.Stat(binary); err != nil {
		binary = "aflock"
	}

	cmd := exec.Command(binary, "verify",
		"--policy", policyPath,
		"--attestations", attestDir,
		"--tree-hash", treeHash)
	cmd.Dir = "/Users/rahulxf/work-dir/aflock"
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("  Exit code: non-zero (verification failed)\n")
	} else {
		fmt.Printf("  Exit code: 0 (verification passed)\n")
	}
	fmt.Printf("  Output:\n")

	// Pretty print the JSON
	var parsed map[string]any
	if json.Unmarshal(out, &parsed) == nil {
		pretty, _ := json.MarshalIndent(parsed, "    ", "  ")
		fmt.Printf("    %s\n", string(pretty))
	} else {
		fmt.Printf("    %s\n", string(out))
	}
}

func writeJSON(path string, data any) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}
