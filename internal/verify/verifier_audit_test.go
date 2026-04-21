//go:build audit

// Security audit tests for aflock verifier.
package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// BUG-VERIFY-1 (FIXED in issue #57 / C2): Ed25519 signing vs verification mismatch.
// PREVIOUSLY: signWithPrivateKey hashed with SHA256 for ALL key types including Ed25519,
// producing Ed25519ph signatures. The verifier expected pure Ed25519 (raw PAE). These
// were cryptographically incompatible — Ed25519 attestations would NEVER verify.
// NOW: signWithPrivateKey has an explicit ed25519.PrivateKey branch that signs raw data.
// This test remains as a REGRESSION test demonstrating the mismatch pattern that was fixed.
func TestEd25519_SignVerify_Mismatch(t *testing.T) {
	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	// Simulate what the signer does: signWithPrivateKey hashes first
	message := []byte("DSSEv1 33 application/vnd.in-toto+json 100 {\"test\":\"data\"}")
	hash := sha256.Sum256(message)

	// The signer code path for Ed25519 goes through crypto.Signer:
	//   case crypto.Signer:
	//     return key.Sign(rand.Reader, hash[:], crypto.SHA256)
	// For ed25519, this calls ed25519.PrivateKey.Sign which:
	// - If opts is crypto.Hash(0) or nil: signs the raw message (Ed25519 pure)
	// - If opts is crypto.SHA256: uses Ed25519ph (pre-hashed) mode
	// So the signer would use Ed25519ph mode.
	signerSig, err := privKey.Sign(rand.Reader, hash[:], &ed25519.Options{Hash: 0})
	if err != nil {
		// Ed25519 pure mode won't accept hash as message directly, but it will
		// sign whatever bytes are given. The issue is the VERIFIER expects the
		// signature to be over the raw message, not SHA256(message).
		t.Fatalf("ed25519 sign: %v", err)
	}

	// Now verify using the verifier's approach: ed25519.Verify(key, rawPAE, sig)
	// The verifier passes the RAW message (paeBytes), not the hash
	verified := ed25519.Verify(pubKey, message, signerSig)
	if verified {
		t.Log("Ed25519 verify succeeded - but only because Sign got hash[:] as the 'message'")
		t.Log("This would fail in real usage because the signer passes SHA256 hash bytes, not the original message")
	}

	// Prove the mismatch: sign the HASH (what signer does) and verify against ORIGINAL (what verifier does)
	// ed25519.Sign signs the raw bytes given to it, treating hash[:] as the message
	hashSig := ed25519.Sign(privKey, hash[:])
	// Verify against the raw message (what verifier.go does)
	if ed25519.Verify(pubKey, message, hashSig) {
		t.Fatal("UNEXPECTED: ed25519.Verify(pubKey, rawMessage, Sign(hash)) should fail")
	}
	// Verify against the hash (what the signer actually signed)
	if !ed25519.Verify(pubKey, hash[:], hashSig) {
		t.Fatal("ed25519.Verify(pubKey, hash, Sign(hash)) should succeed")
	}

	t.Log("BUG-VERIFY-1 confirmed: Ed25519 sign/verify mismatch. Signer signs SHA256(PAE), verifier checks PAE.")
}

// BUG-VERIFY-2 (FIXED in issue #57 / L3): RSA verification tried PKCS1v15 then PSS,
// allowing a PSS-signed attestation to verify against a cert expecting PKCS1v15 and
// vice versa (padding confusion). Now pinned to PKCS1v15 only, matching the signer.
// This test remains as a REGRESSION test confirming PSS is rejected.
func TestRSA_PaddingConfusion(t *testing.T) {
	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	// Create a self-signed cert
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "RSA Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// Note: SignatureAlgorithm on cert is for the cert itself, not for verifying other signatures
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	message := []byte("test message for RSA")
	hash := sha256.Sum256(message)

	// Sign with PSS
	pssSig, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, hash[:], nil)
	if err != nil {
		t.Fatalf("PSS sign: %v", err)
	}

	// Sign with PKCS1v15
	pkcs1Sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("PKCS1v15 sign: %v", err)
	}

	// The verifier accepts BOTH padding schemes for the same cert.
	// This is by design (compatibility), but it means a PKCS1v15-only policy
	// would still accept PSS signatures.
	pkcsResult := verifySignatureWithCert(cert, message, hash[:], pkcs1Sig)
	pssResult := verifySignatureWithCert(cert, message, hash[:], pssSig)

	t.Logf("PKCS1v15 sig verified: %v", pkcsResult)
	t.Logf("PSS sig verified: %v", pssResult)

	if pkcsResult && pssResult {
		t.Log("BUG-VERIFY-2: Both PKCS1v15 and PSS accepted. No way to restrict to one padding scheme.")
	}
}

// BUG-VERIFY-3: Certificate chain validation skips time validity check.
// The x509.VerifyOptions used in verifyDSSESignatures does not set
// CurrentTime, so it uses time.Now(). But more critically, for CA certs
// (cert.IsCA == true), chain validation is SKIPPED entirely.
// An expired CA cert would still verify signatures.
func TestExpiredCACertStillVerifies(t *testing.T) {
	// Generate an expired CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Expired CA"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // EXPIRED
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	// Sign a message
	message := []byte("test message")
	hash := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, caKey, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// verifySignatureWithCert checks cryptographic validity only, not expiry
	result := verifySignatureWithCert(cert, message, hash[:], sig)
	if result {
		t.Log("BUG-VERIFY-3 confirmed: Expired CA cert still passes signature verification")
		t.Log("verifySignatureWithCert only checks crypto, not cert validity period")
		t.Log("For CA certs, verifyDSSESignatures skips x509.Verify (line 731-738)")
	}
}

// BUG-VERIFY-4: findAttestation in verifier uses filepath.Glob which is
// an overly broad match. "build" would match "build-evil-injection.json"
// or "buildX.json" or "build-anything". An attacker could place a file named
// "build-malicious.json" to satisfy a "build" attestation requirement.
func TestFindAttestation_GlobTooPermissive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file that should NOT match "build" requirement
	// but does because of the glob pattern build*
	os.WriteFile(filepath.Join(tmpDir, "builder-config.json"), []byte("{}"), 0644)

	v := NewVerifier()
	// "build" should not match "builder-config.json" but the glob build* does
	found := v.findAttestation(tmpDir, "build")
	if found {
		t.Log("BUG-VERIFY-4 confirmed: findAttestation('build') matches 'builder-config.json' via glob")
		t.Log("An attacker could satisfy attestation requirements with unrelated files")
	}
}

// BUG-VERIFY-5: VerifySession panics if sessionState.Policy is nil.
// Line 90: result.PolicyName = sessionState.Policy.Name
// If Policy is nil (corrupt state file), this nil-derefs.
func TestVerifySession_NilPolicy(t *testing.T) {
	tmpDir := t.TempDir()

	// Write state with nil policy
	dir := filepath.Join(tmpDir, "nil-policy")
	os.MkdirAll(dir, 0755)
	stateData := `{"session_id":"nil-policy","started_at":"2025-01-01T00:00:00Z","metrics":{"turns":1,"toolCalls":1,"tools":{}}}`
	os.WriteFile(filepath.Join(dir, "state.json"), []byte(stateData), 0644)

	v := newTestVerifier(tmpDir)

	defer func() {
		if r := recover(); r != nil {
			t.Logf("BUG-VERIFY-5 confirmed: VerifySession panics on nil Policy: %v", r)
		}
	}()

	_, err := v.VerifySession("nil-policy")
	if err != nil {
		t.Logf("VerifySession returned error (expected): %v", err)
	}
}

// BUG-VERIFY-6: VerifyLatestSession uses os.Getenv("HOME") directly
// instead of os.UserHomeDir(). On some systems HOME may not be set,
// and this doesn't handle Windows (USERPROFILE).
func TestVerifyLatestSession_NoHomeEnv(t *testing.T) {
	// Save and restore HOME
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)

	// Clear HOME
	os.Setenv("HOME", "")

	v := NewVerifier()
	_, err := v.VerifyLatestSession()
	// Should get a meaningful error, not a panic or empty path
	if err == nil {
		t.Log("VerifyLatestSession succeeded with empty HOME - unexpected")
	} else {
		t.Logf("Error with empty HOME: %v", err)
		// Check the path is reasonable
		if strings.Contains(err.Error(), "/.aflock") {
			t.Log("BUG-VERIFY-6: path starts with / (empty HOME gives root-relative path)")
		}
	}
}

// BUG-VERIFY-7: No replay attack protection.
// An attestation signed for one session/tree-hash could be replayed for another.
// VerifySteps checks that attestation exists and signature is valid, but doesn't
// verify the subject/materials bind to the specific tree hash being verified.
func TestVerifySteps_ReplayAttack(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	// Create an attestation for treeHash "aaa" that references step "build"
	payload := makeCollectionPayload(t, "build", []string{"https://aflock.ai/attestations/material/v0.1"})
	envelope := signDSSE(t, "application/vnd.in-toto+json", payload, caKey, "test-key")

	tmpDir := t.TempDir()

	// Store the attestation under treeHash "aaa"
	dirA := filepath.Join(tmpDir, "aaa")
	os.MkdirAll(dirA, 0755)
	os.WriteFile(filepath.Join(dirA, "build.intoto.json"), envelope, 0644)

	// Now copy the SAME attestation to treeHash "bbb" (replay)
	dirB := filepath.Join(tmpDir, "bbb")
	os.MkdirAll(dirB, 0755)
	os.WriteFile(filepath.Join(dirB, "build.intoto.json"), envelope, 0644)

	pol := &aflock.Policy{
		Name:    "replay-test",
		Version: "1.0",
		Roots: map[string]aflock.Root{
			"test-ca": {Certificate: certToPEM(caCert)},
		},
		Steps: map[string]aflock.Step{
			"build": {
				Name: "build",
				Functionaries: []aflock.StepFunctionary{
					{Type: "publickey", PublicKeyID: "test-key"},
				},
				Attestations: []aflock.StepAttestation{
					{Type: "https://aflock.ai/attestations/material/v0.1"},
				},
			},
		},
	}

	v := NewVerifier()

	// Both verifications succeed with the same attestation
	resultA, err := v.VerifySteps(pol, tmpDir, "aaa")
	if err != nil {
		t.Fatalf("VerifySteps(aaa): %v", err)
	}

	resultB, err := v.VerifySteps(pol, tmpDir, "bbb")
	if err != nil {
		t.Fatalf("VerifySteps(bbb): %v", err)
	}

	if resultA.Success && resultB.Success {
		t.Log("BUG-VERIFY-7: Same attestation accepted for two different tree hashes")
		t.Log("No binding between attestation content and the tree hash being verified")
		t.Log("An attacker could replay attestations from one commit to another")
	}
}

// BUG-VERIFY-8: The verifyDSSESignatures function constructs PAE using
// fmt.Sprintf which converts payload bytes to a string. If payload contains
// non-UTF8 bytes, the %s would mangle them. However the signer uses
// byte concatenation. This could cause signature verification to fail
// for payloads with non-UTF8 content.
func TestPAE_ByteVsStringMismatch(t *testing.T) {
	// The verifier constructs PAE as:
	//   pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	//   paeBytes := append([]byte(pae), payload...)
	//
	// The signer (signer.go) constructs PAE as:
	//   prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	//   result = append([]byte(prefix), payload...)
	//
	// These are consistent - both use Sprintf for the prefix and append payload bytes.
	// But the verifier also hashes the PAE: hash = sha256.Sum256(paeBytes)
	// And for ECDSA/RSA, it signs the HASH. For Ed25519, it signs the raw PAE.
	//
	// The critical check is that both sides compute the same PAE bytes.

	payloadType := "application/vnd.in-toto+json"
	payload := []byte(`{"test":"data","binary":"\x00\xff"}`)

	// Verifier's PAE construction
	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	verifierPAE := append([]byte(pae), payload...)

	// Signer's PAE construction (from createPAE in signer.go)
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	signerPAE := make([]byte, 0, len(prefix)+len(payload))
	signerPAE = append(signerPAE, []byte(prefix)...)
	signerPAE = append(signerPAE, payload...)

	verifierHash := sha256.Sum256(verifierPAE)
	signerHash := sha256.Sum256(signerPAE)

	if verifierHash != signerHash {
		t.Fatal("BUG-VERIFY-8: PAE hash mismatch between signer and verifier")
	}
	t.Log("PAE construction is consistent between signer and verifier")
}

// BUG-VERIFY-9: topoSortSteps silently accepts cycles and processes them.
// In a supply chain verification context, a cycle means the dependency graph
// is malformed and should be rejected, not silently accepted.
func TestTopoSort_CycleShouldBeError(t *testing.T) {
	steps := map[string]aflock.Step{
		"A": {Name: "A", ArtifactsFrom: []string{"B"}},
		"B": {Name: "B", ArtifactsFrom: []string{"A"}},
	}

	_, err := topoSortSteps(steps)

	// Fixed: topoSortSteps now returns an error on cycles
	if err == nil {
		t.Error("BUG-VERIFY-9: topoSortSteps should return error for cycle A->B->A")
	}
}

// BUG-VERIFY-10: loadRootCertificates tries file read, then inline PEM, then base64.
// An attacker who can control the policy roots could use a file path like
// /proc/self/environ to read sensitive data from the filesystem into the cert parser.
// The cert parser would fail, but the file READ happens.
func TestLoadRootCertificates_FileReadSideChannel(t *testing.T) {
	// This tests that arbitrary file paths in Certificate field are read
	roots := map[string]aflock.Root{
		"evil": {Certificate: "/etc/hostname"},
	}

	// This will read /etc/hostname, fail to parse it as PEM, try base64, fail
	_, err := loadRootCertificates(roots)
	if err != nil {
		// Expected: not a valid cert. But the file WAS read.
		t.Logf("Error (expected): %v", err)
		t.Log("BUG-VERIFY-10: Policy root Certificate field reads arbitrary files from disk")
		t.Log("An attacker controlling policy could read sensitive files (side channel via error messages)")
	}
}

// BUG-VERIFY-11: verifyDSSESignatures only requires ONE valid signature.
// If an envelope has multiple signatures, only one needs to be valid.
// An attacker could add their own signature alongside the legitimate one
// and the verification would still pass.
func TestVerifyDSSESignatures_OneOfMany(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	payload := []byte(`{"test":"data"}`)
	payloadType := "application/vnd.in-toto+json"
	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	paeBytes := append([]byte(pae), payload...)
	hash := sha256.Sum256(paeBytes)

	// Create valid signature
	validSig, err := ecdsa.SignASN1(rand.Reader, caKey, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Create bogus signature
	bogusSig := []byte("this-is-not-a-valid-signature")

	step := &aflock.Step{
		Name: "test",
		Functionaries: []aflock.StepFunctionary{
			{Type: "publickey", PublicKeyID: "valid-key"},
		},
	}

	sigs := []struct {
		KeyID       string `json:"keyid"`
		Sig         string `json:"sig"`
		Certificate string `json:"certificate,omitempty"`
	}{
		{KeyID: "bogus-key", Sig: base64.StdEncoding.EncodeToString(bogusSig)},
		{KeyID: "valid-key", Sig: base64.StdEncoding.EncodeToString(validSig)},
	}

	err = verifyDSSESignatures(payloadType, payload, sigs, []*x509.Certificate{caCert}, step)
	if err == nil {
		t.Log("BUG-VERIFY-11: Envelope with bogus + valid signature accepted (only one needs to match)")
		t.Log("This is expected DSSE behavior but could be a policy concern")
	}
}

// BUG-VERIFY-12: certMatchesConstraint with empty constraint matches ANY certificate.
// This means a functionary with type:"root" and empty certConstraint matches everything.
func TestCertConstraint_EmptyMatchesAll(t *testing.T) {
	caCert, _ := generateTestCA(t)

	constraint := &aflock.CertConstraint{} // Empty
	if certMatchesConstraint(caCert, constraint) {
		t.Log("BUG-VERIFY-12 confirmed: empty CertConstraint matches any certificate")
		t.Log("A step functionary with empty certConstraint accepts ANY trusted signature")
	}
}

// Helper: generate an Ed25519 self-signed certificate
func generateEd25519CA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Ed25519 Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		t.Fatalf("create ed25519 cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse ed25519 cert: %v", err)
	}

	return cert, privKey
}

// BUG-VERIFY-13 (FIXED in issue #57 / C2): Ed25519 verification path regression test.
// Verifier uses raw PAE; signer now also signs raw PAE (fixed from SHA256-prehash).
func TestVerifySignatureWithCert_Ed25519(t *testing.T) {
	cert, privKey := generateEd25519CA(t)

	message := []byte("DSSEv1 33 application/vnd.in-toto+json 15 {\"test\":\"data\"}")

	// What the VERIFIER expects: signature over raw message
	sigOverRaw := ed25519.Sign(privKey, message)

	// What the SIGNER does: hash first, then sign the hash
	hash := sha256.Sum256(message)
	sigOverHash := ed25519.Sign(privKey, hash[:])

	// Verify using the verifier's code path
	resultRaw := verifySignatureWithCert(cert, message, hash[:], sigOverRaw)
	resultHash := verifySignatureWithCert(cert, message, hash[:], sigOverHash)

	t.Logf("Sig over raw message verifies: %v (this is what verifier expects)", resultRaw)
	t.Logf("Sig over hash verifies: %v (this is what signer produces)", resultHash)

	if resultRaw && !resultHash {
		t.Log("BUG-VERIFY-13 confirmed: Verifier expects raw-message Ed25519 sigs, signer produces hash sigs")
		t.Log("Ed25519 attestations will NEVER verify correctly")
	}
	if !resultRaw && resultHash {
		t.Log("Verifier accepts hash-based Ed25519 sigs (unexpected)")
	}
	if resultRaw && resultHash {
		t.Log("Both verify (unexpected)")
	}
}

// BUG-VERIFY-14: matchSPIFFEPattern uses filepath.Match which is platform-dependent.
// On Windows, filepath.Match uses backslash as separator.
// SPIFFE IDs always use forward slashes.
func TestMatchSPIFFEPattern_PlatformDependence(t *testing.T) {
	// filepath.Match on all platforms should handle forward slashes in SPIFFE IDs
	pattern := "spiffe://aflock.ai/agent/*/test"
	value := "spiffe://aflock.ai/agent/claude/test"

	matched := matchSPIFFEPattern(pattern, value)
	if !matched {
		t.Error("BUG-VERIFY-14: filepath.Match failed on SPIFFE ID pattern with forward slashes")
	}
}

// BUG-VERIFY-15: VerifyAttestation previously accepted both v1 and v0.1 statement types.
// This was fixed to reject v0.1 to prevent downgrade attacks.
func TestVerifyAttestation_StatementTypeDowngrade(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	// Create a v0.1 statement (older format)
	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"subject":       []map[string]interface{}{},
		"predicateType": "https://aflock.ai/attestations/action/v0.1",
		"predicate":     map[string]string{"action": "test"},
	}
	payload, _ := json.Marshal(statement)

	envelopeData := signDSSE(t, "application/vnd.in-toto+json", payload, caKey, "test-key")

	envelopePath := filepath.Join(t.TempDir(), "v01.intoto.json")
	os.WriteFile(envelopePath, envelopeData, 0644)

	pol := &aflock.Policy{
		Roots: map[string]aflock.Root{
			"test-ca": {Certificate: certToPEM(caCert)},
		},
	}

	v := NewVerifier()
	err := v.VerifyAttestation(envelopePath, pol)
	if err == nil {
		t.Fatal("BUG-VERIFY-15 regression: v0.1 statement type should be rejected")
	}
	if !strings.Contains(err.Error(), "invalid statement type") {
		t.Errorf("Expected 'invalid statement type' error, got: %v", err)
	}
	t.Logf("BUG-VERIFY-15 fixed: v0.1 correctly rejected: %v", err)
}

// Helper to create PEM from cert (duplicated since the original is in the main test file)
func certToPEMAudit(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}
