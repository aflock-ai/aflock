package attestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/internal/identity"
	"github.com/aflock-ai/aflock/pkg/aflock"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// --- Test helpers ---

// generateTestCA creates a self-signed CA certificate and private key.
func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"aflock-test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	return caCert, caKey
}

// generateTestLeafCert creates a leaf certificate signed by the given CA.
func generateTestLeafCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Leaf",
			Organization: []string{"aflock-test"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	return leafCert, leafKey
}

// newTestIdentity creates a test Identity with real crypto keys.
func newTestIdentity(t *testing.T) (*identity.Identity, *x509.Certificate) {
	t.Helper()
	caCert, caKey := generateTestCA(t)
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey)

	spiffeID := spiffeid.RequireFromSegments(
		spiffeid.RequireTrustDomainFromString("aflock.ai"),
		"agent", "test-model", "1-0", "abcdef1234567890",
	)

	id := &identity.Identity{
		SPIFFEID:    spiffeID,
		Certificate: leafCert,
		PrivateKey:  leafKey,
		TrustBundle: []*x509.Certificate{caCert},
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}

	return id, caCert
}

// newSignerWithIdentity creates a Signer with a preloaded test identity,
// bypassing SPIRE entirely.
func newSignerWithIdentity(t *testing.T) (*Signer, *identity.Identity, *x509.Certificate) {
	t.Helper()
	id, caCert := newTestIdentity(t)
	s := &Signer{
		identity: id,
	}
	return s, id, caCert
}

// --- PAE Tests ---

func TestCreatePAE_Correctness(t *testing.T) {
	// DSSE v1 spec: "DSSEv1" || LE64(len(type)) || type || LE64(len(body)) || body
	// LE64 is an 8-byte unsigned little-endian integer.
	le64 := func(n int) []byte {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(n))
		return b
	}
	buildExpected := func(payloadType string, payload []byte) []byte {
		var buf []byte
		buf = append(buf, "DSSEv1"...)
		buf = append(buf, le64(len(payloadType))...)
		buf = append(buf, payloadType...)
		buf = append(buf, le64(len(payload))...)
		buf = append(buf, payload...)
		return buf
	}

	tests := []struct {
		name        string
		payloadType string
		payload     []byte
	}{
		{
			name:        "standard in-toto payload type",
			payloadType: "application/vnd.in-toto+json",
			payload:     []byte(`{"hello":"world"}`),
		},
		{
			name:        "empty payload",
			payloadType: "application/vnd.in-toto+json",
			payload:     []byte{},
		},
		{
			name:        "empty payload type",
			payloadType: "",
			payload:     []byte("data"),
		},
		{
			name:        "binary-ish payload",
			payloadType: "application/octet-stream",
			payload:     []byte{0x41, 0x42, 0x43}, // "ABC"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createPAE(tt.payloadType, tt.payload)
			expected := buildExpected(tt.payloadType, tt.payload)
			if !bytes.Equal(got, expected) {
				t.Errorf("createPAE(%q, %q):\n  got  = %x\n  want = %x", tt.payloadType, tt.payload, got, expected)
			}
		})
	}
}

func TestCreatePAE_LengthPrefix(t *testing.T) {
	payload := []byte("café") // 5 bytes in UTF-8 (é = 2 bytes)
	pae := createPAE("test", payload)

	// The LE64 length prefix for "test" (4 bytes) should be [4,0,0,0,0,0,0,0]
	// Starting at offset 6 (after "DSSEv1").
	typeLen := binary.LittleEndian.Uint64(pae[6:14])
	if typeLen != 4 {
		t.Errorf("type length = %d, want 4", typeLen)
	}

	// Payload length should be the byte count (5), not rune count (4).
	payloadLenOffset := 6 + 8 + 4 // "DSSEv1" + LE64(type len) + "test"
	payloadLen := binary.LittleEndian.Uint64(pae[payloadLenOffset : payloadLenOffset+8])
	if payloadLen != uint64(len(payload)) {
		t.Errorf("payload length = %d, want %d (byte count, not rune count)", payloadLen, len(payload))
	}
}

// --- computeSHA256 Tests ---

func TestComputeSHA256(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantHash string
	}{
		{
			name:     "empty input",
			input:    []byte{},
			wantHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "nil input",
			input:    nil,
			wantHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "known value",
			input:    []byte("hello"),
			wantHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeSHA256(tt.input)
			if got != tt.wantHash {
				t.Errorf("computeSHA256(%q) = %q, want %q", tt.input, got, tt.wantHash)
			}
		})
	}
}

// --- signWithPrivateKey Tests ---

func TestSignWithPrivateKey_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	data := []byte("test data to sign")
	sig, err := signWithPrivateKey(key, data)
	if err != nil {
		t.Fatalf("signWithPrivateKey: %v", err)
	}

	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}

	// Verify the signature manually
	hash := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(&key.PublicKey, hash[:], sig) {
		t.Error("signature verification failed")
	}
}

func TestSignWithPrivateKey_UnsupportedKeyType(t *testing.T) {
	_, err := signWithPrivateKey("not-a-key", []byte("data"))
	if err == nil {
		t.Fatal("expected error for unsupported key type, got nil")
	}
	if got := err.Error(); got != "unsupported key type: string" {
		t.Errorf("unexpected error message: %q", got)
	}
}

func TestSignWithPrivateKey_DeterministicVerification(t *testing.T) {
	// ECDSA signatures are non-deterministic, but they should all verify
	// against the same public key and data.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	data := []byte("determinism test")
	hash := sha256.Sum256(data)

	for i := 0; i < 10; i++ {
		sig, err := signWithPrivateKey(key, data)
		if err != nil {
			t.Fatalf("iteration %d: signWithPrivateKey: %v", i, err)
		}
		if !ecdsa.VerifyASN1(&key.PublicKey, hash[:], sig) {
			t.Fatalf("iteration %d: signature verification failed", i)
		}
	}
}

// --- Sign Tests ---

func TestSign_ProducesValidEnvelope(t *testing.T) {
	signer, id, _ := newSignerWithIdentity(t)

	statement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{
				Name:   "test-subject",
				Digest: map[string]string{"sha256": "abc123"},
			},
		},
		PredicateType: PredicateTypeAflockAction,
		Predicate:     map[string]string{"key": "value"},
	}

	env, err := signer.Sign(context.Background(), statement)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Check envelope structure
	if env.PayloadType != PayloadType {
		t.Errorf("PayloadType = %q, want %q", env.PayloadType, PayloadType)
	}

	if len(env.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(env.Signatures))
	}

	if env.Signatures[0].KeyID != id.SPIFFEID.String() {
		t.Errorf("KeyID = %q, want %q", env.Signatures[0].KeyID, id.SPIFFEID.String())
	}

	// Decode payload and verify it's the serialized statement
	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var decoded Statement
	if err := json.Unmarshal(payloadBytes, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	if decoded.Type != StatementType {
		t.Errorf("decoded Type = %q, want %q", decoded.Type, StatementType)
	}
	if decoded.PredicateType != PredicateTypeAflockAction {
		t.Errorf("decoded PredicateType = %q, want %q", decoded.PredicateType, PredicateTypeAflockAction)
	}
	if len(decoded.Subject) != 1 || decoded.Subject[0].Name != "test-subject" {
		t.Errorf("decoded Subject unexpected: %+v", decoded.Subject)
	}
}

func TestSign_NilIdentity_ReturnsError(t *testing.T) {
	signer := &Signer{} // No identity set

	statement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "test", Digest: map[string]string{"sha256": "abc"}},
		},
		PredicateType: "test-type",
		Predicate:     "test",
	}

	_, err := signer.Sign(context.Background(), statement)
	if err == nil {
		t.Fatal("expected error when signing without identity, got nil")
	}

	expectedMsg := "no signing identity available"
	if err.Error() != expectedMsg {
		t.Errorf("error = %q, want %q", err.Error(), expectedMsg)
	}
}

func TestSign_SignatureIsVerifiable(t *testing.T) {
	signer, id, _ := newSignerWithIdentity(t)

	statement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "verifiable", Digest: map[string]string{"sha256": "deadbeef"}},
		},
		PredicateType: PredicateTypeAflockAction,
		Predicate:     map[string]string{"test": "verify"},
	}

	env, err := signer.Sign(context.Background(), statement)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Manually verify: decode payload, recreate PAE, check signature
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	pae := createPAE(env.PayloadType, payload)
	hash := sha256.Sum256(pae)

	sigBytes, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	ecdsaPub := id.Certificate.PublicKey.(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(ecdsaPub, hash[:], sigBytes) {
		t.Error("manual ECDSA verification of signed envelope failed")
	}
}

// --- VerifyEnvelope Tests ---

func TestVerifyEnvelope_ValidSignature(t *testing.T) {
	signer, _, caCert := newSignerWithIdentity(t)

	statement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "verified-subject", Digest: map[string]string{"sha256": "aaa"}},
		},
		PredicateType: PredicateTypeAflockAction,
		Predicate:     "verify-me",
	}

	env, err := signer.Sign(context.Background(), statement)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify with the leaf certificate (VerifyEnvelope checks cert public keys)
	id := signer.identity
	err = VerifyEnvelope(env, []*x509.Certificate{id.Certificate})
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}

	// Also verify it works with the CA cert in the list (should NOT work
	// because the CA cert's public key is different from the signing key)
	err = VerifyEnvelope(env, []*x509.Certificate{caCert})
	if err == nil {
		t.Error("expected verification to fail with CA cert only (wrong public key)")
	}

	// Verify with both certs in the list (should work because leaf cert matches)
	err = VerifyEnvelope(env, []*x509.Certificate{caCert, id.Certificate})
	if err != nil {
		t.Errorf("VerifyEnvelope with both certs: %v", err)
	}
}

func TestVerifyEnvelope_NoSignatures(t *testing.T) {
	env := &Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{}`)),
		Signatures:  []Signature{},
	}

	err := VerifyEnvelope(env, []*x509.Certificate{})
	if err == nil {
		t.Fatal("expected error for envelope with no signatures")
	}
	if err.Error() != "no signatures in envelope" {
		t.Errorf("unexpected error: %q", err.Error())
	}
}

func TestVerifyEnvelope_InvalidPayloadBase64(t *testing.T) {
	env := &Envelope{
		PayloadType: PayloadType,
		Payload:     "not-valid-base64!!!",
		Signatures: []Signature{
			{KeyID: "test", Sig: base64.StdEncoding.EncodeToString([]byte("fake"))},
		},
	}

	err := VerifyEnvelope(env, []*x509.Certificate{})
	if err == nil {
		t.Fatal("expected error for invalid base64 payload")
	}
}

func TestVerifyEnvelope_InvalidSignatureBase64(t *testing.T) {
	env := &Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{}`)),
		Signatures: []Signature{
			{KeyID: "test", Sig: "not-valid-base64!!!"},
		},
	}

	_, leafKey := generateTestCA(t)
	leafCert := &x509.Certificate{PublicKey: &leafKey.PublicKey}

	err := VerifyEnvelope(env, []*x509.Certificate{leafCert})
	if err == nil {
		t.Fatal("expected error for invalid base64 signature")
	}
}

func TestVerifyEnvelope_WrongKey(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)

	statement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "wrong-key-test", Digest: map[string]string{"sha256": "bbb"}},
		},
		PredicateType: PredicateTypeAflockAction,
		Predicate:     "tamper-test",
	}

	env, err := signer.Sign(context.Background(), statement)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Generate a completely different key pair
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	wrongCert := &x509.Certificate{PublicKey: &wrongKey.PublicKey}

	err = VerifyEnvelope(env, []*x509.Certificate{wrongCert})
	if err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestVerifyEnvelope_TamperedPayload(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)

	statement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "tamper-test", Digest: map[string]string{"sha256": "ccc"}},
		},
		PredicateType: PredicateTypeAflockAction,
		Predicate:     "original-data",
	}

	env, err := signer.Sign(context.Background(), statement)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper with the payload
	tamperedStatement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "TAMPERED", Digest: map[string]string{"sha256": "evil"}},
		},
		PredicateType: PredicateTypeAflockAction,
		Predicate:     "tampered-data",
	}
	tamperedPayload, _ := json.Marshal(tamperedStatement)
	env.Payload = base64.StdEncoding.EncodeToString(tamperedPayload)

	// Verification should fail because PAE changed
	id := signer.identity
	err = VerifyEnvelope(env, []*x509.Certificate{id.Certificate})
	if err == nil {
		t.Fatal("expected verification to fail after payload tampering")
	}
}

func TestVerifyEnvelope_TamperedSignature(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)

	statement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "sig-tamper", Digest: map[string]string{"sha256": "ddd"}},
		},
		PredicateType: PredicateTypeAflockAction,
		Predicate:     "data",
	}

	env, err := signer.Sign(context.Background(), statement)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper with the signature bytes
	sigBytes, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	// Flip a byte
	if len(sigBytes) > 5 {
		sigBytes[5] ^= 0xFF
	}
	env.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sigBytes)

	id := signer.identity
	err = VerifyEnvelope(env, []*x509.Certificate{id.Certificate})
	if err == nil {
		t.Fatal("expected verification to fail after signature tampering")
	}
}

func TestVerifyEnvelope_EmptyTrustedCerts(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)

	statement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "empty-certs", Digest: map[string]string{"sha256": "eee"}},
		},
		PredicateType: PredicateTypeAflockAction,
		Predicate:     "data",
	}

	env, err := signer.Sign(context.Background(), statement)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	err = VerifyEnvelope(env, []*x509.Certificate{})
	if err == nil {
		t.Fatal("expected error when verifying with empty trusted certs")
	}
}

func TestVerifyEnvelope_MultipleSignatures(t *testing.T) {
	// Create an envelope with two signatures from different keys.
	// Both must verify for VerifyEnvelope to succeed.
	id1, _ := newTestIdentity(t)
	id2, _ := newTestIdentity(t)

	signer1 := &Signer{identity: id1}

	statement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "multi-sig", Digest: map[string]string{"sha256": "fff"}},
		},
		PredicateType: PredicateTypeAflockAction,
		Predicate:     "multi-sig-data",
	}

	// Sign with first signer
	env, err := signer1.Sign(context.Background(), statement)
	if err != nil {
		t.Fatalf("Sign with signer1: %v", err)
	}

	// Manually add a second signature
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	pae := createPAE(env.PayloadType, payload)
	sig2, err := signWithPrivateKey(id2.PrivateKey, pae)
	if err != nil {
		t.Fatalf("sign with second key: %v", err)
	}

	env.Signatures = append(env.Signatures, Signature{
		KeyID: id2.SPIFFEID.String(),
		Sig:   base64.StdEncoding.EncodeToString(sig2),
	})

	// Verify with both leaf certs
	err = VerifyEnvelope(env, []*x509.Certificate{id1.Certificate, id2.Certificate})
	if err != nil {
		t.Fatalf("VerifyEnvelope with both certs: %v", err)
	}

	// Verify with only one cert should fail (second sig won't verify)
	err = VerifyEnvelope(env, []*x509.Certificate{id1.Certificate})
	if err == nil {
		t.Error("expected failure when only one of two signing certs is trusted")
	}
}

// --- CreateActionAttestation Tests ---

//nolint:gocyclo // comprehensive integration test
func TestCreateActionAttestation_BasicAction(t *testing.T) {
	signer, id, _ := newSignerWithIdentity(t)

	now := time.Now()
	record := aflock.ActionRecord{
		Timestamp: now,
		ToolName:  "Bash",
		ToolUseID: "tu_abc123",
		ToolInput: json.RawMessage(`{"command":"ls -la"}`),
		Decision:  "allow",
		Reason:    "matched allow list",
	}

	metrics := &aflock.SessionMetrics{
		TokensIn:  1000,
		TokensOut: 500,
		CostUSD:   0.05,
		Turns:     3,
		ToolCalls: 7,
	}

	agentID := &identity.AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
		Binary: &identity.BinaryIdentity{
			Name:    "claude-code",
			Version: "1.0.26",
			Digest:  "sha256:deadbeef",
		},
		Environment: &identity.EnvironmentIdentity{
			Type: "local",
		},
		PolicyDigest: "sha256:cafebabe",
		IdentityHash: "abcdef1234567890abcdef1234567890",
	}

	env, err := signer.CreateActionAttestation(
		context.Background(),
		record,
		"session-xyz",
		metrics,
		agentID,
	)
	if err != nil {
		t.Fatalf("CreateActionAttestation: %v", err)
	}

	// Verify envelope structure
	if env.PayloadType != PayloadType {
		t.Errorf("PayloadType = %q, want %q", env.PayloadType, PayloadType)
	}
	if len(env.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(env.Signatures))
	}
	if env.Signatures[0].KeyID != id.SPIFFEID.String() {
		t.Errorf("KeyID = %q, want %q", env.Signatures[0].KeyID, id.SPIFFEID.String())
	}

	// Decode and verify the statement
	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var stmt Statement
	if err := json.Unmarshal(payloadBytes, &stmt); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}

	if stmt.Type != StatementType {
		t.Errorf("statement Type = %q, want %q", stmt.Type, StatementType)
	}
	if stmt.PredicateType != PredicateTypeAflockAction {
		t.Errorf("PredicateType = %q, want %q", stmt.PredicateType, PredicateTypeAflockAction)
	}

	// Verify subject
	if len(stmt.Subject) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(stmt.Subject))
	}
	expectedSubjectName := "session:session-xyz/action:tu_abc123"
	if stmt.Subject[0].Name != expectedSubjectName {
		t.Errorf("subject name = %q, want %q", stmt.Subject[0].Name, expectedSubjectName)
	}

	// The subject digest should be SHA256 of the tool input
	expectedDigest := computeSHA256(record.ToolInput)
	if stmt.Subject[0].Digest["sha256"] != expectedDigest {
		t.Errorf("subject digest = %q, want %q", stmt.Subject[0].Digest["sha256"], expectedDigest)
	}

	// Unmarshal predicate to check fields
	predicateJSON, err := json.Marshal(stmt.Predicate)
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	var pred ActionPredicate
	if err := json.Unmarshal(predicateJSON, &pred); err != nil {
		t.Fatalf("unmarshal predicate: %v", err)
	}

	if pred.Action != "tool_call" {
		t.Errorf("action = %q, want %q", pred.Action, "tool_call")
	}
	if pred.SessionID != "session-xyz" {
		t.Errorf("sessionId = %q, want %q", pred.SessionID, "session-xyz")
	}
	if pred.ToolName != "Bash" {
		t.Errorf("toolName = %q, want %q", pred.ToolName, "Bash")
	}
	if pred.ToolUseID != "tu_abc123" {
		t.Errorf("toolUseId = %q, want %q", pred.ToolUseID, "tu_abc123")
	}
	if pred.Decision != "allow" {
		t.Errorf("decision = %q, want %q", pred.Decision, "allow")
	}
	if pred.Reason != "matched allow list" {
		t.Errorf("reason = %q, want %q", pred.Reason, "matched allow list")
	}
	if pred.AgentID != id.SPIFFEID.String() {
		t.Errorf("agentId = %q, want %q", pred.AgentID, id.SPIFFEID.String())
	}

	// Verify agent identity
	if pred.AgentIdentity == nil {
		t.Fatal("agentIdentity is nil")
	}
	if pred.AgentIdentity.Model != "claude-opus-4-5-20251101" {
		t.Errorf("model = %q, want %q", pred.AgentIdentity.Model, "claude-opus-4-5-20251101")
	}
	if pred.AgentIdentity.Binary != "claude-code@1.0.26" {
		t.Errorf("binary = %q, want %q", pred.AgentIdentity.Binary, "claude-code@1.0.26")
	}
	if pred.AgentIdentity.BinaryHash != "sha256:deadbeef" {
		t.Errorf("binaryHash = %q, want %q", pred.AgentIdentity.BinaryHash, "sha256:deadbeef")
	}
	if pred.AgentIdentity.Environment != "local" {
		t.Errorf("environment = %q, want %q", pred.AgentIdentity.Environment, "local")
	}
	if pred.AgentIdentity.PolicyDigest != "sha256:cafebabe" {
		t.Errorf("policyDigest = %q, want %q", pred.AgentIdentity.PolicyDigest, "sha256:cafebabe")
	}

	// Verify metrics
	if pred.Metrics == nil {
		t.Fatal("metrics is nil")
	}
	if pred.Metrics.CumulativeTokensIn != 1000 {
		t.Errorf("tokensIn = %d, want %d", pred.Metrics.CumulativeTokensIn, 1000)
	}
	if pred.Metrics.CumulativeTokensOut != 500 {
		t.Errorf("tokensOut = %d, want %d", pred.Metrics.CumulativeTokensOut, 500)
	}
	if pred.Metrics.CumulativeCostUSD != 0.05 {
		t.Errorf("costUSD = %f, want %f", pred.Metrics.CumulativeCostUSD, 0.05)
	}
	if pred.Metrics.TurnNumber != 3 {
		t.Errorf("turns = %d, want %d", pred.Metrics.TurnNumber, 3)
	}
	if pred.Metrics.ToolCallNumber != 7 {
		t.Errorf("toolCalls = %d, want %d", pred.Metrics.ToolCallNumber, 7)
	}

	// Finally, verify the envelope signature is valid
	err = VerifyEnvelope(env, []*x509.Certificate{signer.identity.Certificate})
	if err != nil {
		t.Fatalf("VerifyEnvelope on action attestation: %v", err)
	}
}

func TestCreateActionAttestation_NilToolInput(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)

	record := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Read",
		ToolUseID: "tu_nil_input",
		ToolInput: nil, // Nil tool input
		Decision:  "allow",
	}

	env, err := signer.CreateActionAttestation(
		context.Background(),
		record,
		"session-nil",
		nil, // nil metrics
		nil, // nil agent identity
	)
	if err != nil {
		t.Fatalf("CreateActionAttestation with nil input: %v", err)
	}

	// Should still produce a valid envelope
	if len(env.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(env.Signatures))
	}

	// Verify the envelope is valid
	err = VerifyEnvelope(env, []*x509.Certificate{signer.identity.Certificate})
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}

	// Verify predicate has nil metrics and no agent identity
	payloadBytes, _ := base64.StdEncoding.DecodeString(env.Payload)
	var stmt Statement
	if err := json.Unmarshal(payloadBytes, &stmt); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}

	predicateJSON, _ := json.Marshal(stmt.Predicate)
	var pred ActionPredicate
	if err := json.Unmarshal(predicateJSON, &pred); err != nil {
		t.Fatalf("unmarshal predicate: %v", err)
	}

	if pred.Metrics != nil {
		t.Error("expected nil metrics for nil input")
	}
	if pred.AgentIdentity != nil {
		t.Error("expected nil agentIdentity for nil input")
	}
}

func TestCreateActionAttestation_InvalidToolInputJSON(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)

	record := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Bash",
		ToolUseID: "tu_bad_json",
		ToolInput: json.RawMessage(`{not valid json`),
		Decision:  "allow",
	}

	// Should not error -- invalid JSON is handled gracefully
	env, err := signer.CreateActionAttestation(
		context.Background(),
		record,
		"session-bad-json",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateActionAttestation with bad JSON: %v", err)
	}

	// Verify it still produces a signed envelope
	err = VerifyEnvelope(env, []*x509.Certificate{signer.identity.Certificate})
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
}

func TestCreateActionAttestation_NoIdentity(t *testing.T) {
	signer := &Signer{} // No identity

	record := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Bash",
		ToolUseID: "tu_no_id",
		Decision:  "allow",
	}

	_, err := signer.CreateActionAttestation(
		context.Background(),
		record,
		"session-no-id",
		nil,
		nil,
	)
	if err == nil {
		t.Fatal("expected error when creating attestation without identity")
	}
}

func TestCreateActionAttestation_AgentIdentityWithoutBinary(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)

	record := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Read",
		ToolUseID: "tu_no_binary",
		Decision:  "allow",
	}

	agentID := &identity.AgentIdentity{
		Model:        "claude-opus-4-5-20251101",
		ModelVersion: "4.5.20251101",
		Binary:       nil, // No binary info
		Environment:  nil, // No environment info
		IdentityHash: "1234567890abcdef1234567890abcdef",
	}

	env, err := signer.CreateActionAttestation(
		context.Background(),
		record,
		"session-no-binary",
		nil,
		agentID,
	)
	if err != nil {
		t.Fatalf("CreateActionAttestation: %v", err)
	}

	payloadBytes, _ := base64.StdEncoding.DecodeString(env.Payload)
	var stmt Statement
	if err := json.Unmarshal(payloadBytes, &stmt); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}
	predicateJSON, _ := json.Marshal(stmt.Predicate)
	var pred ActionPredicate
	if err := json.Unmarshal(predicateJSON, &pred); err != nil {
		t.Fatalf("unmarshal predicate: %v", err)
	}

	if pred.AgentIdentity == nil {
		t.Fatal("agentIdentity should not be nil")
	}
	if pred.AgentIdentity.Binary != "" {
		t.Errorf("binary should be empty, got %q", pred.AgentIdentity.Binary)
	}
	if pred.AgentIdentity.Environment != "" {
		t.Errorf("environment should be empty, got %q", pred.AgentIdentity.Environment)
	}
}

// --- ExportCertificatePEM / ExportTrustBundlePEM Tests ---

func TestExportCertificatePEM(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)

	pemBytes, err := signer.ExportCertificatePEM()
	if err != nil {
		t.Fatalf("ExportCertificatePEM: %v", err)
	}

	if len(pemBytes) == 0 {
		t.Fatal("PEM bytes are empty")
	}

	// Verify it's valid PEM
	if string(pemBytes[:27]) != "-----BEGIN CERTIFICATE-----" {
		t.Errorf("expected PEM header, got: %q", string(pemBytes[:27]))
	}
}

func TestExportCertificatePEM_NoIdentity(t *testing.T) {
	signer := &Signer{}

	_, err := signer.ExportCertificatePEM()
	if err == nil {
		t.Fatal("expected error when exporting cert without identity")
	}
}

func TestExportTrustBundlePEM(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)

	pemBytes, err := signer.ExportTrustBundlePEM()
	if err != nil {
		t.Fatalf("ExportTrustBundlePEM: %v", err)
	}

	if len(pemBytes) == 0 {
		t.Fatal("trust bundle PEM bytes are empty")
	}

	if string(pemBytes[:27]) != "-----BEGIN CERTIFICATE-----" {
		t.Errorf("expected PEM header, got: %q", string(pemBytes[:27]))
	}
}

func TestExportTrustBundlePEM_NoIdentity(t *testing.T) {
	signer := &Signer{}

	_, err := signer.ExportTrustBundlePEM()
	if err == nil {
		t.Fatal("expected error when exporting trust bundle without identity")
	}
}

func TestExportTrustBundlePEM_EmptyBundle(t *testing.T) {
	id, _ := newTestIdentity(t)
	id.TrustBundle = nil // Clear trust bundle

	signer := &Signer{identity: id}

	_, err := signer.ExportTrustBundlePEM()
	if err == nil {
		t.Fatal("expected error when exporting empty trust bundle")
	}
}

// --- spireSigner Tests ---

func TestSpireSigner_Sign(t *testing.T) {
	id, _ := newTestIdentity(t)
	ss := &spireSigner{identity: id}

	data := []byte("data to sign via spireSigner")
	sigBytes, err := ss.Sign(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("spireSigner.Sign: %v", err)
	}

	// Verify the signature
	hash := sha256.Sum256(data)
	ecdsaPub := id.Certificate.PublicKey.(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(ecdsaPub, hash[:], sigBytes) {
		t.Error("spireSigner signature verification failed")
	}
}

func TestSpireSigner_KeyID(t *testing.T) {
	id, _ := newTestIdentity(t)
	ss := &spireSigner{identity: id}

	keyID, err := ss.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}

	if keyID != id.SPIFFEID.String() {
		t.Errorf("KeyID = %q, want %q", keyID, id.SPIFFEID.String())
	}
}

func TestSpireSigner_KeyID_NilIdentity(t *testing.T) {
	ss := &spireSigner{identity: nil}

	_, err := ss.KeyID()
	if err == nil {
		t.Fatal("expected error for nil identity")
	}
}

func TestSpireSigner_Verifier(t *testing.T) {
	id, _ := newTestIdentity(t)
	ss := &spireSigner{identity: id}

	verifier, err := ss.Verifier()
	if err != nil {
		t.Fatalf("Verifier: %v", err)
	}

	if verifier == nil {
		t.Fatal("verifier is nil")
	}
}

func TestSpireSigner_Verifier_NilIdentity(t *testing.T) {
	ss := &spireSigner{identity: nil}

	_, err := ss.Verifier()
	if err == nil {
		t.Fatal("expected error for nil identity")
	}
}

func TestSpireSigner_Verifier_NilCertificate(t *testing.T) {
	id, _ := newTestIdentity(t)
	id.Certificate = nil

	ss := &spireSigner{identity: id}

	_, err := ss.Verifier()
	if err == nil {
		t.Fatal("expected error for nil certificate")
	}
}

// --- GetSigner Tests ---

func TestGetSigner(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)

	cryptoSigner, err := signer.GetSigner()
	if err != nil {
		t.Fatalf("GetSigner: %v", err)
	}

	if cryptoSigner == nil {
		t.Fatal("signer is nil")
	}

	// Verify it can sign
	keyID, err := cryptoSigner.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	if keyID == "" {
		t.Error("key ID is empty")
	}
}

func TestGetSigner_NoIdentity(t *testing.T) {
	signer := &Signer{}

	_, err := signer.GetSigner()
	if err == nil {
		t.Fatal("expected error when getting signer without identity")
	}
}

// --- GetSigningIdentity Tests ---

func TestGetSigningIdentity(t *testing.T) {
	signer, expectedID, _ := newSignerWithIdentity(t)

	id, name := signer.GetSigningIdentity()
	if id == nil {
		t.Fatal("identity is nil")
	}
	if id.SPIFFEID.String() != expectedID.SPIFFEID.String() {
		t.Errorf("SPIFFE ID = %q, want %q", id.SPIFFEID.String(), expectedID.SPIFFEID.String())
	}
	if name != "" {
		t.Errorf("name = %q, want empty", name)
	}
}

func TestGetSigningIdentity_Nil(t *testing.T) {
	signer := &Signer{}

	id, _ := signer.GetSigningIdentity()
	if id != nil {
		t.Error("expected nil identity for empty signer")
	}
}

// --- Close Tests ---

func TestClose_NilSpireClient(t *testing.T) {
	signer := &Signer{spireClient: nil}

	err := signer.Close()
	if err != nil {
		t.Fatalf("Close with nil spireClient should not error: %v", err)
	}
}

// --- Attestation Path Helpers Tests ---

func TestAttestationPath(t *testing.T) {
	path := AttestationPath("/attestations", "abc123", "build")
	expected := filepath.Join("/attestations", "abc123", "build.intoto.json")
	if path != expected {
		t.Errorf("AttestationPath = %q, want %q", path, expected)
	}
}

func TestEnsureAttestationDir(t *testing.T) {
	tmpDir := t.TempDir()

	err := EnsureAttestationDir(tmpDir, "treehash123")
	if err != nil {
		t.Fatalf("EnsureAttestationDir: %v", err)
	}

	expectedDir := filepath.Join(tmpDir, "treehash123")
	info, err := os.Stat(expectedDir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory, got file")
	}
}

func TestListAttestations_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	treeHash := "emptyhash"

	// Directory doesn't exist yet
	attestations, err := ListAttestations(tmpDir, treeHash)
	if err != nil {
		t.Fatalf("ListAttestations on non-existent dir: %v", err)
	}
	if attestations != nil {
		t.Errorf("expected nil for non-existent dir, got %v", attestations)
	}
}

func TestListAttestations_WithFiles(t *testing.T) {
	tmpDir := t.TempDir()
	treeHash := "hash456"

	dir := filepath.Join(tmpDir, treeHash)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Create some attestation files and non-attestation files
	testFiles := map[string]bool{
		"build.intoto.json":  true,
		"test.intoto.json":   true,
		"deploy.intoto.json": true,
		"readme.md":          false,
		"config.json":        false,
		"notintoto.json":     false,
	}

	for name := range testFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0644); err != nil {
			t.Fatalf("write file %s: %v", name, err)
		}
	}

	attestations, err := ListAttestations(tmpDir, treeHash)
	if err != nil {
		t.Fatalf("ListAttestations: %v", err)
	}

	if len(attestations) != 3 {
		t.Fatalf("expected 3 attestation files, got %d: %v", len(attestations), attestations)
	}

	// Verify all returned paths end with .intoto.json
	for _, a := range attestations {
		if !filepath.IsAbs(a) {
			t.Errorf("expected absolute path, got %q", a)
		}
		base := filepath.Base(a)
		if expected, ok := testFiles[base]; !ok || !expected {
			t.Errorf("unexpected attestation file: %q", a)
		}
	}
}

// --- Envelope JSON Serialization Tests ---

func TestEnvelope_JSONRoundtrip(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)

	statement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "roundtrip-test", Digest: map[string]string{"sha256": "1234"}},
		},
		PredicateType: PredicateTypeAflockAction,
		Predicate:     map[string]string{"test": "roundtrip"},
	}

	env, err := signer.Sign(context.Background(), statement)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	// Unmarshal back
	var decoded Envelope
	if err := json.Unmarshal(jsonBytes, &decoded); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}

	// Verify structure preserved
	if decoded.PayloadType != env.PayloadType {
		t.Errorf("PayloadType mismatch: got %q, want %q", decoded.PayloadType, env.PayloadType)
	}
	if decoded.Payload != env.Payload {
		t.Errorf("Payload mismatch")
	}
	if len(decoded.Signatures) != len(env.Signatures) {
		t.Fatalf("Signatures count mismatch: got %d, want %d", len(decoded.Signatures), len(env.Signatures))
	}
	if decoded.Signatures[0].KeyID != env.Signatures[0].KeyID {
		t.Errorf("KeyID mismatch: got %q, want %q", decoded.Signatures[0].KeyID, env.Signatures[0].KeyID)
	}
	if decoded.Signatures[0].Sig != env.Signatures[0].Sig {
		t.Errorf("Sig mismatch")
	}

	// Verify the deserialized envelope still verifies
	err = VerifyEnvelope(&decoded, []*x509.Certificate{signer.identity.Certificate})
	if err != nil {
		t.Fatalf("VerifyEnvelope after roundtrip: %v", err)
	}
}

// --- End-to-end: Sign then Verify ---

func TestEndToEnd_SignAndVerify(t *testing.T) {
	signer, _, _ := newSignerWithIdentity(t)

	// Create a realistic action record
	record := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Write",
		ToolUseID: "tu_e2e_001",
		ToolInput: json.RawMessage(`{"file_path":"/tmp/test.go","content":"package main"}`),
		Decision:  "allow",
		Reason:    "file path matches allow pattern",
	}

	metrics := &aflock.SessionMetrics{
		TokensIn:  5000,
		TokensOut: 2500,
		CostUSD:   0.25,
		Turns:     10,
		ToolCalls: 25,
		Tools:     map[string]int{"Write": 5, "Read": 15, "Bash": 5},
	}

	env, err := signer.CreateActionAttestation(
		context.Background(),
		record,
		"session-e2e-test",
		metrics,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateActionAttestation: %v", err)
	}

	// Verify with the correct certificate
	err = VerifyEnvelope(env, []*x509.Certificate{signer.identity.Certificate})
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}

	// Tamper and verify it fails
	original := env.Payload
	tamperedJSON, _ := json.Marshal(Statement{Type: "tampered"})
	env.Payload = base64.StdEncoding.EncodeToString(tamperedJSON)
	err = VerifyEnvelope(env, []*x509.Certificate{signer.identity.Certificate})
	if err == nil {
		t.Error("expected verification failure after tampering")
	}

	// Restore and verify it works again
	env.Payload = original
	err = VerifyEnvelope(env, []*x509.Certificate{signer.identity.Certificate})
	if err != nil {
		t.Fatalf("VerifyEnvelope after restore: %v", err)
	}
}

// --- Constants Tests ---

func TestConstants(t *testing.T) {
	if PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("PayloadType = %q, want %q", PayloadType, "application/vnd.in-toto+json")
	}
	if StatementType != "https://in-toto.io/Statement/v1" {
		t.Errorf("StatementType = %q, want %q", StatementType, "https://in-toto.io/Statement/v1")
	}
	if PredicateTypeAflockAction != "https://aflock.ai/attestations/action/v0.1" {
		t.Errorf("PredicateTypeAflockAction = %q, want %q", PredicateTypeAflockAction, "https://aflock.ai/attestations/action/v0.1")
	}
}
