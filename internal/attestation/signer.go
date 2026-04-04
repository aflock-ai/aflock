// Package attestation provides attestation creation and signing.
package attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"

	"github.com/aflock-ai/aflock/internal/identity"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

const (
	// PayloadType is the DSSE payload type for attestation statements.
	PayloadType = "application/vnd.in-toto+json"
	// StatementType is the attestation statement type.
	StatementType = "https://in-toto.io/Statement/v1"
	// PredicateTypeAflockAction is the predicate type for aflock actions.
	PredicateTypeAflockAction = "https://aflock.ai/attestations/action/v0.1"
)

// Signer creates and signs attestations.
type Signer struct {
	spireClient *identity.SpireClient
	identity    *identity.Identity
	modelName   string
}

// NewSigner creates a new attestation signer.
// If spireSocketPath is empty, uses default SPIRE socket or falls back to local signing.
func NewSigner(spireSocketPath string) *Signer {
	return &Signer{
		spireClient: identity.NewSpireClient(spireSocketPath),
	}
}

// Initialize connects to SPIRE and fetches identity.
func (s *Signer) Initialize(ctx context.Context) error {
	if err := s.spireClient.Connect(ctx); err != nil {
		return fmt.Errorf("connect to SPIRE: %w", err)
	}

	id, err := s.spireClient.GetIdentity(ctx)
	if err != nil {
		return fmt.Errorf("get identity: %w", err)
	}

	s.identity = id
	return nil
}

// SetModel sets the AI model name and validates it against the trusted models list.
// This should be called after Initialize when the model is known.
func (s *Signer) SetModel(ctx context.Context, modelName string) error {
	s.modelName = modelName

	// Check if this is a trusted model
	if !identity.IsTrustedModel(modelName) {
		return fmt.Errorf("model %s is not trusted - attestations will not be signed", modelName)
	}

	return nil
}

// GetSigningIdentity returns the identity to use for signing.
func (s *Signer) GetSigningIdentity() (*identity.Identity, string) {
	return s.identity, ""
}

// Close releases resources.
func (s *Signer) Close() error {
	if s.spireClient != nil {
		return s.spireClient.Close()
	}
	return nil
}

// Statement represents an attestation statement.
type Statement struct {
	Type          string      `json:"_type"`
	Subject       []Subject   `json:"subject"`
	PredicateType string      `json:"predicateType"`
	Predicate     interface{} `json:"predicate"`
}

// Subject represents an attestation subject.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// ActionPredicate is the predicate for aflock action attestations.
type ActionPredicate struct {
	Action        string                 `json:"action"`
	SessionID     string                 `json:"sessionId"`
	ToolName      string                 `json:"toolName"`
	ToolUseID     string                 `json:"toolUseId"`
	ToolInput     map[string]interface{} `json:"toolInput,omitempty"`
	Decision      string                 `json:"decision"`
	Reason        string                 `json:"reason,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	AgentID       string                 `json:"agentId,omitempty"`
	AgentIdentity *TransitiveIdentity    `json:"agentIdentity,omitempty"`
	Metrics       *MetricsPredicate      `json:"metrics,omitempty"`
}

// TransitiveIdentity represents the full transitive agent identity.
type TransitiveIdentity struct {
	Model        string `json:"model"`
	ModelVersion string `json:"modelVersion,omitempty"`
	Binary       string `json:"binary,omitempty"`
	BinaryHash   string `json:"binaryHash,omitempty"`
	Environment  string `json:"environment,omitempty"`
	PolicyDigest string `json:"policyDigest,omitempty"`
	IdentityHash string `json:"identityHash"`
}

// MetricsPredicate contains metrics at the time of the action.
type MetricsPredicate struct {
	CumulativeTokensIn  int64   `json:"cumulativeTokensIn"`
	CumulativeTokensOut int64   `json:"cumulativeTokensOut"`
	CumulativeCostUSD   float64 `json:"cumulativeCostUSD"`
	TurnNumber          int     `json:"turnNumber"`
	ToolCallNumber      int     `json:"toolCallNumber"`
}

// Envelope is a DSSE envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is a DSSE signature.
type Signature struct {
	KeyID       string `json:"keyid"`
	Sig         string `json:"sig"`
	Certificate string `json:"certificate,omitempty"` // PEM-encoded signing certificate
}

// CreateActionAttestation creates an attestation for an action.
func (s *Signer) CreateActionAttestation(
	ctx context.Context,
	record aflock.ActionRecord,
	sessionID string,
	metrics *aflock.SessionMetrics,
	agentIdentity *identity.AgentIdentity,
) (*Envelope, error) {
	// Parse tool input (best-effort, ignore errors)
	var toolInput map[string]interface{}
	if record.ToolInput != nil {
		_ = json.Unmarshal(record.ToolInput, &toolInput)
	}

	// Build predicate
	predicate := ActionPredicate{
		Action:    "tool_call",
		SessionID: sessionID,
		ToolName:  record.ToolName,
		ToolUseID: record.ToolUseID,
		ToolInput: toolInput,
		Decision:  record.Decision,
		Reason:    record.Reason,
		Timestamp: record.Timestamp,
	}

	if s.identity != nil {
		predicate.AgentID = s.identity.SPIFFEID.String()
	}

	// Add transitive agent identity
	if agentIdentity != nil {
		predicate.AgentIdentity = &TransitiveIdentity{
			Model:        agentIdentity.Model,
			ModelVersion: agentIdentity.ModelVersion,
			PolicyDigest: agentIdentity.PolicyDigest,
			IdentityHash: agentIdentity.IdentityHash,
		}
		if agentIdentity.Binary != nil {
			predicate.AgentIdentity.Binary = fmt.Sprintf("%s@%s", agentIdentity.Binary.Name, agentIdentity.Binary.Version)
			predicate.AgentIdentity.BinaryHash = agentIdentity.Binary.Digest
		}
		if agentIdentity.Environment != nil {
			predicate.AgentIdentity.Environment = agentIdentity.Environment.Type
		}
	}

	if metrics != nil {
		predicate.Metrics = &MetricsPredicate{
			CumulativeTokensIn:  metrics.TokensIn,
			CumulativeTokensOut: metrics.TokensOut,
			CumulativeCostUSD:   metrics.CostUSD,
			TurnNumber:          metrics.Turns,
			ToolCallNumber:      metrics.ToolCalls,
		}
	}

	// Build statement
	statement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{
				Name: fmt.Sprintf("session:%s/action:%s", sessionID, record.ToolUseID),
				Digest: map[string]string{
					"sha256": computeSHA256(record.ToolInput),
				},
			},
		},
		PredicateType: PredicateTypeAflockAction,
		Predicate:     predicate,
	}

	return s.Sign(ctx, statement)
}

// Sign signs a statement and returns a DSSE envelope.
func (s *Signer) Sign(ctx context.Context, statement Statement) (*Envelope, error) {
	// Get the appropriate signing identity (delegated or aflock's)
	signingIdentity, _ := s.GetSigningIdentity()
	if signingIdentity == nil {
		return nil, fmt.Errorf("no signing identity available")
	}

	// Serialize statement
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}

	// Base64 encode payload
	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	// Create PAE (Pre-Authentication Encoding)
	pae := createPAE(PayloadType, payload)

	// Sign PAE with the signing identity
	sig, err := signWithPrivateKey(signingIdentity.PrivateKey, pae)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// Encode the signing certificate as PEM for inclusion in the envelope
	var certPEM string
	if signingIdentity.Certificate != nil {
		certPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: signingIdentity.Certificate.Raw,
		}))
	}

	envelope := &Envelope{
		PayloadType: PayloadType,
		Payload:     payloadB64,
		Signatures: []Signature{
			{
				KeyID:       signingIdentity.SPIFFEID.String(),
				Sig:         base64.StdEncoding.EncodeToString(sig),
				Certificate: certPEM,
			},
		},
	}

	return envelope, nil
}

// createPAE creates Pre-Authentication Encoding for DSSE.
// Uses byte slice concatenation instead of fmt.Sprintf to avoid
// corrupting non-UTF-8 payload bytes via string() conversion.
func createPAE(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ",
		len(payloadType), payloadType,
		len(payload))
	result := make([]byte, 0, len(prefix)+len(payload))
	result = append(result, []byte(prefix)...)
	result = append(result, payload...)
	return result
}

// signWithPrivateKey signs data using the provided private key.
func signWithPrivateKey(privateKey interface{}, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)

	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, hash[:])
	case crypto.Signer:
		return key.Sign(rand.Reader, hash[:], crypto.SHA256)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", privateKey)
	}
}

// computeSHA256 computes SHA256 hash of data.
func computeSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// ExportCertificatePEM exports the identity certificate as PEM.
func (s *Signer) ExportCertificatePEM() ([]byte, error) {
	if s.identity == nil || s.identity.Certificate == nil {
		return nil, fmt.Errorf("no identity certificate available")
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.identity.Certificate.Raw,
	}), nil
}

// ExportTrustBundlePEM exports the trust bundle as PEM.
func (s *Signer) ExportTrustBundlePEM() ([]byte, error) {
	if s.identity == nil || len(s.identity.TrustBundle) == 0 {
		return nil, fmt.Errorf("no trust bundle available")
	}

	var bundle []byte
	for _, cert := range s.identity.TrustBundle {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	return bundle, nil
}

// VerifyEnvelope verifies a DSSE envelope signature.
func VerifyEnvelope(envelope *Envelope, trustedCerts []*x509.Certificate) error { //nolint:gocognit // complex signature verification logic
	if len(envelope.Signatures) == 0 {
		return fmt.Errorf("no signatures in envelope")
	}

	// Decode payload
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	// Create PAE
	pae := createPAE(envelope.PayloadType, payload)
	hash := sha256.Sum256(pae)

	// Verify each signature
	for _, sig := range envelope.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			return fmt.Errorf("decode signature: %w", err)
		}

		// Find matching certificate — supports ECDSA, RSA, and Ed25519
		verified := false
		for _, cert := range trustedCerts {
			switch key := cert.PublicKey.(type) {
			case *ecdsa.PublicKey:
				if ecdsa.VerifyASN1(key, hash[:], sigBytes) {
					verified = true
				}
			case *rsa.PublicKey:
				if rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sigBytes) == nil {
					verified = true
				} else if rsa.VerifyPSS(key, crypto.SHA256, hash[:], sigBytes, nil) == nil {
					verified = true
				}
			case ed25519.PublicKey:
				if ed25519.Verify(key, pae, sigBytes) {
					verified = true
				}
			}
			if verified {
				break
			}
		}

		if !verified {
			return fmt.Errorf("signature verification failed for keyid %s", sig.KeyID)
		}
	}

	return nil
}

// spireSigner wraps a SPIRE identity to implement cryptoutil.Signer.
type spireSigner struct {
	identity *identity.Identity
}

// KeyID returns the SPIFFE ID as the key identifier.
func (s *spireSigner) KeyID() (string, error) {
	if s.identity == nil {
		return "", fmt.Errorf("no identity available")
	}
	return s.identity.SPIFFEID.String(), nil
}

// Sign signs the data with the SPIRE private key.
func (s *spireSigner) Sign(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}

	hash := sha256.Sum256(data)

	switch key := s.identity.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, hash[:])
	case crypto.Signer:
		return key.Sign(rand.Reader, hash[:], crypto.SHA256)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", s.identity.PrivateKey)
	}
}

// Verifier returns a verifier for the signer's public key.
func (s *spireSigner) Verifier() (cryptoutil.Verifier, error) {
	if s.identity == nil || s.identity.Certificate == nil {
		return nil, fmt.Errorf("no certificate available")
	}
	return cryptoutil.NewVerifier(s.identity.Certificate.PublicKey)
}

// SignCollection signs an attestation Collection and returns an Envelope.
// The collection is wrapped in an in-toto Statement v1 before signing, so that
// the verifier can parse it as: Statement → predicate → Collection.
func (s *Signer) SignCollection(ctx context.Context, collection attestation.Collection) (*Envelope, error) {
	// Compute a digest of the collection for the subject
	collectionJSON, err := json.Marshal(collection)
	if err != nil {
		return nil, fmt.Errorf("marshal collection: %w", err)
	}
	digest := sha256.Sum256(collectionJSON)

	// Wrap collection in an in-toto Statement
	statement := Statement{
		Type: StatementType,
		Subject: []Subject{
			{
				Name: fmt.Sprintf("step:%s", collection.Name),
				Digest: map[string]string{
					"sha256": fmt.Sprintf("%x", digest),
				},
			},
		},
		PredicateType: attestation.CollectionType,
		Predicate:     collection,
	}

	// Sign using the standard Sign() path (PAE + in-toto envelope)
	return s.Sign(ctx, statement)
}

// GetSigner returns a cryptoutil.Signer using the SPIRE identity.
func (s *Signer) GetSigner() (cryptoutil.Signer, error) {
	if s.identity == nil {
		return nil, fmt.Errorf("no signing identity available")
	}
	return &spireSigner{identity: s.identity}, nil
}
