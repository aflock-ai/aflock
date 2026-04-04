// Package attestation provides attestation creation and signing.
package attestation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	fulcioSigner "github.com/aflock-ai/rookery/plugins/signers/fulcio"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/aflock-ai/aflock/internal/identity"
)

const (
	// DefaultFulcioURL is the Sigstore public good Fulcio instance.
	DefaultFulcioURL = "https://fulcio.sigstore.dev"
)

// InitializeFulcio attempts Fulcio keyless signing using OIDC tokens available
// in the environment (e.g., GitHub Actions). Returns an error if Fulcio signing
// is not available or fails.
func (s *Signer) InitializeFulcio(ctx context.Context) error {
	// Build Fulcio signer provider from environment
	provider, err := buildFulcioProvider()
	if err != nil {
		return fmt.Errorf("fulcio not available: %w", err)
	}

	// Get signer from Fulcio (generates ephemeral key, requests cert)
	rookerySig, err := provider.Signer(ctx)
	if err != nil {
		return fmt.Errorf("fulcio signing failed: %w", err)
	}

	// Extract the X509Signer to get the certificate
	x509Sig, ok := rookerySig.(*cryptoutil.X509Signer)
	if !ok {
		return fmt.Errorf("fulcio signer is not an X509Signer (got %T)", rookerySig)
	}

	cert := x509Sig.Certificate()

	// Store the rookery signer for use in SignFulcio()
	s.fulcioX509Signer = x509Sig

	// Create a SPIFFE ID for the Fulcio-signed identity
	spiffeID, err := spiffeid.FromString("spiffe://aflock.ai/agent/keyless/fulcio")
	if err != nil {
		spiffeID = spiffeid.RequireFromString("spiffe://aflock.ai/agent/keyless/fulcio")
	}

	// Set identity with the Fulcio certificate (PrivateKey is nil — signing goes through rookery signer)
	s.identity = &identity.Identity{
		SPIFFEID:    spiffeID,
		Certificate: cert,
		TrustBundle: x509Sig.Intermediates(),
		ExpiresAt:   cert.NotAfter,
	}

	return nil
}

// signWithFulcio signs PAE data using the rookery Fulcio X509Signer.
// This is used when InitializeFulcio() was called instead of Initialize()/InitializeEphemeral().
func (s *Signer) signWithFulcio(pae []byte) ([]byte, error) {
	if s.fulcioX509Signer == nil {
		return nil, fmt.Errorf("fulcio signer not initialized")
	}
	return s.fulcioX509Signer.Sign(bytes.NewReader(pae))
}

// IsFulcioSigning returns true if the signer is using Fulcio keyless signing.
func (s *Signer) IsFulcioSigning() bool {
	return s.fulcioX509Signer != nil
}

// signFulcioEnvelope creates and signs a DSSE envelope using the Fulcio signer.
// This is a Fulcio-specific signing path because the rookery signer handles its own
// hashing (SHA256 digest inside ECDSASigner.Sign), unlike signWithPrivateKey which
// receives raw data.
func (s *Signer) signFulcioEnvelope(payloadType string, payload []byte) (*Envelope, error) {
	payloadB64 := base64.StdEncoding.EncodeToString(payload)
	pae := createPAE(payloadType, payload)

	sig, err := s.signWithFulcio(pae)
	if err != nil {
		return nil, fmt.Errorf("fulcio sign: %w", err)
	}

	var certPEM string
	if s.identity != nil && s.identity.Certificate != nil {
		certPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: s.identity.Certificate.Raw,
		}))
	}

	keyID := "fulcio-keyless"
	if s.identity != nil {
		keyID = s.identity.SPIFFEID.String()
	}

	return &Envelope{
		PayloadType: payloadType,
		Payload:     payloadB64,
		Signatures: []Signature{
			{
				KeyID:       keyID,
				Sig:         base64.StdEncoding.EncodeToString(sig),
				Certificate: certPEM,
			},
		},
	}, nil
}

// buildFulcioProvider constructs a FulcioSignerProvider from environment variables.
// Supports GitHub Actions OIDC, direct token, and token file.
func buildFulcioProvider() (fulcioSigner.FulcioSignerProvider, error) {
	fulcioURL := os.Getenv("FULCIO_URL")
	if fulcioURL == "" {
		fulcioURL = DefaultFulcioURL
	}

	opts := []fulcioSigner.Option{
		fulcioSigner.WithFulcioURL(fulcioURL),
	}

	// Check for available OIDC token sources
	switch {
	case os.Getenv("GITHUB_ACTIONS") == "true":
		// GitHub Actions: tokens are fetched automatically by the rookery plugin
	case os.Getenv("FULCIO_TOKEN") != "":
		opts = append(opts, fulcioSigner.WithToken(os.Getenv("FULCIO_TOKEN")))
	case os.Getenv("FULCIO_TOKEN_PATH") != "":
		opts = append(opts, fulcioSigner.WithTokenPath(os.Getenv("FULCIO_TOKEN_PATH")))
	default:
		return fulcioSigner.FulcioSignerProvider{}, fmt.Errorf(
			"no OIDC token source: set GITHUB_ACTIONS=true, FULCIO_TOKEN, or FULCIO_TOKEN_PATH")
	}

	if issuer := os.Getenv("FULCIO_OIDC_ISSUER"); issuer != "" {
		opts = append(opts, fulcioSigner.WithOidcIssuer(issuer))
	}
	if clientID := os.Getenv("FULCIO_OIDC_CLIENT_ID"); clientID != "" {
		opts = append(opts, fulcioSigner.WithOidcClientID(clientID))
	}

	return fulcioSigner.New(opts...), nil
}

// init validates compile-time interface compatibility.
func init() {
	var _ interface {
		Certificate() *x509.Certificate
		Intermediates() []*x509.Certificate
	} = (*cryptoutil.X509Signer)(nil)
}
