package policy

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	rdsse "github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	fulcioSigner "github.com/aflock-ai/rookery/plugins/signers/fulcio"
)

// DefaultFulcioURL is the Sigstore public good Fulcio instance. Override via
// $FULCIO_URL for self-hosted Sigstore deployments.
const DefaultFulcioURL = "https://fulcio.sigstore.dev"

// SignWithKey wraps policyBytes in a DSSE envelope signed by a PEM-encoded
// private key on disk. ECDSA, RSA, and Ed25519 are accepted (rookery dispatches
// on the parsed type). Use this when Fulcio isn't an option — air-gapped CI,
// no OIDC IdP, or self-hosted Sigstore without a Fulcio deployment. No TSA
// timestamp is bundled because raw keys don't have the 10-minute validity
// window Fulcio leaf certs have.
//
// Operators are responsible for key management (generation, distribution,
// rotation, protection). If you can use Fulcio, prefer SignWithFulcio.
func SignWithKey(_ context.Context, keyPath string, policyBytes []byte) ([]byte, error) {
	f, err := os.Open(keyPath) //nolint:gosec // G304: operator-controlled CLI flag
	if err != nil {
		return nil, fmt.Errorf("open private key: %w", err)
	}
	defer f.Close()

	signer, err := cryptoutil.NewSignerFromReader(f)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	envelope, err := rdsse.Sign(PolicyPayloadType, bytes.NewReader(policyBytes), rdsse.SignWithSigners(signer))
	if err != nil {
		return nil, fmt.Errorf("dsse sign: %w", err)
	}

	out, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return out, nil
}

// SignWithFulcio wraps policyBytes in a DSSE envelope signed by an ephemeral
// Fulcio-issued keypair bound to the caller's OIDC identity, and bundles an
// RFC 3161 timestamp from the Sigstore TSA so verifiers using time.Now()
// don't reject after the Fulcio cert's ~10-minute validity window.
//
// OIDC token source resolution:
//   - GITHUB_ACTIONS=true: tokens fetched automatically (workflow needs id-token: write)
//   - $FULCIO_TOKEN: literal token (for testing or out-of-band CI)
//   - $FULCIO_TOKEN_PATH: token read from file
//   - $FULCIO_OIDC_ISSUER: interactive browser OAuth (local dev)
//
// TSA configuration:
//   - $AFLOCK_TSA_URL: override the Sigstore production TSA endpoint
//   - $AFLOCK_TSA_DISABLE=1: skip timestamping (signature stops verifying
//     after Fulcio cert expiry; only useful for air-gapped tests)
//
// Requires network reach to both Fulcio and the TSA at sign time. Verify time
// is offline once the envelope is in hand.
func SignWithFulcio(ctx context.Context, policyBytes []byte) ([]byte, error) {
	provider, err := buildPolicyFulcioProvider()
	if err != nil {
		return nil, err
	}

	signer, err := provider.Signer(ctx)
	if err != nil {
		return nil, fmt.Errorf("fulcio signing: %w", err)
	}

	// Sanity-check that we got an X509 signer with an embedded cert — that's
	// what verifiers chain against. Falling back to raw-key signing would
	// produce an envelope that no Sigstore-aware verifier can validate.
	if _, ok := signer.(*cryptoutil.X509Signer); !ok {
		return nil, fmt.Errorf("fulcio signer is not an X509Signer (got %T)", signer)
	}

	signOpts := []rdsse.SignOption{rdsse.SignWithSigners(signer)}
	if os.Getenv("AFLOCK_TSA_DISABLE") != "1" {
		tsaURL := os.Getenv("AFLOCK_TSA_URL")
		if tsaURL == "" {
			tsaURL = DefaultSigstoreTSAURL
		}
		tsa := timestamp.NewTimestamper(
			timestamp.TimestampWithUrl(tsaURL),
			timestamp.TimestampWithHash(crypto.SHA256),
		)
		signOpts = append(signOpts, rdsse.SignWithTimestampers(tsa))
	}

	envelope, err := rdsse.Sign(PolicyPayloadType, bytes.NewReader(policyBytes), signOpts...)
	if err != nil {
		return nil, fmt.Errorf("dsse sign: %w", err)
	}

	out, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return out, nil
}

// buildPolicyFulcioProvider mirrors internal/attestation/fulcio.go's env-driven
// configuration so the same OIDC token sources work for policy signing and
// attestation signing. Kept here (not imported from attestation/) because
// importing attestation into policy would invert the existing dependency
// direction.
func buildPolicyFulcioProvider() (fulcioSigner.FulcioSignerProvider, error) {
	fulcioURL := os.Getenv("FULCIO_URL")
	if fulcioURL == "" {
		fulcioURL = DefaultFulcioURL
	}

	opts := []fulcioSigner.Option{
		fulcioSigner.WithFulcioURL(fulcioURL),
	}

	if issuer := os.Getenv("FULCIO_OIDC_ISSUER"); issuer != "" {
		opts = append(opts, fulcioSigner.WithOidcIssuer(issuer))
	}
	if clientID := os.Getenv("FULCIO_OIDC_CLIENT_ID"); clientID != "" {
		opts = append(opts, fulcioSigner.WithOidcClientID(clientID))
	}

	switch {
	case os.Getenv("GITHUB_ACTIONS") == "true":
		// tokens fetched automatically by the rookery plugin
	case os.Getenv("FULCIO_TOKEN") != "":
		opts = append(opts, fulcioSigner.WithToken(os.Getenv("FULCIO_TOKEN")))
	case os.Getenv("FULCIO_TOKEN_PATH") != "":
		opts = append(opts, fulcioSigner.WithTokenPath(os.Getenv("FULCIO_TOKEN_PATH")))
	case os.Getenv("FULCIO_OIDC_ISSUER") != "":
		// Interactive OAuth: rookery opens a browser and listens on localhost
		// for the OIDC callback. Useful for local dev/testing. Set both
		// FULCIO_OIDC_ISSUER (e.g. https://oauth2.sigstore.dev/auth) and
		// FULCIO_OIDC_CLIENT_ID (e.g. sigstore).
	default:
		return fulcioSigner.FulcioSignerProvider{}, errors.New(
			"no OIDC token source: set GITHUB_ACTIONS=true (CI), FULCIO_TOKEN, FULCIO_TOKEN_PATH, or FULCIO_OIDC_ISSUER (interactive browser)")
	}

	return fulcioSigner.New(opts...), nil
}
