package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	rdsse "github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	fulcioSigner "github.com/aflock-ai/rookery/plugins/signers/fulcio"
)

// DefaultFulcioURL is the Sigstore public good Fulcio instance. Override via
// $FULCIO_URL for self-hosted Sigstore deployments.
const DefaultFulcioURL = "https://fulcio.sigstore.dev"

// SignWithFulcio wraps policyBytes in a DSSE envelope signed by an ephemeral
// Fulcio-issued keypair bound to the caller's OIDC identity. Returns the
// envelope as JSON suitable for writing as a .signed file.
//
// OIDC token source resolution:
//   - GITHUB_ACTIONS=true: tokens fetched automatically (workflow needs id-token: write)
//   - $FULCIO_TOKEN: literal token (for testing or out-of-band CI)
//   - $FULCIO_TOKEN_PATH: token read from file
//
// Caveats:
//   - The Fulcio cert in the produced envelope is ~10 min valid. Without a TSA
//     or Rekor SET (not yet wired — follow-up), verifiers using time.Now() will
//     reject after expiry. Re-sign close to verification, or sign in CI on
//     every policy change.
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

	envelope, err := rdsse.Sign(
		PolicyPayloadType,
		bytes.NewReader(policyBytes),
		rdsse.SignWithSigners(signer),
	)
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

	switch {
	case os.Getenv("GITHUB_ACTIONS") == "true":
		// tokens fetched automatically by the rookery plugin
	case os.Getenv("FULCIO_TOKEN") != "":
		opts = append(opts, fulcioSigner.WithToken(os.Getenv("FULCIO_TOKEN")))
	case os.Getenv("FULCIO_TOKEN_PATH") != "":
		opts = append(opts, fulcioSigner.WithTokenPath(os.Getenv("FULCIO_TOKEN_PATH")))
	default:
		return fulcioSigner.FulcioSignerProvider{}, errors.New(
			"no OIDC token source: set GITHUB_ACTIONS=true (in CI), FULCIO_TOKEN, or FULCIO_TOKEN_PATH")
	}

	if issuer := os.Getenv("FULCIO_OIDC_ISSUER"); issuer != "" {
		opts = append(opts, fulcioSigner.WithOidcIssuer(issuer))
	}
	if clientID := os.Getenv("FULCIO_OIDC_CLIENT_ID"); clientID != "" {
		opts = append(opts, fulcioSigner.WithOidcClientID(clientID))
	}

	return fulcioSigner.New(opts...), nil
}
