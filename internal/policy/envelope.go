package policy

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	rdsse "github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policysig"
	"github.com/sigstore/fulcio/pkg/certificate"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// PolicyPayloadType is the DSSE payloadType that signed aflock policies must
// declare. Used both to recognize envelopes on Load and to set on Sign.
const PolicyPayloadType = "application/vnd.aflock.policy+json"

// ErrUnsignedRequired is returned when AFLOCK_REQUIRE_SIGNED_POLICY=1 is set
// but the policy on disk is not wrapped in a DSSE envelope.
var ErrUnsignedRequired = errors.New("policy is unsigned but AFLOCK_REQUIRE_SIGNED_POLICY=1")

// isEnvelope detects whether data has DSSE envelope shape — i.e. a non-empty
// payloadType + payload + signatures key. ANY envelope-shaped JSON triggers
// the verify-or-fail path. Restricting detection to PolicyPayloadType would
// let an attacker feed e.g. an in-toto attestation envelope as a policy and
// have its envelope fields (PayloadType, Payload, Signatures) parsed as
// "unknown JSON fields" — leaving every aflock.Policy field zero-valued and
// silently producing an empty allow-most policy.
func isEnvelope(data []byte) bool {
	var peek struct {
		PayloadType string            `json:"payloadType"`
		Payload     string            `json:"payload"`
		Signatures  []json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(data, &peek); err != nil {
		return false
	}
	return peek.PayloadType != "" && peek.Payload != "" && peek.Signatures != nil
}

// verifyAndUnwrap validates a DSSE envelope against the trust config and
// returns the inner policy bytes plus signature metadata. Returns an error
// rather than fall back to raw parsing — once an envelope shape is detected,
// the only safe outcomes are verified-success or hard-fail. Falling back on
// verification failure would be a silent downgrade attack vector.
func verifyAndUnwrap(ctx context.Context, envelopeBytes []byte, trust *aflock.TrustConfig) ([]byte, *aflock.SignatureInfo, error) {
	var env rdsse.Envelope
	if err := json.Unmarshal(envelopeBytes, &env); err != nil {
		return nil, nil, fmt.Errorf("parse DSSE envelope: %w", err)
	}

	if env.PayloadType != PolicyPayloadType {
		return nil, nil, fmt.Errorf("unexpected payload type %q (want %q)", env.PayloadType, PolicyPayloadType)
	}

	if len(env.Signatures) == 0 {
		return nil, nil, errors.New("envelope has no signatures")
	}

	leafCert, err := extractLeafCert(env)
	if err != nil {
		return nil, nil, fmt.Errorf("extract leaf cert: %w", err)
	}

	var lastErr error
	for _, v := range trust.Verifiers {
		if v.Type != "sigstore" {
			continue
		}

		roots, err := loadFulcioRoots(v.FulcioRootPath)
		if err != nil {
			lastErr = fmt.Errorf("verifier(issuer=%s): load fulcio roots: %w", v.Issuer, err)
			continue
		}

		// Route the configured subject into either Emails or URIs based on its
		// shape. Fulcio puts human identities (Google/GitHub OIDC login) in the
		// SAN email field, and CI workflow identities (GitHub Actions, GitLab
		// CI) in the SAN URI field. We can't put the same string into both
		// constraint slices because rookery's checkCertConstraint requires that
		// constraints and values match 1:1 — a cert with only an email will
		// fail a non-empty URI constraint and vice versa.
		emails := []string{"*"}
		uris := []string{"*"}
		if isEmail(v.SubjectPattern) {
			emails = []string{v.SubjectPattern}
		} else {
			uris = []string{v.SubjectPattern}
		}

		opts := policysig.NewVerifyPolicySignatureOptions(
			policysig.VerifyWithPolicyCARoots(roots),
			policysig.VerifyWithPolicyCertConstraints(
				"*",           // commonName
				[]string{"*"}, // dnsNames
				emails,
				[]string{"*"}, // organizations
				uris,
			),
			policysig.VerifyWithPolicyFulcioCertExtensions(certificate.Extensions{
				Issuer: v.Issuer,
			}),
		)

		if err := policysig.VerifyPolicySignature(ctx, env, opts); err != nil {
			lastErr = fmt.Errorf("verifier(issuer=%s): %w", v.Issuer, err)
			continue
		}

		// Verification passed. Build SignatureInfo from the leaf cert we already
		// parsed above (policysig.VerifyPolicySignature only returns error, not
		// the cert it verified — but the cert is fixed by the envelope so this
		// is sound).
		info := signatureInfoFromCert(leafCert)
		info.PayloadType = env.PayloadType
		return env.Payload, info, nil
	}

	if lastErr == nil {
		return nil, nil, errors.New("no sigstore verifier in trust config matched the envelope")
	}
	return nil, nil, lastErr
}

// extractLeafCert pulls the first embedded leaf certificate out of a DSSE
// envelope's signatures. Fulcio-signed policies always embed the short-lived
// cert here so verifiers can chain it without an external lookup.
func extractLeafCert(env rdsse.Envelope) (*x509.Certificate, error) {
	for _, sig := range env.Signatures {
		if len(sig.Certificate) == 0 {
			continue
		}
		block, _ := pem.Decode(sig.Certificate)
		if block == nil {
			return nil, errors.New("signature.certificate is not PEM-encoded")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse leaf cert: %w", err)
		}
		return cert, nil
	}
	return nil, errors.New("no embedded leaf certificate in envelope signatures")
}

// signatureInfoFromCert extracts the identity fields we surface in attestations
// from a verified Fulcio leaf cert. Fulcio embeds the OIDC issuer in OID
// 1.3.6.1.4.1.57264.1.1 (parsed by sigstore/fulcio/pkg/certificate) and the
// signing identity in the SAN URI (or email for human identities).
func signatureInfoFromCert(cert *x509.Certificate) *aflock.SignatureInfo {
	info := &aflock.SignatureInfo{
		CertNotBefore: cert.NotBefore,
		CertNotAfter:  cert.NotAfter,
	}

	if ext, err := certificate.ParseExtensions(cert.Extensions); err == nil {
		info.Issuer = ext.Issuer
		// Prefer the explicit BuildSignerURI extension (set for CI workflow
		// identities); fall back to issuer V2 extension; finally fall back to
		// SAN URI/email so human identities still produce a non-empty Subject.
		if ext.BuildSignerURI != "" {
			info.Subject = ext.BuildSignerURI
		}
	}

	if info.Subject == "" {
		if len(cert.URIs) > 0 {
			info.Subject = cert.URIs[0].String()
		} else if len(cert.EmailAddresses) > 0 {
			info.Subject = cert.EmailAddresses[0]
		}
	}

	return info
}

// isEmail returns true for subject patterns that should be matched against the
// cert's SAN email field rather than its SAN URI field. We use a simple
// heuristic: contains "@" and no URI scheme. Globs like "*@gmail.com" count as
// emails too — though note that rookery's slice-constraint matcher does exact
// match only on these fields, so glob support here only matters for forward
// compat with a future hardened verifier.
func isEmail(subject string) bool {
	if strings.Contains(subject, "://") {
		return false
	}
	return strings.Contains(subject, "@")
}

// loadFulcioRoots returns the Fulcio root cert(s) to chain against. When path
// is empty, the embedded Sigstore production root is used. Self-hosted Sigstore
// deployments point at their own root via TrustedVerifier.FulcioRootPath.
func loadFulcioRoots(path string) ([]*x509.Certificate, error) {
	var pemBytes []byte
	if path == "" {
		pemBytes = []byte(SigstoreProductionFulcioRoot)
	} else {
		data, err := os.ReadFile(path) //nolint:gosec // G304: operator-controlled trust config
		if err != nil {
			return nil, fmt.Errorf("read fulcio root %s: %w", path, err)
		}
		pemBytes = data
	}

	roots := make([]*x509.Certificate, 0, 1)
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse fulcio root: %w", err)
		}
		roots = append(roots, cert)
	}

	if len(roots) == 0 {
		return nil, errors.New("no certificates found in fulcio root PEM")
	}
	return roots, nil
}
