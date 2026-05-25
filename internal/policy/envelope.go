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

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	rdsse "github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policysig"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/sigstore/fulcio/pkg/certificate"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// PolicyPayloadType is the DSSE payloadType that signed aflock policies must
// declare. Used both to recognize envelopes on Load and to set on Sign.
const PolicyPayloadType = "application/vnd.aflock.policy+json"

// ErrUnsignedRequired is returned when AFLOCK_REQUIRE_SIGNED_POLICY=1 is set
// but the policy on disk is not wrapped in a DSSE envelope.
var ErrUnsignedRequired = errors.New("policy is unsigned but AFLOCK_REQUIRE_SIGNED_POLICY=1")

// isEnvelope detects whether data has DSSE envelope shape — i.e. the JSON
// object declares payloadType / payload / signatures keys. ANY envelope-shaped
// JSON triggers the verify-or-fail path. Restricting detection to
// PolicyPayloadType (or to non-empty values) would let an attacker feed e.g.
// an in-toto attestation envelope, or a crafted `{"payloadType":"",...}`,
// and have its envelope fields parsed as "unknown JSON fields" — leaving
// every aflock.Policy field zero-valued and silently producing an empty
// allow-most policy. Key presence, not value population, is the gate.
func isEnvelope(data []byte) bool {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return false
	}
	_, hasPayloadType := keys["payloadType"]
	_, hasPayload := keys["payload"]
	_, hasSignatures := keys["signatures"]
	return hasPayloadType && hasPayload && hasSignatures
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

	var lastErr error
	for _, v := range trust.Verifiers {
		switch v.Type {
		case "sigstore":
			payload, info, err := verifySigstore(ctx, env, v)
			if err != nil {
				lastErr = fmt.Errorf("verifier(type=sigstore, issuer=%s): %w", v.Issuer, err)
				continue
			}
			info.PayloadType = env.PayloadType
			return payload, info, nil

		case "pubkey":
			payload, info, err := verifyPubkey(ctx, env, v)
			if err != nil {
				lastErr = fmt.Errorf("verifier(type=pubkey, keyPath=%s): %w", v.KeyPath, err)
				continue
			}
			info.PayloadType = env.PayloadType
			return payload, info, nil
		}
	}

	if lastErr == nil {
		// No verifier in the trust config recognized a supported type — the
		// schema validator should normally catch this, but be explicit here too.
		return nil, nil, errors.New("no verifier in trust config matched the envelope (no supported types found)")
	}
	return nil, nil, lastErr
}

// verifySigstore verifies an envelope against a Fulcio-issued leaf cert,
// matching the cert's OIDC issuer + subject SAN against the trust config.
// Returns the unwrapped payload + signature metadata on success.
//
// The sigstore path requires exactly one signature in the envelope. With
// multiple signatures, the cert we extract for SignatureInfo might not be the
// one that satisfied verification — which would misreport the signer identity
// in audits/attestations. aflock sign always emits a single signature, so
// rejecting multi-sig envelopes here costs us nothing and keeps the audit
// record honest.
func verifySigstore(ctx context.Context, env rdsse.Envelope, v aflock.TrustedVerifier) ([]byte, *aflock.SignatureInfo, error) {
	if len(env.Signatures) != 1 {
		return nil, nil, fmt.Errorf("sigstore path requires exactly one signature, got %d", len(env.Signatures))
	}

	leafCert, err := extractLeafCert(env)
	if err != nil {
		return nil, nil, fmt.Errorf("extract leaf cert: %w", err)
	}

	roots, err := loadFulcioRoots(v.FulcioRootPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load fulcio roots: %w", err)
	}

	// Route the configured subject into either Emails or URIs based on its
	// shape. Fulcio puts human identities (Google/GitHub OIDC login) in the
	// SAN email field, and CI workflow identities (GitHub Actions, GitLab CI)
	// in the SAN URI field.
	emails := []string{"*"}
	uris := []string{"*"}
	if isEmail(v.SubjectPattern) {
		emails = []string{v.SubjectPattern}
	} else {
		uris = []string{v.SubjectPattern}
	}

	tsaVerifiers, err := loadTSAVerifiers()
	if err != nil {
		return nil, nil, fmt.Errorf("load tsa roots: %w", err)
	}

	opts := policysig.NewVerifyPolicySignatureOptions(
		policysig.VerifyWithPolicyCARoots(roots),
		policysig.VerifyWithPolicyTimestampAuthorities(tsaVerifiers),
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
		return nil, nil, err
	}

	return env.Payload, signatureInfoFromCert(leafCert), nil
}

// verifyPubkey verifies an envelope against a raw PEM-encoded public key on
// disk. No Fulcio cert chain, no TSA timestamp dance — raw keys don't expire
// the way Fulcio leaf certs do. The keyid in the envelope's signature is
// optionally matched against TrustedVerifier.KeyID to prevent loading the
// wrong key from disk.
func verifyPubkey(ctx context.Context, env rdsse.Envelope, v aflock.TrustedVerifier) ([]byte, *aflock.SignatureInfo, error) {
	f, err := os.Open(v.KeyPath) //nolint:gosec // G304: operator-controlled trust config path
	if err != nil {
		return nil, nil, fmt.Errorf("open public key: %w", err)
	}
	defer f.Close()

	verifier, err := cryptoutil.NewVerifierFromReader(f)
	if err != nil {
		return nil, nil, fmt.Errorf("parse public key: %w", err)
	}

	loadedKeyID, err := verifier.KeyID()
	if err != nil {
		return nil, nil, fmt.Errorf("compute keyid: %w", err)
	}

	if v.KeyID != "" && v.KeyID != loadedKeyID {
		return nil, nil, fmt.Errorf("keyid mismatch: trust config expects %q, loaded key is %q", v.KeyID, loadedKeyID)
	}

	if err := policysig.VerifyPolicySignature(
		ctx, env,
		policysig.NewVerifyPolicySignatureOptions(
			policysig.VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
		),
	); err != nil {
		return nil, nil, err
	}

	info := &aflock.SignatureInfo{
		Issuer:  "pubkey",
		Subject: loadedKeyID,
	}
	return env.Payload, info, nil
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
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter
	info := &aflock.SignatureInfo{
		CertNotBefore: &notBefore,
		CertNotAfter:  &notAfter,
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

// loadTSAVerifiers returns timestamp verifiers built from the embedded
// Sigstore TSA cert chain. A signed policy is expected to bundle an RFC 3161
// timestamp; the verifier uses the TSA-attested time when checking the Fulcio
// leaf cert's validity, so signatures stay verifiable past the cert's
// ~10-minute window.
func loadTSAVerifiers() ([]timestamp.TimestampVerifier, error) {
	certs, err := parsePEMCerts([]byte(SigstoreProductionTSACerts))
	if err != nil {
		return nil, fmt.Errorf("parse embedded TSA chain: %w", err)
	}
	return []timestamp.TimestampVerifier{timestamp.NewVerifier(timestamp.VerifyWithCerts(certs))}, nil
}

// parsePEMCerts decodes concatenated PEM-encoded certificates.
func parsePEMCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0)
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
			return nil, err
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates found in PEM bytes")
	}
	return out, nil
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
