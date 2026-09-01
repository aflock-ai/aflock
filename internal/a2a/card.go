// Package a2a implements verification of signed A2A AgentCards and the
// peer-principal taxonomy used by the agents policy section.
//
// Wire format: the sigstore-a2a signed card layout — a JSON document
//
//	{"agentCard": {...}, "attestations": {"signatureBundle": <sigstore bundle v0.3>}}
//
// where the bundle's dsseEnvelope wraps an in-toto Statement whose predicate
// type is PredicateTypeAgentCard and whose subject digest is the SHA-256 of
// the RFC 8785 (JCS) canonicalization of the agentCard object, and whose
// signing certificate is a Fulcio leaf embedded in
// verificationMaterial.certificate.rawBytes.
//
// Principal taxonomy (mirrors the Pushgate/judge agent-principal model —
// "the SAN type is the assertion"):
//   - a URI SAN with scheme spiffe://  → PrincipalAgent
//   - an email SAN                     → PrincipalHuman
//   - any other URI SAN                → PrincipalWorkflow
//
// A leaf carrying both an email SAN and a URI SAN claims two principals and
// is refused outright.
//
// Current limitation (Phase 1): the certificate chain is validated against
// the trust roots, but Rekor transparency-log inclusion and RFC 3161
// timestamps in the bundle are not yet verified — chain validity is checked
// at the certificate's own NotBefore instant, so an expired-but-once-valid
// Fulcio leaf still verifies. Signature-time proof is roadmap.
package a2a

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/aflock-ai/aflock/pkg/aflock"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/gobwas/glob"
)

// PredicateTypeAgentCard is the in-toto predicate type sigstore-a2a signs.
const PredicateTypeAgentCard = "https://a2a.openwallet.dev/agentcard/v1"

// Principal kinds — who signed the card, structurally.
const (
	PrincipalAgent    = "agent"
	PrincipalHuman    = "human"
	PrincipalWorkflow = "workflow"
)

// oidFulcioIssuer is the Fulcio OIDC issuer certificate extension.
var oidFulcioIssuer = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}

// Principal is the identity that signed an AgentCard, parsed from the leaf
// certificate's SANs. Kind is one of the Principal* constants.
type Principal struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`               // SPIFFE URI, email, or workflow URI
	Issuer string `json:"issuer,omitempty"` // Fulcio OIDC issuer extension, if present
}

// Result is a successfully verified signed AgentCard.
type Result struct {
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	Version    string    `json:"version,omitempty"`
	Principal  Principal `json:"principal"`
	CardDigest string    `json:"cardDigest"` // hex SHA-256 of the JCS-canonical card
}

// Options constrain verification.
type Options struct {
	// Roots are the trust anchors for the signing certificate chain. When
	// empty, the embedded Sigstore public-good Fulcio root is used.
	Roots []*x509.Certificate
	// Issuers, when non-empty, are glob patterns the leaf's Fulcio OIDC
	// issuer extension must match.
	Issuers []string
}

// --- wire structures (both camelCase and snake_case accepted) ---

type signedCardWire struct {
	AgentCard      json.RawMessage `json:"agentCard"`
	AgentCardSnake json.RawMessage `json:"agent_card"`
	Attestations   struct {
		SignatureBundle      json.RawMessage `json:"signatureBundle"`
		SignatureBundleSnake json.RawMessage `json:"signature_bundle"`
	} `json:"attestations"`
}

type bundleWire struct {
	VerificationMaterial struct {
		Certificate struct {
			RawBytes []byte `json:"rawBytes"`
		} `json:"certificate"`
		X509CertificateChain struct {
			Certificates []struct {
				RawBytes []byte `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"x509CertificateChain"`
	} `json:"verificationMaterial"`
	DSSEEnvelope struct {
		Payload     []byte `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Sig []byte `json:"sig"`
		} `json:"signatures"`
	} `json:"dsseEnvelope"`
}

type statementWire struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
}

type agentCardMeta struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Version string `json:"version"`
}

// VerifySignedCard verifies a signed AgentCard document and returns the
// card metadata plus the signing principal. Every returned error means the
// card must be treated as unverified.
func VerifySignedCard(data []byte, opts Options) (*Result, error) {
	var wire signedCardWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("parse signed card: %w", err)
	}
	card := wire.AgentCard
	if len(card) == 0 {
		card = wire.AgentCardSnake
	}
	if len(card) == 0 {
		return nil, fmt.Errorf("signed card has no agentCard field")
	}
	bundleRaw := wire.Attestations.SignatureBundle
	if len(bundleRaw) == 0 {
		bundleRaw = wire.Attestations.SignatureBundleSnake
	}
	if len(bundleRaw) == 0 {
		return nil, fmt.Errorf("signed card has no attestations.signatureBundle")
	}

	var bundle bundleWire
	if err := json.Unmarshal(bundleRaw, &bundle); err != nil {
		return nil, fmt.Errorf("parse signature bundle: %w", err)
	}

	// Leaf certificate: bundle v0.3 uses verificationMaterial.certificate;
	// older bundles carry an x509CertificateChain.
	certDER := bundle.VerificationMaterial.Certificate.RawBytes
	if len(certDER) == 0 && len(bundle.VerificationMaterial.X509CertificateChain.Certificates) > 0 {
		certDER = bundle.VerificationMaterial.X509CertificateChain.Certificates[0].RawBytes
	}
	if len(certDER) == 0 {
		return nil, fmt.Errorf("signature bundle has no signing certificate")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse signing certificate: %w", err)
	}

	env := bundle.DSSEEnvelope
	if env.PayloadType != "application/vnd.in-toto+json" {
		return nil, fmt.Errorf("unexpected DSSE payload type %q", env.PayloadType)
	}
	if len(env.Payload) == 0 || len(env.Signatures) == 0 {
		return nil, fmt.Errorf("signature bundle has empty DSSE envelope")
	}

	// 1 — DSSE signature over the PAE, with the leaf's public key.
	pae := dssePAE(env.PayloadType, env.Payload)
	sigOK := false
	for _, s := range env.Signatures {
		if verifySignature(cert.PublicKey, pae, s.Sig) {
			sigOK = true
			break
		}
	}
	if !sigOK {
		return nil, fmt.Errorf("DSSE signature does not verify with the embedded certificate")
	}

	// 2 — chain to the trust roots. Rekor/TSA signature-time proof is not
	// yet checked (see package comment), so chain validity is evaluated at
	// the leaf's own NotBefore instant rather than time.Now().
	roots := opts.Roots
	if len(roots) == 0 {
		fulcio, rootErr := fulcioPublicRoot()
		if rootErr != nil {
			return nil, rootErr
		}
		roots = []*x509.Certificate{fulcio}
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: cert.NotBefore.Add(1),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("signing certificate does not chain to a trusted root: %w", err)
	}

	// 3 — the statement must bind THIS card: subject digest == SHA-256 of
	// the JCS-canonical agentCard, and the predicate type must match.
	var stmt statementWire
	if err := json.Unmarshal(env.Payload, &stmt); err != nil {
		return nil, fmt.Errorf("parse in-toto statement: %w", err)
	}
	if stmt.PredicateType != PredicateTypeAgentCard {
		return nil, fmt.Errorf("unexpected predicate type %q (want %s)", stmt.PredicateType, PredicateTypeAgentCard)
	}
	canonical, err := jsoncanonicalizer.Transform(card)
	if err != nil {
		return nil, fmt.Errorf("canonicalize agent card: %w", err)
	}
	digest := sha256.Sum256(canonical)
	digestHex := hex.EncodeToString(digest[:])
	digestOK := false
	for _, sub := range stmt.Subject {
		if strings.EqualFold(sub.Digest["sha256"], digestHex) {
			digestOK = true
			break
		}
	}
	if !digestOK {
		return nil, fmt.Errorf("agent card does not match the signed statement's subject digest (card tampered?)")
	}

	// 4 — principal extraction + issuer constraint.
	principal, err := CertPrincipal(cert)
	if err != nil {
		return nil, err
	}
	if len(opts.Issuers) > 0 && !matchAnyGlob(opts.Issuers, principal.Issuer) {
		return nil, fmt.Errorf("card signer's OIDC issuer %q not in allowed issuers", principal.Issuer)
	}

	var meta agentCardMeta
	if err := json.Unmarshal(card, &meta); err != nil {
		return nil, fmt.Errorf("parse agent card fields: %w", err)
	}

	return &Result{
		Name:       meta.Name,
		URL:        meta.URL,
		Version:    meta.Version,
		Principal:  principal,
		CardDigest: digestHex,
	}, nil
}

// CertPrincipal parses the signing principal from a leaf certificate's SANs.
// One principal per leaf: a certificate carrying both an email SAN and a URI
// SAN is refused — verification never guesses which identity was meant.
func CertPrincipal(cert *x509.Certificate) (Principal, error) {
	p := Principal{Issuer: fulcioIssuer(cert)}

	if len(cert.EmailAddresses) > 0 && len(cert.URIs) > 0 {
		return p, fmt.Errorf("certificate claims two principals (email SAN and URI SAN) — refused")
	}

	switch {
	case len(cert.URIs) > 0:
		uri := cert.URIs[0].String()
		if strings.HasPrefix(uri, "spiffe://") {
			p.Kind = PrincipalAgent
		} else {
			p.Kind = PrincipalWorkflow
		}
		p.ID = uri
	case len(cert.EmailAddresses) > 0:
		p.Kind = PrincipalHuman
		p.ID = cert.EmailAddresses[0]
	default:
		return p, fmt.Errorf("certificate carries no principal SAN (no email, no URI)")
	}
	return p, nil
}

// MatchIdentity reports whether the principal matches any of the patterns.
// A pattern may be prefixed with a kind — "agent:", "human:", "workflow:" —
// which must then equal the principal's kind; the remainder (or the whole
// unprefixed pattern) is a glob matched against the principal's ID.
func (p Principal) MatchIdentity(patterns []string) bool {
	for _, pattern := range patterns {
		id := pattern
		if kind, rest, ok := strings.Cut(pattern, ":"); ok {
			switch kind {
			case PrincipalAgent, PrincipalHuman, PrincipalWorkflow:
				if p.Kind != kind {
					continue
				}
				id = rest
			}
		}
		if g, err := glob.Compile(id); err == nil && g.Match(p.ID) {
			return true
		}
	}
	return false
}

// LoadRoots resolves aflock policy roots (file path, inline PEM, or base64
// DER) into certificates. Relative paths resolve against baseDir.
func LoadRoots(roots map[string]aflock.Root, baseDir string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for name, root := range roots {
		val := root.Certificate
		if val == "" {
			continue
		}
		var der []byte
		switch {
		case strings.Contains(val, "-----BEGIN"):
			block, _ := pem.Decode([]byte(val))
			if block == nil {
				return nil, fmt.Errorf("root %q: invalid PEM", name)
			}
			der = block.Bytes
		default:
			path := val
			if !strings.HasPrefix(path, "/") && baseDir != "" {
				path = baseDir + "/" + path
			}
			if data, err := os.ReadFile(path); err == nil { //nolint:gosec // G304: path from operator-authored policy
				block, _ := pem.Decode(data)
				if block == nil {
					return nil, fmt.Errorf("root %q: file %s is not PEM", name, path)
				}
				der = block.Bytes
			} else if decoded, b64Err := base64.StdEncoding.DecodeString(val); b64Err == nil {
				der = decoded
			} else {
				return nil, fmt.Errorf("root %q: not a readable file, PEM, or base64: %v", name, err)
			}
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("root %q: parse certificate: %w", name, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// --- internals ---

// dssePAE builds the DSSE v1 pre-authentication encoding.
func dssePAE(payloadType string, payload []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
}

func verifySignature(pub crypto.PublicKey, message, sig []byte) bool {
	digest := sha256.Sum256(message)
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, digest[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(key, message, sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) == nil
	default:
		return false
	}
}

func fulcioIssuer(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidFulcioIssuer) {
			return extensionString(ext)
		}
	}
	return ""
}

func extensionString(ext pkix.Extension) string {
	var utf8Val string
	rest, err := asn1.Unmarshal(ext.Value, &utf8Val)
	if err == nil && len(rest) == 0 {
		return utf8Val
	}
	return string(ext.Value)
}

func matchAnyGlob(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if g, err := glob.Compile(pattern); err == nil && g.Match(value) {
			return true
		}
	}
	return false
}

// fulcioPublicRootPEM is the Sigstore public-good Fulcio root CA (same
// anchor embedded in internal/verify for keyless functionaries).
const fulcioPublicRootPEM = `-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpGangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----`

func fulcioPublicRoot() (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(fulcioPublicRootPEM))
	if block == nil {
		return nil, fmt.Errorf("decode embedded Fulcio root PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
