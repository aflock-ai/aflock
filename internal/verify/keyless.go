// Package verify implements attestation verification against policy.
package verify

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/aflock-ai/aflock/pkg/aflock"
	"github.com/gobwas/glob"
)

// Fulcio certificate extension OIDs.
// See: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
var (
	oidFulcioIssuer             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidFulcioBuildSignerURI     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	oidFulcioBuildSignerDigest  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}
	oidFulcioRunnerEnvironment  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 10}
	oidFulcioBuildTrigger       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 11}
	oidFulcioSourceRepoURI      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}
	oidFulcioSourceRepoRef      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 14}
	oidFulcioSourceRepoOwnerURI = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 17}
)

// fulcioCertExtensions holds parsed Fulcio certificate extension values.
type fulcioCertExtensions struct {
	Issuer                   string
	BuildSignerURI           string
	BuildSignerDigest        string
	RunnerEnvironment        string
	BuildTrigger             string
	SourceRepositoryURI      string
	SourceRepositoryRef      string
	SourceRepositoryOwnerURI string
}

// matchesKeylessFunctionary checks if a certificate was issued by Fulcio with
// OIDC identity matching the functionary's issuer/subject/extension constraints.
func matchesKeylessFunctionary(cert *x509.Certificate, f aflock.StepFunctionary) bool {
	if cert == nil {
		return false
	}

	// Extract Fulcio OIDC issuer from certificate extensions
	extensions := extractFulcioExtensions(cert)

	// A keyless cert must have a Fulcio issuer extension to be considered valid.
	// Without this check, any non-Fulcio cert would match an empty-constraint keyless functionary.
	if extensions.Issuer == "" {
		return false
	}

	// Check issuer constraint (exact match)
	if f.Issuer != "" && extensions.Issuer != f.Issuer {
		return false
	}

	// Check subject constraint against cert SANs (email or URI)
	// Fulcio puts the OIDC subject in either:
	//   - Email SAN (for email-based OIDC like Google)
	//   - URI SAN (for workload identity like GitHub Actions)
	if f.Subject != "" {
		if !matchesCertSubject(cert, f.Subject) {
			return false
		}
	}

	// Check Fulcio-specific extension constraints if specified
	if f.FulcioExtensions != nil {
		if !matchesFulcioExtensions(extensions, f.FulcioExtensions) {
			return false
		}
	}

	return true
}

// extractFulcioExtensions parses Fulcio-specific OIDs from X.509 certificate extensions.
// Fulcio v2 encodes values as ASN.1 UTF8String; v1 used raw bytes. We handle both.
func extractFulcioExtensions(cert *x509.Certificate) *fulcioCertExtensions {
	ext := &fulcioCertExtensions{}
	for _, e := range cert.Extensions {
		val := extractExtensionString(e)
		switch {
		case e.Id.Equal(oidFulcioIssuer):
			ext.Issuer = val
		case e.Id.Equal(oidFulcioBuildSignerURI):
			ext.BuildSignerURI = val
		case e.Id.Equal(oidFulcioBuildSignerDigest):
			ext.BuildSignerDigest = val
		case e.Id.Equal(oidFulcioRunnerEnvironment):
			ext.RunnerEnvironment = val
		case e.Id.Equal(oidFulcioBuildTrigger):
			ext.BuildTrigger = val
		case e.Id.Equal(oidFulcioSourceRepoURI):
			ext.SourceRepositoryURI = val
		case e.Id.Equal(oidFulcioSourceRepoRef):
			ext.SourceRepositoryRef = val
		case e.Id.Equal(oidFulcioSourceRepoOwnerURI):
			ext.SourceRepositoryOwnerURI = val
		}
	}
	return ext
}

// extractExtensionString tries ASN.1 UTF8String decoding, falls back to raw bytes.
func extractExtensionString(ext pkix.Extension) string {
	var utf8Val string
	rest, err := asn1.Unmarshal(ext.Value, &utf8Val)
	if err == nil && len(rest) == 0 {
		return utf8Val
	}
	return string(ext.Value)
}

// matchesCertSubject checks if any email or URI SAN matches the given pattern.
// Uses gobwas/glob for matching (same library as rookery), which supports * across path separators.
func matchesCertSubject(cert *x509.Certificate, pattern string) bool {
	g, err := glob.Compile(pattern)
	if err != nil {
		return false
	}
	for _, email := range cert.EmailAddresses {
		if g.Match(email) {
			return true
		}
	}
	for _, u := range cert.URIs {
		if g.Match(u.String()) {
			return true
		}
	}
	return false
}

// matchesFulcioExtensions checks Fulcio certificate extensions against constraints.
// All non-empty constraint fields must match (AND logic). Supports glob patterns.
func matchesFulcioExtensions(actual *fulcioCertExtensions, expected *aflock.FulcioExtensions) bool {
	checks := []struct {
		constraint string
		value      string
	}{
		{expected.Issuer, actual.Issuer},
		{expected.BuildTrigger, actual.BuildTrigger},
		{expected.SourceRepositoryURI, actual.SourceRepositoryURI},
		{expected.SourceRepositoryRef, actual.SourceRepositoryRef},
		{expected.SourceRepositoryOwnerURI, actual.SourceRepositoryOwnerURI},
		{expected.RunnerEnvironment, actual.RunnerEnvironment},
		{expected.BuildSignerURI, actual.BuildSignerURI},
		{expected.BuildSignerDigest, actual.BuildSignerDigest},
	}

	for _, c := range checks {
		if c.constraint == "" {
			continue
		}
		g, err := glob.Compile(c.constraint)
		if err != nil {
			return false
		}
		if !g.Match(c.value) {
			return false
		}
	}
	return true
}

// hasKeylessFunctionary checks if any step in the policy uses keyless functionaries.
func hasKeylessFunctionary(pol *aflock.Policy) bool {
	for _, step := range pol.Steps {
		for _, f := range step.Functionaries {
			if f.Type == "keyless" {
				return true
			}
		}
	}
	return false
}

// Sigstore public good Fulcio root CA certificate (v3, active since 2024).
// This is the trust anchor for Sigstore's public Fulcio instance.
// Source: https://github.com/sigstore/root-signing - fulcio_v1.crt.pem
// Note: The v1 root is ECDSA P-384. Older Go versions may have issues with P-384
// point validation. If loadFulcioRoot() fails, consider using the TUF client.
//
// For production, policies should specify their own roots via the Roots field.
// This embedded root is a convenience for the Sigstore public good instance.
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

// loadFulcioRoot returns the Sigstore public Fulcio root CA certificate.
func loadFulcioRoot() (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(fulcioPublicRootPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode Fulcio root PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Fulcio root certificate: %w", err)
	}
	return cert, nil
}
