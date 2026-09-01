package a2a

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"maps"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// --- fixture helpers -------------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "a2a-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

type leafOpts struct {
	uris   []string
	emails []string
	issuer string
}

func (ca *testCA) newLeaf(t *testing.T, opts leafOpts) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(2),
		Subject:        pkix.Name{},
		NotBefore:      time.Now().Add(-time.Minute),
		NotAfter:       time.Now().Add(10 * time.Minute),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		EmailAddresses: opts.emails,
	}
	for _, u := range opts.uris {
		parsed, parseErr := url.Parse(u)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	if opts.issuer != "" {
		val, marshalErr := asn1.MarshalWithParams(opts.issuer, "utf8")
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidFulcioIssuer, Value: val})
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

var testCard = map[string]any{
	"protocolVersion": "0.2.9",
	"name":            "Test Triage Agent",
	"url":             "https://agents.partner.example/a2a/v1",
	"version":         "1.0.0",
}

// signCard assembles a sigstore-a2a-shaped signed card for testCard.
func signCard(t *testing.T, ca *testCA, opts leafOpts, mutate func(card map[string]any)) []byte {
	t.Helper()
	cert, key := ca.newLeaf(t, opts)

	card := map[string]any{}
	maps.Copy(card, testCard)
	if mutate != nil {
		mutate(card)
	}
	cardJSON, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jsoncanonicalizer.Transform(cardJSON)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)

	statement := map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]any{{
			"name":   card["name"],
			"digest": map[string]string{"sha256": hex.EncodeToString(digest[:])},
		}},
		"predicateType": PredicateTypeAgentCard,
		"predicate":     card,
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}

	pae := dssePAE("application/vnd.in-toto+json", payload)
	paeDigest := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, key, paeDigest[:])
	if err != nil {
		t.Fatal(err)
	}

	signed := map[string]any{
		"agentCard": card,
		"attestations": map[string]any{
			"signatureBundle": map[string]any{
				"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
				"verificationMaterial": map[string]any{
					"certificate": map[string]any{"rawBytes": cert.Raw},
				},
				"dsseEnvelope": map[string]any{
					"payload":     payload,
					"payloadType": "application/vnd.in-toto+json",
					"signatures":  []map[string]any{{"sig": sig}},
				},
			},
		},
	}
	out, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// --- tests -----------------------------------------------------------------

func TestVerifySignedCard_AgentPrincipal(t *testing.T) {
	ca := newTestCA(t)
	data := signCard(t, ca, leafOpts{
		uris:   []string{"spiffe://judge.testifysec.com/tenant/acme/agent/a1"},
		issuer: "https://issuer.test.dev",
	}, nil)

	res, err := VerifySignedCard(data, Options{Roots: []*x509.Certificate{ca.cert}})
	if err != nil {
		t.Fatalf("VerifySignedCard: %v", err)
	}
	if res.Principal.Kind != PrincipalAgent {
		t.Errorf("Kind = %q, want agent", res.Principal.Kind)
	}
	if res.Principal.ID != "spiffe://judge.testifysec.com/tenant/acme/agent/a1" {
		t.Errorf("ID = %q", res.Principal.ID)
	}
	if res.Principal.Issuer != "https://issuer.test.dev" {
		t.Errorf("Issuer = %q", res.Principal.Issuer)
	}
	if res.URL != "https://agents.partner.example/a2a/v1" {
		t.Errorf("URL = %q", res.URL)
	}
	if res.Name != "Test Triage Agent" {
		t.Errorf("Name = %q", res.Name)
	}
}

func TestVerifySignedCard_PrincipalTaxonomy(t *testing.T) {
	ca := newTestCA(t)

	human := signCard(t, ca, leafOpts{emails: []string{"cole@example.com"}}, nil)
	res, err := VerifySignedCard(human, Options{Roots: []*x509.Certificate{ca.cert}})
	if err != nil {
		t.Fatalf("human card: %v", err)
	}
	if res.Principal.Kind != PrincipalHuman || res.Principal.ID != "cole@example.com" {
		t.Errorf("human principal = %+v", res.Principal)
	}

	workflow := signCard(t, ca, leafOpts{
		uris: []string{"https://github.com/aflock-ai/aflock/.github/workflows/sign.yml@refs/heads/main"},
	}, nil)
	res, err = VerifySignedCard(workflow, Options{Roots: []*x509.Certificate{ca.cert}})
	if err != nil {
		t.Fatalf("workflow card: %v", err)
	}
	if res.Principal.Kind != PrincipalWorkflow {
		t.Errorf("workflow principal = %+v", res.Principal)
	}
}

func TestVerifySignedCard_DualPrincipalRefused(t *testing.T) {
	ca := newTestCA(t)
	dual := signCard(t, ca, leafOpts{
		uris:   []string{"spiffe://td/agent/a"},
		emails: []string{"who@example.com"},
	}, nil)
	if _, err := VerifySignedCard(dual, Options{Roots: []*x509.Certificate{ca.cert}}); err == nil {
		t.Fatal("certificate with both email and URI SANs must be refused")
	}
}

func TestVerifySignedCard_TamperedCardFails(t *testing.T) {
	ca := newTestCA(t)
	data := signCard(t, ca, leafOpts{uris: []string{"spiffe://td/agent/a"}}, nil)

	// Tamper: swap the endpoint URL in the (unsigned) agentCard object.
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var card map[string]any
	if err := json.Unmarshal(doc["agentCard"], &card); err != nil {
		t.Fatal(err)
	}
	card["url"] = "https://evil.example/a2a/v1"
	tampered, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	doc["agentCard"] = tampered
	data, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifySignedCard(data, Options{Roots: []*x509.Certificate{ca.cert}}); err == nil {
		t.Fatal("tampered agentCard must fail subject-digest verification")
	}
}

func TestVerifySignedCard_UntrustedRootFails(t *testing.T) {
	ca := newTestCA(t)
	other := newTestCA(t)
	data := signCard(t, ca, leafOpts{uris: []string{"spiffe://td/agent/a"}}, nil)
	if _, err := VerifySignedCard(data, Options{Roots: []*x509.Certificate{other.cert}}); err == nil {
		t.Fatal("card chained to a different CA must be refused")
	}
}

func TestVerifySignedCard_IssuerConstraint(t *testing.T) {
	ca := newTestCA(t)
	data := signCard(t, ca, leafOpts{
		uris:   []string{"spiffe://td/agent/a"},
		issuer: "https://issuer.test.dev",
	}, nil)

	if _, err := VerifySignedCard(data, Options{
		Roots:   []*x509.Certificate{ca.cert},
		Issuers: []string{"https://issuer.test.dev"},
	}); err != nil {
		t.Fatalf("matching issuer refused: %v", err)
	}
	if _, err := VerifySignedCard(data, Options{
		Roots:   []*x509.Certificate{ca.cert},
		Issuers: []string{"https://other-issuer.dev"},
	}); err == nil {
		t.Fatal("non-matching issuer must be refused")
	}
}

func TestPrincipalMatchIdentity(t *testing.T) {
	agent := Principal{Kind: PrincipalAgent, ID: "spiffe://judge.testifysec.com/tenant/acme/agent/a1"}
	human := Principal{Kind: PrincipalHuman, ID: "cole@example.com"}

	cases := []struct {
		p       Principal
		pattern string
		want    bool
	}{
		{agent, "spiffe://judge.testifysec.com/tenant/acme/agent/*", true},
		{agent, "agent:spiffe://judge.testifysec.com/tenant/*/agent/*", true},
		{agent, "human:spiffe://judge.testifysec.com/*", false}, // kind mismatch
		{agent, "spiffe://other.dev/*", false},
		{human, "human:*@example.com", true},
		{human, "agent:*@example.com", false},
		{human, "*@example.com", true},
	}
	for _, c := range cases {
		if got := c.p.MatchIdentity([]string{c.pattern}); got != c.want {
			t.Errorf("MatchIdentity(%q) on %+v = %v, want %v", c.pattern, c.p, got, c.want)
		}
	}
}
