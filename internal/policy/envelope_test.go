package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	rdsse "github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsEnvelope_DetectsSignedPolicy(t *testing.T) {
	env := []byte(`{"payloadType":"application/vnd.aflock.policy+json","payload":"e30=","signatures":[]}`)
	assert.True(t, isEnvelope(env))
}

func TestIsEnvelope_RejectsRawPolicy(t *testing.T) {
	raw := []byte(`{"version":"1","name":"demo"}`)
	assert.False(t, isEnvelope(raw))
}

func TestIsEnvelope_DetectsAnyEnvelopeShape(t *testing.T) {
	// Any envelope-shaped JSON must be detected so the load path can
	// verify-or-fail. Restricting detection to our payloadType would let an
	// attacker feed e.g. an in-toto attestation envelope as a policy and have
	// its fields silently parse as a zero-valued aflock.Policy.
	env := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}`)
	assert.True(t, isEnvelope(env))
}

func TestIsEnvelope_RejectsMissingPayload(t *testing.T) {
	env := []byte(`{"payloadType":"application/vnd.aflock.policy+json","signatures":[]}`)
	assert.False(t, isEnvelope(env))
}

func TestIsEnvelope_RejectsMissingSignatures(t *testing.T) {
	env := []byte(`{"payloadType":"application/vnd.aflock.policy+json","payload":"e30="}`)
	assert.False(t, isEnvelope(env))
}

func TestIsEnvelope_RejectsMalformedJSON(t *testing.T) {
	assert.False(t, isEnvelope([]byte("not json")))
}

func TestIsEnvelope_DetectsEmptyAndNullValues(t *testing.T) {
	// Defense against bypass: a crafted envelope with empty strings or null
	// values still has the envelope-shaped keys, so it must trigger the
	// verify-or-fail path. Falling back to raw parsing on these would
	// produce a zero-valued allow-most policy.
	cases := [][]byte{
		[]byte(`{"payloadType":"","payload":"","signatures":null}`),
		[]byte(`{"payloadType":"","payload":"","signatures":[]}`),
		[]byte(`{"payloadType":"x","payload":"","signatures":null}`),
	}
	for _, env := range cases {
		assert.True(t, isEnvelope(env), "must detect envelope shape: %s", env)
	}
}

func TestIsEmail(t *testing.T) {
	cases := map[string]bool{
		"rahul@gmail.com":                       true,
		"*@gmail.com":                           true,
		"https://github.com/org/repo/.github/*": false,
		"spiffe://aflock.local/agent/xyz":       false,
		"":                                      false,
		"no-at-here":                            false,
	}
	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, want, isEmail(input))
		})
	}
}

func TestLoadFulcioRoots_EmbeddedDefault(t *testing.T) {
	roots, err := loadFulcioRoots("")
	require.NoError(t, err)
	require.Len(t, roots, 1)
	assert.Equal(t, "sigstore", roots[0].Subject.CommonName)
}

func TestLoadFulcioRoots_CustomPath(t *testing.T) {
	// Self-signed cert as a stand-in for a self-hosted Fulcio root.
	cert := mustSelfSignedCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	path := filepath.Join(t.TempDir(), "custom-root.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0600))

	roots, err := loadFulcioRoots(path)
	require.NoError(t, err)
	require.Len(t, roots, 1)
	assert.Equal(t, cert.Subject.CommonName, roots[0].Subject.CommonName)
}

func TestLoadFulcioRoots_MissingFile(t *testing.T) {
	_, err := loadFulcioRoots(filepath.Join(t.TempDir(), "missing.pem"))
	require.Error(t, err)
}

func TestLoadFulcioRoots_NotPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.pem")
	require.NoError(t, os.WriteFile(path, []byte("not a cert"), 0600))
	_, err := loadFulcioRoots(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates found")
}

func TestExtractLeafCert_NoCertificate(t *testing.T) {
	env := rdsse.Envelope{
		PayloadType: PolicyPayloadType,
		Payload:     []byte("{}"),
		Signatures:  []rdsse.Signature{{KeyID: "k"}},
	}
	_, err := extractLeafCert(env)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no embedded leaf certificate")
}

func TestExtractLeafCert_NotPEM(t *testing.T) {
	env := rdsse.Envelope{
		PayloadType: PolicyPayloadType,
		Payload:     []byte("{}"),
		Signatures: []rdsse.Signature{{
			KeyID:       "k",
			Certificate: []byte("not pem"),
		}},
	}
	_, err := extractLeafCert(env)
	require.Error(t, err)
}

// mustSelfSignedCert returns a minimal self-signed cert usable as a fake CA in
// tests. Caller takes ownership of the returned cert; we don't preserve the
// private key.
func mustSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-fulcio-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
