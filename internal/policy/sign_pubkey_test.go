package policy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignWithKey_RoundTrip is the end-to-end raw-pubkey proof: generate a
// keypair, sign a policy with the private half, point a trust config at the
// public half, Load → success and SignatureInfo populated.
func TestSignWithKey_RoundTrip(t *testing.T) {
	t.Setenv("AFLOCK_REQUIRE_SIGNED_POLICY", "1")
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	privPath, pubPath := mustWriteECDSAKeyPair(t, dir)

	policyPath := filepath.Join(dir, ".aflock")
	require.NoError(t, os.WriteFile(policyPath,
		[]byte(`{"version":"1","name":"raw-key-roundtrip"}`), 0600))

	// Sign with the private key.
	policyBytes, err := os.ReadFile(policyPath)
	require.NoError(t, err)
	envelopeJSON, err := SignWithKey(context.Background(), privPath, policyBytes)
	require.NoError(t, err)

	signedPath := filepath.Join(dir, ".aflock.signed")
	require.NoError(t, os.WriteFile(signedPath, envelopeJSON, 0600))

	// Trust config points at the matching public key.
	trustPath := filepath.Join(dir, "trust.json")
	require.NoError(t, os.WriteFile(trustPath,
		[]byte(`{"version":"1","verifiers":[{"type":"pubkey","keyPath":"`+pubPath+`"}]}`),
		0600))
	t.Setenv("AFLOCK_TRUST_CONFIG", trustPath)

	pol, _, err := Load(signedPath)
	require.NoError(t, err)
	require.NotNil(t, pol.SignatureInfo)
	assert.Equal(t, "pubkey", pol.SignatureInfo.Issuer)
	assert.NotEmpty(t, pol.SignatureInfo.Subject, "keyid fingerprint should be set")
	assert.Equal(t, "raw-key-roundtrip", pol.Name)
}

// TestSignWithKey_TamperRejected proves that flipping a byte in the inner
// payload invalidates verification — the central security property of signed
// policies.
func TestSignWithKey_TamperRejected(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	privPath, pubPath := mustWriteECDSAKeyPair(t, dir)

	envelopeJSON, err := SignWithKey(context.Background(),
		privPath, []byte(`{"version":"1","name":"tamper-target"}`))
	require.NoError(t, err)

	// Flip a byte in the base64 payload — keeps it valid base64, invalidates
	// the signature.
	tampered := flipFirstPayloadChar(t, envelopeJSON)
	signedPath := filepath.Join(dir, ".aflock.signed")
	require.NoError(t, os.WriteFile(signedPath, tampered, 0600))

	trustPath := filepath.Join(dir, "trust.json")
	require.NoError(t, os.WriteFile(trustPath,
		[]byte(`{"version":"1","verifiers":[{"type":"pubkey","keyPath":"`+pubPath+`"}]}`),
		0600))
	t.Setenv("AFLOCK_TRUST_CONFIG", trustPath)

	_, _, err = Load(signedPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

// TestSignWithKey_WrongKeyRejected proves that pairing a signature with the
// wrong public key fails verification (not just the wrong fingerprint, but
// actual signature math).
func TestSignWithKey_WrongKeyRejected(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	privPath, _ := mustWriteECDSAKeyPair(t, dir)
	_, wrongPubPath := mustWriteECDSAKeyPair(t, dir) // unrelated keypair

	envelopeJSON, err := SignWithKey(context.Background(),
		privPath, []byte(`{"version":"1","name":"x"}`))
	require.NoError(t, err)
	signedPath := filepath.Join(dir, ".aflock.signed")
	require.NoError(t, os.WriteFile(signedPath, envelopeJSON, 0600))

	trustPath := filepath.Join(dir, "trust.json")
	require.NoError(t, os.WriteFile(trustPath,
		[]byte(`{"version":"1","verifiers":[{"type":"pubkey","keyPath":"`+wrongPubPath+`"}]}`),
		0600))
	t.Setenv("AFLOCK_TRUST_CONFIG", trustPath)

	_, _, err = Load(signedPath)
	require.Error(t, err)
}

// mustWriteECDSAKeyPair generates a P-256 keypair and writes both halves as
// PEM into dir. Returns (privPath, pubPath).
func mustWriteECDSAKeyPair(t *testing.T, dir string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// Suffix paths so callers can request multiple keypairs in one dir.
	base := filepath.Join(dir, randSuffix(t))
	privPath := base + ".priv.pem"
	pubPath := base + ".pub.pem"
	require.NoError(t, os.WriteFile(privPath, privPEM, 0600))
	require.NoError(t, os.WriteFile(pubPath, pubPEM, 0600))
	return privPath, pubPath
}

func randSuffix(t *testing.T) string {
	t.Helper()
	var buf [4]byte
	_, err := rand.Read(buf[:])
	require.NoError(t, err, "crypto/rand.Read must not fail")
	const hex = "0123456789abcdef"
	out := make([]byte, 8)
	for i, b := range buf {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}

// flipFirstPayloadChar mutates the envelope's base64 payload by toggling one
// character — produces still-valid base64 with different bytes underneath, so
// the signature math fails but the envelope structure parses.
func flipFirstPayloadChar(t *testing.T, envelopeJSON []byte) []byte {
	t.Helper()
	// Naive but sufficient: find the payload string in the JSON and replace
	// the first base64 char with a different one.
	s := string(envelopeJSON)
	const needle = `"payload": "`
	idx := indexOf(s, needle)
	require.GreaterOrEqual(t, idx, 0)
	pos := idx + len(needle)
	orig := s[pos]
	swap := byte('B')
	if orig == 'B' {
		swap = 'C'
	}
	return []byte(s[:pos] + string(swap) + s[pos+1:])
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
