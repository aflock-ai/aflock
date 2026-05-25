package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const minimalRawPolicy = `{"version":"1","name":"demo"}`

func TestLoad_RawPolicy_StillWorks(t *testing.T) {
	t.Setenv("AFLOCK_REQUIRE_SIGNED_POLICY", "")
	t.Setenv("HOME", t.TempDir())

	path := filepath.Join(t.TempDir(), ".aflock")
	require.NoError(t, os.WriteFile(path, []byte(minimalRawPolicy), 0600))

	pol, _, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "demo", pol.Name)
	assert.NotEmpty(t, pol.RawDigest, "RawDigest must be set for JWT binding")
	assert.Nil(t, pol.SignatureInfo, "unsigned policy must not have SignatureInfo")
}

func TestLoad_RawPolicy_RejectedWhenSignatureRequired(t *testing.T) {
	t.Setenv("AFLOCK_REQUIRE_SIGNED_POLICY", "1")
	t.Setenv("HOME", t.TempDir())

	path := filepath.Join(t.TempDir(), ".aflock")
	require.NoError(t, os.WriteFile(path, []byte(minimalRawPolicy), 0600))

	_, _, err := Load(path)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnsignedRequired),
		"expected ErrUnsignedRequired wrap, got: %v", err)
}

func TestLoad_Envelope_FailsWithoutTrustConfig(t *testing.T) {
	t.Setenv("AFLOCK_REQUIRE_SIGNED_POLICY", "")
	t.Setenv("AFLOCK_TRUST_CONFIG", "")
	t.Setenv("HOME", t.TempDir())

	// Envelope shape but no trust config → must hard-fail, not fall back to
	// raw parsing. This is the silent-degrade case #133 originally flagged:
	// passing a .signed file to load today returns an empty allow-most policy.
	envelope := []byte(`{"payloadType":"application/vnd.aflock.policy+json","payload":"eyJ2ZXJzaW9uIjoiMSJ9","signatures":[]}`)
	path := filepath.Join(t.TempDir(), ".aflock.signed")
	require.NoError(t, os.WriteFile(path, envelope, 0600))

	_, _, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no trust config", "envelope without trust must hard-fail")
}

func TestLoad_Envelope_FailsWithEmptySignatures(t *testing.T) {
	t.Setenv("AFLOCK_REQUIRE_SIGNED_POLICY", "")
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "aflock-trust.json"),
		[]byte(`{"version":"1","verifiers":[{"type":"sigstore","issuer":"i","subjectPattern":"s"}]}`),
		0600))

	envelope := []byte(`{"payloadType":"application/vnd.aflock.policy+json","payload":"eyJ2ZXJzaW9uIjoiMSJ9","signatures":[]}`)
	path := filepath.Join(dir, ".aflock.signed")
	require.NoError(t, os.WriteFile(path, envelope, 0600))

	_, _, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "envelope has no signatures")
}

func TestLoad_Envelope_FailsWithWrongPayloadType(t *testing.T) {
	t.Setenv("AFLOCK_REQUIRE_SIGNED_POLICY", "")
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "aflock-trust.json"),
		[]byte(`{"version":"1","verifiers":[{"type":"sigstore","issuer":"i","subjectPattern":"s"}]}`),
		0600))

	// isEnvelope() detects ANY DSSE envelope shape, so an in-toto envelope
	// fed as a policy enters the verify-or-fail path and gets rejected at the
	// payloadType check — proving aflock won't accept envelopes for other
	// formats (in-toto attestations, etc.) as policies, and won't silently
	// fall back to raw parsing.
	envelope := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"eyJ2ZXJzaW9uIjoiMSJ9","signatures":[]}`)
	path := filepath.Join(dir, "weird.json")
	require.NoError(t, os.WriteFile(path, envelope, 0600))

	_, _, err := Load(path)
	require.Error(t, err, "non-aflock payloadType must not be accepted as a policy")
	assert.Contains(t, err.Error(), "unexpected payload type",
		"must fail at the envelope payloadType gate, not at raw JSON unmarshal")
}
