package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTrustConfig_EnvVarWins(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // isolate ~/.aflock/trust.json

	envCfg := filepath.Join(t.TempDir(), "env-trust.json")
	dirCfg := filepath.Join(t.TempDir(), "aflock-trust.json")

	good := []byte(`{"version":"1","verifiers":[{"type":"sigstore","issuer":"https://e","subjectPattern":"e"}]}`)
	wrong := []byte(`{"version":"1","verifiers":[{"type":"sigstore","issuer":"https://d","subjectPattern":"d"}]}`)
	require.NoError(t, os.WriteFile(envCfg, good, 0600))
	require.NoError(t, os.WriteFile(dirCfg, wrong, 0600))

	t.Setenv("AFLOCK_TRUST_CONFIG", envCfg)

	cfg, path, err := LoadTrustConfig(filepath.Join(filepath.Dir(dirCfg), ".aflock"))
	require.NoError(t, err)
	assert.Equal(t, envCfg, path)
	assert.Equal(t, "https://e", cfg.Verifiers[0].Issuer)
}

func TestLoadTrustConfig_PolicyDirFallback(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AFLOCK_TRUST_CONFIG", "")

	dir := t.TempDir()
	dirCfg := filepath.Join(dir, "aflock-trust.json")
	good := []byte(`{"version":"1","verifiers":[{"type":"sigstore","issuer":"https://d","subjectPattern":"d"}]}`)
	require.NoError(t, os.WriteFile(dirCfg, good, 0600))

	cfg, path, err := LoadTrustConfig(filepath.Join(dir, ".aflock"))
	require.NoError(t, err)
	assert.Equal(t, dirCfg, path)
	assert.Equal(t, "https://d", cfg.Verifiers[0].Issuer)
}

func TestLoadTrustConfig_EnvVarMissingIsHardError(t *testing.T) {
	// If the operator set AFLOCK_TRUST_CONFIG, we must NOT silently fall back
	// to <policy_dir>/aflock-trust.json or ~/.aflock/trust.json — that could
	// turn an intended override into trusting an attacker-controlled file.
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	// Put a valid trust config in the policy dir; the env-var-missing path
	// must still fail rather than silently use it.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "aflock-trust.json"),
		[]byte(`{"version":"1","verifiers":[{"type":"sigstore","issuer":"https://d","subjectPattern":"d"}]}`),
		0600))

	t.Setenv("AFLOCK_TRUST_CONFIG", filepath.Join(t.TempDir(), "does-not-exist.json"))

	_, _, err := LoadTrustConfig(filepath.Join(dir, ".aflock"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read trust config")
}

func TestLoadTrustConfig_NoneFound(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AFLOCK_TRUST_CONFIG", "")

	_, _, err := LoadTrustConfig(filepath.Join(t.TempDir(), ".aflock"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoTrustConfig))
}

func TestLoadTrustConfig_InvalidVersion(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), "trust.json")
	require.NoError(t, os.WriteFile(cfgPath,
		[]byte(`{"version":"2","verifiers":[{"type":"sigstore","issuer":"i","subjectPattern":"s"}]}`),
		0600))
	t.Setenv("AFLOCK_TRUST_CONFIG", cfgPath)

	_, _, err := LoadTrustConfig("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported version "2"`)
}

func TestLoadTrustConfig_EmptyVerifiers(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), "trust.json")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`{"version":"1","verifiers":[]}`), 0600))
	t.Setenv("AFLOCK_TRUST_CONFIG", cfgPath)

	_, _, err := LoadTrustConfig("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verifiers list is empty")
}

func TestLoadTrustConfig_UnsupportedType(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), "trust.json")
	require.NoError(t, os.WriteFile(cfgPath,
		[]byte(`{"version":"1","verifiers":[{"type":"x509","issuer":"i","subjectPattern":"s"}]}`),
		0600))
	t.Setenv("AFLOCK_TRUST_CONFIG", cfgPath)

	_, _, err := LoadTrustConfig("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported type "x509"`)
}

func TestLoadTrustConfig_PubkeyType(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), "trust.json")
	require.NoError(t, os.WriteFile(cfgPath,
		[]byte(`{"version":"1","verifiers":[{"type":"pubkey","keyPath":"/tmp/key.pem"}]}`),
		0600))
	t.Setenv("AFLOCK_TRUST_CONFIG", cfgPath)

	cfg, _, err := LoadTrustConfig("")
	require.NoError(t, err)
	assert.Equal(t, "pubkey", cfg.Verifiers[0].Type)
	assert.Equal(t, "/tmp/key.pem", cfg.Verifiers[0].KeyPath)
}

func TestLoadTrustConfig_PubkeyMissingKeyPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), "trust.json")
	require.NoError(t, os.WriteFile(cfgPath,
		[]byte(`{"version":"1","verifiers":[{"type":"pubkey"}]}`),
		0600))
	t.Setenv("AFLOCK_TRUST_CONFIG", cfgPath)

	_, _, err := LoadTrustConfig("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keyPath is required for type=pubkey")
}

func TestLoadTrustConfig_MissingFields(t *testing.T) {
	cases := map[string]string{
		"missing issuer":         `{"version":"1","verifiers":[{"type":"sigstore","subjectPattern":"s"}]}`,
		"missing subjectPattern": `{"version":"1","verifiers":[{"type":"sigstore","issuer":"i"}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			cfgPath := filepath.Join(t.TempDir(), "trust.json")
			require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0600))
			t.Setenv("AFLOCK_TRUST_CONFIG", cfgPath)
			_, _, err := LoadTrustConfig("")
			require.Error(t, err)
		})
	}
}

func TestLoadTrustConfig_MalformedJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), "trust.json")
	require.NoError(t, os.WriteFile(cfgPath, []byte("not json"), 0600))
	t.Setenv("AFLOCK_TRUST_CONFIG", cfgPath)

	_, _, err := LoadTrustConfig("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse trust config")
}
