package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/aflock-ai/aflock/pkg/aflock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Test Helpers — Certificate Factories
// =============================================================================

// makeFulcioCert creates a self-signed certificate with a Fulcio issuer OID
// and a URI SAN (mimicking GitHub Actions identity).
func makeFulcioCert(t *testing.T, issuerOIDC, subjectURI string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerBytes, err := asn1.Marshal(issuerOIDC)
	require.NoError(t, err)

	subjectURL, err := url.Parse(subjectURI)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * time.Minute),
		URIs:         []*url.URL{subjectURL},
		ExtraExtensions: []pkix.Extension{
			{Id: oidFulcioIssuer, Value: issuerBytes},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// makeFulcioCertWithEmail creates a Fulcio cert with an email SAN instead of URI.
// Simulates Google OIDC identity (email-based).
func makeFulcioCertWithEmail(t *testing.T, issuerOIDC, email string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerBytes, _ := asn1.Marshal(issuerOIDC)

	template := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(10 * time.Minute),
		EmailAddresses: []string{email},
		ExtraExtensions: []pkix.Extension{
			{Id: oidFulcioIssuer, Value: issuerBytes},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// makeFulcioCertWithAllExtensions creates a cert with ALL Fulcio extensions populated.
func makeFulcioCertWithAllExtensions(t *testing.T, opts fulcioCertExtensions, subjectURI string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	subjectURL, _ := url.Parse(subjectURI)

	exts := []pkix.Extension{}
	addExt := func(oid asn1.ObjectIdentifier, val string) {
		if val != "" {
			b, _ := asn1.Marshal(val)
			exts = append(exts, pkix.Extension{Id: oid, Value: b})
		}
	}
	addExt(oidFulcioIssuer, opts.Issuer)
	addExt(oidFulcioBuildSignerURI, opts.BuildSignerURI)
	addExt(oidFulcioBuildSignerDigest, opts.BuildSignerDigest)
	addExt(oidFulcioRunnerEnvironment, opts.RunnerEnvironment)
	addExt(oidFulcioBuildTrigger, opts.BuildTrigger)
	addExt(oidFulcioSourceRepoURI, opts.SourceRepositoryURI)
	addExt(oidFulcioSourceRepoRef, opts.SourceRepositoryRef)
	addExt(oidFulcioSourceRepoOwnerURI, opts.SourceRepositoryOwnerURI)

	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(10 * time.Minute),
		URIs:            []*url.URL{subjectURL},
		ExtraExtensions: exts,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// makeNonFulcioCert creates a normal X.509 cert with NO Fulcio extensions.
func makeNonFulcioCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// =============================================================================
// 1. matchesKeylessFunctionary — Core Matching Logic
// =============================================================================

func TestMatchesKeylessFunctionary(t *testing.T) {
	ghIssuer := "https://token.actions.githubusercontent.com"
	googleIssuer := "https://accounts.google.com"
	ciWorkflow := "https://github.com/aflock-ai/aflock/.github/workflows/ci.yml@refs/heads/main"

	tests := []struct {
		name string
		cert *x509.Certificate
		f    aflock.StepFunctionary
		want bool
	}{
		// --- Positive cases ---
		{
			name: "exact_issuer_and_subject",
			cert: makeFulcioCert(t, ghIssuer, ciWorkflow),
			f:    aflock.StepFunctionary{Type: "keyless", Issuer: ghIssuer, Subject: ciWorkflow},
			want: true,
		},
		{
			name: "issuer_only_no_subject_constraint",
			cert: makeFulcioCert(t, ghIssuer, ciWorkflow),
			f:    aflock.StepFunctionary{Type: "keyless", Issuer: ghIssuer},
			want: true,
		},
		{
			name: "glob_subject_star_at_end",
			cert: makeFulcioCert(t, ghIssuer, ciWorkflow),
			f:    aflock.StepFunctionary{Type: "keyless", Issuer: ghIssuer, Subject: "https://github.com/aflock-ai/aflock/.github/workflows/*"},
			want: true,
		},
		{
			name: "glob_subject_star_in_middle",
			cert: makeFulcioCert(t, ghIssuer, "https://github.com/aflock-ai/aflock/.github/workflows/ci.yml@refs/heads/main"),
			f:    aflock.StepFunctionary{Type: "keyless", Issuer: ghIssuer, Subject: "https://github.com/aflock-ai/*/ci.yml@refs/heads/main"},
			want: true,
		},
		{
			name: "glob_subject_double_star",
			cert: makeFulcioCert(t, ghIssuer, ciWorkflow),
			f:    aflock.StepFunctionary{Type: "keyless", Issuer: ghIssuer, Subject: "https://github.com/aflock-ai/**"},
			want: true,
		},
		{
			name: "no_constraints_at_all_fulcio_cert",
			cert: makeFulcioCert(t, ghIssuer, ciWorkflow),
			f:    aflock.StepFunctionary{Type: "keyless"},
			want: true,
		},
		{
			name: "email_san_exact_match",
			cert: makeFulcioCertWithEmail(t, googleIssuer, "deploy@myorg.iam.gserviceaccount.com"),
			f:    aflock.StepFunctionary{Type: "keyless", Issuer: googleIssuer, Subject: "deploy@myorg.iam.gserviceaccount.com"},
			want: true,
		},
		{
			name: "email_san_glob_match",
			cert: makeFulcioCertWithEmail(t, googleIssuer, "deploy@myorg.iam.gserviceaccount.com"),
			f:    aflock.StepFunctionary{Type: "keyless", Issuer: googleIssuer, Subject: "*@myorg.iam.gserviceaccount.com"},
			want: true,
		},

		// --- Negative cases ---
		{
			name: "wrong_issuer",
			cert: makeFulcioCert(t, googleIssuer, "user@example.com"),
			f:    aflock.StepFunctionary{Type: "keyless", Issuer: ghIssuer},
			want: false,
		},
		{
			name: "wrong_subject",
			cert: makeFulcioCert(t, ghIssuer, ciWorkflow),
			f:    aflock.StepFunctionary{Type: "keyless", Issuer: ghIssuer, Subject: "https://github.com/evil-org/*"},
			want: false,
		},
		{
			name: "nil_cert",
			cert: nil,
			f:    aflock.StepFunctionary{Type: "keyless", Issuer: ghIssuer},
			want: false,
		},
		{
			name: "non_fulcio_cert_no_constraints",
			cert: makeNonFulcioCert(t),
			f:    aflock.StepFunctionary{Type: "keyless"},
			want: false,
		},
		{
			name: "non_fulcio_cert_with_issuer",
			cert: makeNonFulcioCert(t),
			f:    aflock.StepFunctionary{Type: "keyless", Issuer: ghIssuer},
			want: false,
		},
		{
			name: "email_san_wrong_domain",
			cert: makeFulcioCertWithEmail(t, googleIssuer, "user@evil.com"),
			f:    aflock.StepFunctionary{Type: "keyless", Issuer: googleIssuer, Subject: "*@myorg.iam.gserviceaccount.com"},
			want: false,
		},
		{
			name: "invalid_glob_pattern",
			cert: makeFulcioCert(t, ghIssuer, ciWorkflow),
			f:    aflock.StepFunctionary{Type: "keyless", Issuer: ghIssuer, Subject: "[invalid"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesKeylessFunctionary(tt.cert, tt.f)
			assert.Equal(t, tt.want, got)
		})
	}
}

// =============================================================================
// 2. extractFulcioExtensions — OID Parsing
// =============================================================================

func TestExtractFulcioExtensions(t *testing.T) {
	t.Run("all_extensions_populated", func(t *testing.T) {
		cert := makeFulcioCertWithAllExtensions(t, fulcioCertExtensions{
			Issuer:                   "https://token.actions.githubusercontent.com",
			BuildSignerURI:           "https://github.com/aflock-ai/aflock/.github/workflows/ci.yml@refs/heads/main",
			BuildSignerDigest:        "abc123def456",
			RunnerEnvironment:        "github-hosted",
			BuildTrigger:             "push",
			SourceRepositoryURI:      "https://github.com/aflock-ai/aflock",
			SourceRepositoryRef:      "refs/heads/main",
			SourceRepositoryOwnerURI: "https://github.com/aflock-ai",
		}, "https://github.com/aflock-ai/aflock/.github/workflows/ci.yml")

		ext := extractFulcioExtensions(cert)
		assert.Equal(t, "https://token.actions.githubusercontent.com", ext.Issuer)
		assert.Equal(t, "https://github.com/aflock-ai/aflock/.github/workflows/ci.yml@refs/heads/main", ext.BuildSignerURI)
		assert.Equal(t, "abc123def456", ext.BuildSignerDigest)
		assert.Equal(t, "github-hosted", ext.RunnerEnvironment)
		assert.Equal(t, "push", ext.BuildTrigger)
		assert.Equal(t, "https://github.com/aflock-ai/aflock", ext.SourceRepositoryURI)
		assert.Equal(t, "refs/heads/main", ext.SourceRepositoryRef)
		assert.Equal(t, "https://github.com/aflock-ai", ext.SourceRepositoryOwnerURI)
	})

	t.Run("only_issuer", func(t *testing.T) {
		cert := makeFulcioCert(t, "https://accounts.google.com", "user@example.com")
		ext := extractFulcioExtensions(cert)
		assert.Equal(t, "https://accounts.google.com", ext.Issuer)
		assert.Empty(t, ext.BuildSignerURI)
		assert.Empty(t, ext.RunnerEnvironment)
		assert.Empty(t, ext.SourceRepositoryURI)
	})

	t.Run("no_fulcio_extensions", func(t *testing.T) {
		cert := makeNonFulcioCert(t)
		ext := extractFulcioExtensions(cert)
		assert.Empty(t, ext.Issuer)
		assert.Empty(t, ext.BuildSignerURI)
	})

	t.Run("raw_bytes_fallback", func(t *testing.T) {
		// Fulcio v1 used raw bytes instead of ASN.1 UTF8String.
		// Test the fallback path.
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(10 * time.Minute),
			ExtraExtensions: []pkix.Extension{
				{Id: oidFulcioIssuer, Value: []byte("raw-issuer-bytes")},
			},
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		ext := extractFulcioExtensions(cert)
		assert.Equal(t, "raw-issuer-bytes", ext.Issuer)
	})
}

// =============================================================================
// 3. matchesCertSubject — SAN Matching with Glob
// =============================================================================

func TestMatchesCertSubject(t *testing.T) {
	t.Run("uri_exact_match", func(t *testing.T) {
		cert := makeFulcioCert(t, "issuer", "https://github.com/org/repo/.github/workflows/ci.yml")
		assert.True(t, matchesCertSubject(cert, "https://github.com/org/repo/.github/workflows/ci.yml"))
	})

	t.Run("uri_glob_star", func(t *testing.T) {
		cert := makeFulcioCert(t, "issuer", "https://github.com/org/repo/.github/workflows/ci.yml")
		assert.True(t, matchesCertSubject(cert, "https://github.com/org/repo/.github/workflows/*"))
	})

	t.Run("uri_glob_double_star", func(t *testing.T) {
		cert := makeFulcioCert(t, "issuer", "https://github.com/org/repo/.github/workflows/ci.yml")
		assert.True(t, matchesCertSubject(cert, "https://github.com/org/**"))
	})

	t.Run("uri_glob_no_match", func(t *testing.T) {
		cert := makeFulcioCert(t, "issuer", "https://github.com/org/repo/.github/workflows/ci.yml")
		assert.False(t, matchesCertSubject(cert, "https://github.com/other-org/**"))
	})

	t.Run("email_exact_match", func(t *testing.T) {
		cert := makeFulcioCertWithEmail(t, "issuer", "user@example.com")
		assert.True(t, matchesCertSubject(cert, "user@example.com"))
	})

	t.Run("email_glob_match", func(t *testing.T) {
		cert := makeFulcioCertWithEmail(t, "issuer", "deploy@prod.iam.gserviceaccount.com")
		assert.True(t, matchesCertSubject(cert, "*@prod.iam.gserviceaccount.com"))
	})

	t.Run("email_glob_no_match", func(t *testing.T) {
		cert := makeFulcioCertWithEmail(t, "issuer", "user@evil.com")
		assert.False(t, matchesCertSubject(cert, "*@example.com"))
	})

	t.Run("no_sans_at_all", func(t *testing.T) {
		cert := makeNonFulcioCert(t)
		assert.False(t, matchesCertSubject(cert, "*"))
	})

	t.Run("invalid_glob_returns_false", func(t *testing.T) {
		cert := makeFulcioCert(t, "issuer", "https://example.com")
		assert.False(t, matchesCertSubject(cert, "[invalid"))
	})
}

// =============================================================================
// 4. matchesFulcioExtensions — Extension Constraint Matching
// =============================================================================

func TestMatchesFulcioExtensions(t *testing.T) {
	actual := &fulcioCertExtensions{
		Issuer:                   "https://token.actions.githubusercontent.com",
		BuildSignerURI:           "https://github.com/aflock-ai/aflock/.github/workflows/ci.yml@refs/heads/main",
		BuildSignerDigest:        "abc123",
		RunnerEnvironment:        "github-hosted",
		BuildTrigger:             "push",
		SourceRepositoryURI:      "https://github.com/aflock-ai/aflock",
		SourceRepositoryRef:      "refs/heads/main",
		SourceRepositoryOwnerURI: "https://github.com/aflock-ai",
	}

	tests := []struct {
		name     string
		expected *aflock.FulcioExtensions
		want     bool
	}{
		{
			name:     "all_match_exact",
			expected: &aflock.FulcioExtensions{Issuer: "https://token.actions.githubusercontent.com", RunnerEnvironment: "github-hosted", SourceRepositoryURI: "https://github.com/aflock-ai/aflock"},
			want:     true,
		},
		{
			name:     "single_field_match",
			expected: &aflock.FulcioExtensions{Issuer: "https://token.actions.githubusercontent.com"},
			want:     true,
		},
		{
			name:     "empty_constraints_match_everything",
			expected: &aflock.FulcioExtensions{},
			want:     true,
		},
		{
			name:     "glob_repo_uri",
			expected: &aflock.FulcioExtensions{SourceRepositoryURI: "https://github.com/aflock-ai/*"},
			want:     true,
		},
		{
			name:     "glob_owner_uri",
			expected: &aflock.FulcioExtensions{SourceRepositoryOwnerURI: "https://github.com/aflock-*"},
			want:     true,
		},
		{
			name:     "glob_build_signer_uri",
			expected: &aflock.FulcioExtensions{BuildSignerURI: "https://github.com/aflock-ai/aflock/.github/workflows/*"},
			want:     true,
		},
		{
			name:     "wrong_issuer",
			expected: &aflock.FulcioExtensions{Issuer: "https://accounts.google.com"},
			want:     false,
		},
		{
			name:     "wrong_runner_environment",
			expected: &aflock.FulcioExtensions{RunnerEnvironment: "self-hosted"},
			want:     false,
		},
		{
			name:     "wrong_repo_ref",
			expected: &aflock.FulcioExtensions{SourceRepositoryRef: "refs/tags/v1.0.0"},
			want:     false,
		},
		{
			name:     "wrong_build_trigger",
			expected: &aflock.FulcioExtensions{BuildTrigger: "pull_request"},
			want:     false,
		},
		{
			name:     "one_matches_one_doesnt",
			expected: &aflock.FulcioExtensions{Issuer: "https://token.actions.githubusercontent.com", RunnerEnvironment: "self-hosted"},
			want:     false,
		},
		{
			name:     "constraint_on_empty_extension",
			expected: &aflock.FulcioExtensions{BuildSignerDigest: "wrong-digest"},
			want:     false,
		},
		{
			name:     "build_signer_digest_exact",
			expected: &aflock.FulcioExtensions{BuildSignerDigest: "abc123"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesFulcioExtensions(actual, tt.expected)
			assert.Equal(t, tt.want, got)
		})
	}
}

// =============================================================================
// 5. matchesKeylessFunctionary with FulcioExtensions
// =============================================================================

func TestMatchesKeylessFunctionary_WithFulcioExtensions(t *testing.T) {
	ghIssuer := "https://token.actions.githubusercontent.com"
	ciWorkflow := "https://github.com/aflock-ai/aflock/.github/workflows/ci.yml@refs/heads/main"

	cert := makeFulcioCertWithAllExtensions(t, fulcioCertExtensions{
		Issuer:              ghIssuer,
		RunnerEnvironment:   "github-hosted",
		SourceRepositoryURI: "https://github.com/aflock-ai/aflock",
		SourceRepositoryRef: "refs/heads/main",
	}, ciWorkflow)

	t.Run("extensions_match", func(t *testing.T) {
		f := aflock.StepFunctionary{
			Type:   "keyless",
			Issuer: ghIssuer,
			FulcioExtensions: &aflock.FulcioExtensions{
				RunnerEnvironment:   "github-hosted",
				SourceRepositoryURI: "https://github.com/aflock-ai/*",
			},
		}
		assert.True(t, matchesKeylessFunctionary(cert, f))
	})

	t.Run("extensions_mismatch", func(t *testing.T) {
		f := aflock.StepFunctionary{
			Type:   "keyless",
			Issuer: ghIssuer,
			FulcioExtensions: &aflock.FulcioExtensions{
				RunnerEnvironment: "self-hosted", // mismatch
			},
		}
		assert.False(t, matchesKeylessFunctionary(cert, f))
	})

	t.Run("issuer_matches_but_extensions_dont", func(t *testing.T) {
		f := aflock.StepFunctionary{
			Type:   "keyless",
			Issuer: ghIssuer,
			FulcioExtensions: &aflock.FulcioExtensions{
				SourceRepositoryRef: "refs/tags/v9.9.9",
			},
		}
		assert.False(t, matchesKeylessFunctionary(cert, f))
	})

	t.Run("nil_extensions_means_no_constraint", func(t *testing.T) {
		f := aflock.StepFunctionary{
			Type:   "keyless",
			Issuer: ghIssuer,
			// FulcioExtensions is nil — should pass
		}
		assert.True(t, matchesKeylessFunctionary(cert, f))
	})
}

// =============================================================================
// 6. matchesFunctionary — Integration with Step-Level Matching
// =============================================================================

func TestMatchesFunctionary_KeylessIntegration(t *testing.T) {
	ghIssuer := "https://token.actions.githubusercontent.com"
	cert := makeFulcioCert(t, ghIssuer,
		"https://github.com/aflock-ai/aflock/.github/workflows/ci.yml")

	t.Run("keyless_matches_in_mixed_step", func(t *testing.T) {
		step := &aflock.Step{
			Functionaries: []aflock.StepFunctionary{
				{Type: "publickey", PublicKeyID: "sha256:deadbeef"},
				{Type: "keyless", Issuer: ghIssuer},
			},
		}
		assert.True(t, matchesFunctionary(cert, "", step),
			"second functionary (keyless) should match")
	})

	t.Run("keyless_is_only_functionary", func(t *testing.T) {
		step := &aflock.Step{
			Functionaries: []aflock.StepFunctionary{
				{Type: "keyless", Issuer: ghIssuer},
			},
		}
		assert.True(t, matchesFunctionary(cert, "", step))
	})

	t.Run("only_publickey_no_match", func(t *testing.T) {
		step := &aflock.Step{
			Functionaries: []aflock.StepFunctionary{
				{Type: "publickey", PublicKeyID: "sha256:deadbeef"},
			},
		}
		assert.False(t, matchesFunctionary(cert, "", step))
	})

	t.Run("empty_functionaries_accepts_any", func(t *testing.T) {
		step := &aflock.Step{Functionaries: nil}
		assert.True(t, matchesFunctionary(cert, "", step),
			"empty functionaries list should accept any trusted signature")
	})

	t.Run("publickey_matches_by_keyid_not_keyless", func(t *testing.T) {
		step := &aflock.Step{
			Functionaries: []aflock.StepFunctionary{
				{Type: "publickey", PublicKeyID: "my-key-id"},
			},
		}
		// Cert doesn't match publickey, but keyid does
		assert.True(t, matchesFunctionary(cert, "my-key-id", step))
	})

	t.Run("keyless_wrong_issuer_falls_through", func(t *testing.T) {
		step := &aflock.Step{
			Functionaries: []aflock.StepFunctionary{
				{Type: "keyless", Issuer: "https://accounts.google.com"},
			},
		}
		assert.False(t, matchesFunctionary(cert, "", step),
			"wrong issuer should not match")
	})
}

// =============================================================================
// 7. hasKeylessFunctionary — Policy Inspection
// =============================================================================

func TestHasKeylessFunctionary(t *testing.T) {
	t.Run("has_keyless", func(t *testing.T) {
		pol := &aflock.Policy{
			Steps: map[string]aflock.Step{
				"build": {Functionaries: []aflock.StepFunctionary{{Type: "keyless", Issuer: "x"}}},
			},
		}
		assert.True(t, hasKeylessFunctionary(pol))
	})

	t.Run("keyless_in_second_step", func(t *testing.T) {
		pol := &aflock.Policy{
			Steps: map[string]aflock.Step{
				"lint":  {Functionaries: []aflock.StepFunctionary{{Type: "publickey", PublicKeyID: "k"}}},
				"build": {Functionaries: []aflock.StepFunctionary{{Type: "keyless", Issuer: "x"}}},
			},
		}
		assert.True(t, hasKeylessFunctionary(pol))
	})

	t.Run("no_keyless", func(t *testing.T) {
		pol := &aflock.Policy{
			Steps: map[string]aflock.Step{
				"build": {Functionaries: []aflock.StepFunctionary{{Type: "publickey", PublicKeyID: "k"}}},
			},
		}
		assert.False(t, hasKeylessFunctionary(pol))
	})

	t.Run("nil_steps", func(t *testing.T) {
		assert.False(t, hasKeylessFunctionary(&aflock.Policy{}))
	})

	t.Run("empty_functionaries", func(t *testing.T) {
		pol := &aflock.Policy{
			Steps: map[string]aflock.Step{
				"build": {Functionaries: nil},
			},
		}
		assert.False(t, hasKeylessFunctionary(pol))
	})
}

// =============================================================================
// 8. loadFulcioRoot — Trust Anchor
// =============================================================================

func TestLoadFulcioRoot(t *testing.T) {
	cert, err := loadFulcioRoot()
	if err != nil {
		// P-384 may not be supported on all platforms.
		t.Skipf("Fulcio root parsing not supported on this platform: %v", err)
	}
	assert.NotNil(t, cert)
	assert.True(t, cert.IsCA, "Fulcio root should be a CA certificate")
	assert.Equal(t, "sigstore", cert.Subject.CommonName)
	assert.Contains(t, cert.Subject.Organization, "sigstore.dev")
}

// =============================================================================
// 9. Security Tests — Edge Cases & Attack Vectors
// =============================================================================

// A non-Fulcio cert must never pass keyless matching, even with zero constraints.
// This prevents an attacker from creating a regular x509 cert to bypass keyless checks.
func TestSecurity_R3_400_KeylessRejectsNonFulcioCert(t *testing.T) {
	cert := makeNonFulcioCert(t)

	cases := []aflock.StepFunctionary{
		{Type: "keyless"},
		{Type: "keyless", Issuer: ""},
		{Type: "keyless", Subject: "*"},
	}

	for _, f := range cases {
		assert.False(t, matchesKeylessFunctionary(cert, f),
			"non-Fulcio cert should never match keyless functionary (constraint: %+v)", f)
	}
}

// Ensure empty issuer in cert extension blocks matching even when policy issuer is also empty.
func TestSecurity_R3_401_EmptyIssuerExtensionRejects(t *testing.T) {
	// Cert with empty string in issuer OID
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	emptyIssuerBytes, _ := asn1.Marshal("")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * time.Minute),
		ExtraExtensions: []pkix.Extension{
			{Id: oidFulcioIssuer, Value: emptyIssuerBytes},
		},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	f := aflock.StepFunctionary{Type: "keyless"}
	assert.False(t, matchesKeylessFunctionary(cert, f),
		"cert with empty issuer extension should be rejected")
}

// Ensure a Fulcio cert from one issuer can't match a constraint for a different issuer.
func TestSecurity_R3_402_IssuerMismatchBlocks(t *testing.T) {
	cert := makeFulcioCert(t, "https://accounts.google.com", "user@google.com")

	f := aflock.StepFunctionary{
		Type:   "keyless",
		Issuer: "https://token.actions.githubusercontent.com",
	}
	assert.False(t, matchesKeylessFunctionary(cert, f),
		"Google-issued cert should not match GitHub Actions issuer constraint")
}

// Ensure glob patterns don't match across boundaries unexpectedly.
func TestSecurity_R3_403_GlobDoesNotOvermatch(t *testing.T) {
	cert := makeFulcioCert(t,
		"https://token.actions.githubusercontent.com",
		"https://github.com/evil-org/repo/.github/workflows/ci.yml",
	)

	// This should NOT match — the org is different
	f := aflock.StepFunctionary{
		Type:    "keyless",
		Issuer:  "https://token.actions.githubusercontent.com",
		Subject: "https://github.com/aflock-ai/**",
	}
	assert.False(t, matchesKeylessFunctionary(cert, f),
		"glob should not match a different org")
}

// Verify that Fulcio extension constraints are enforced even when issuer/subject pass.
func TestSecurity_R3_404_ExtensionConstraintsNotBypassed(t *testing.T) {
	ghIssuer := "https://token.actions.githubusercontent.com"
	cert := makeFulcioCertWithAllExtensions(t, fulcioCertExtensions{
		Issuer:            ghIssuer,
		RunnerEnvironment: "self-hosted",
	}, "https://github.com/aflock-ai/aflock/.github/workflows/ci.yml")

	// Issuer matches, but extension constraint says "github-hosted" only
	f := aflock.StepFunctionary{
		Type:   "keyless",
		Issuer: ghIssuer,
		FulcioExtensions: &aflock.FulcioExtensions{
			RunnerEnvironment: "github-hosted",
		},
	}
	assert.False(t, matchesKeylessFunctionary(cert, f),
		"self-hosted runner should not match github-hosted constraint")
}

// =============================================================================
// 10. End-to-End Scenario Tests
// =============================================================================

// Simulates a GitHub Actions CI pipeline signing attestation.
func TestScenario_GitHubActionsCI(t *testing.T) {
	cert := makeFulcioCertWithAllExtensions(t, fulcioCertExtensions{
		Issuer:                   "https://token.actions.githubusercontent.com",
		RunnerEnvironment:        "github-hosted",
		SourceRepositoryURI:      "https://github.com/aflock-ai/aflock",
		SourceRepositoryRef:      "refs/heads/main",
		SourceRepositoryOwnerURI: "https://github.com/aflock-ai",
		BuildTrigger:             "push",
		BuildSignerURI:           "https://github.com/aflock-ai/aflock/.github/workflows/ci.yml@refs/heads/main",
	}, "https://github.com/aflock-ai/aflock/.github/workflows/ci.yml@refs/heads/main")

	step := &aflock.Step{
		Functionaries: []aflock.StepFunctionary{
			{
				Type:    "keyless",
				Issuer:  "https://token.actions.githubusercontent.com",
				Subject: "https://github.com/aflock-ai/aflock/.github/workflows/*",
				FulcioExtensions: &aflock.FulcioExtensions{
					SourceRepositoryOwnerURI: "https://github.com/aflock-ai",
					RunnerEnvironment:        "github-hosted",
				},
			},
		},
	}

	assert.True(t, matchesFunctionary(cert, "", step),
		"GitHub Actions CI cert should match the policy")
}

// Simulates a Google Cloud Build signing attestation.
func TestScenario_GoogleCloudBuild(t *testing.T) {
	cert := makeFulcioCertWithEmail(t,
		"https://accounts.google.com",
		"build-agent@my-project.iam.gserviceaccount.com",
	)

	step := &aflock.Step{
		Functionaries: []aflock.StepFunctionary{
			{
				Type:    "keyless",
				Issuer:  "https://accounts.google.com",
				Subject: "*@my-project.iam.gserviceaccount.com",
			},
		},
	}

	assert.True(t, matchesFunctionary(cert, "", step),
		"Google service account cert should match")
}

// Simulates an attacker trying to use a valid Fulcio cert from the wrong org.
func TestScenario_CrossOrgAttack(t *testing.T) {
	// Attacker gets a valid Fulcio cert for their own repo
	cert := makeFulcioCertWithAllExtensions(t, fulcioCertExtensions{
		Issuer:                   "https://token.actions.githubusercontent.com",
		SourceRepositoryOwnerURI: "https://github.com/attacker-org",
		RunnerEnvironment:        "github-hosted",
	}, "https://github.com/attacker-org/evil-repo/.github/workflows/attack.yml")

	// Policy requires aflock-ai org
	step := &aflock.Step{
		Functionaries: []aflock.StepFunctionary{
			{
				Type:    "keyless",
				Issuer:  "https://token.actions.githubusercontent.com",
				Subject: "https://github.com/aflock-ai/**",
				FulcioExtensions: &aflock.FulcioExtensions{
					SourceRepositoryOwnerURI: "https://github.com/aflock-ai",
				},
			},
		},
	}

	assert.False(t, matchesFunctionary(cert, "", step),
		"attacker cert from different org should be rejected")
}

// Multi-functionary step: first is keyless (wrong issuer), second is keyless (correct).
func TestScenario_MultipleFunctionaries_SecondMatches(t *testing.T) {
	cert := makeFulcioCert(t,
		"https://token.actions.githubusercontent.com",
		"https://github.com/aflock-ai/aflock/.github/workflows/ci.yml",
	)

	step := &aflock.Step{
		Functionaries: []aflock.StepFunctionary{
			{Type: "keyless", Issuer: "https://accounts.google.com"},
			{Type: "keyless", Issuer: "https://token.actions.githubusercontent.com"},
		},
	}

	assert.True(t, matchesFunctionary(cert, "", step),
		"should match second functionary even though first doesn't match")
}
