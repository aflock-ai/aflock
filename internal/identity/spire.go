// Package identity provides SPIRE/SPIFFE workload identity integration.
package identity

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	// DefaultSocketPath is the default SPIRE workload API socket path.
	DefaultSocketPath = "unix:///tmp/spire-agent/public/api.sock"
	// EnvSocketPath is the environment variable for the socket path.
	EnvSocketPath = "SPIFFE_ENDPOINT_SOCKET"
	// TrustDomain is the SPIFFE trust domain for aflock.
	TrustDomain = "aflock.ai"
)

// TrustedModel contains the SPIFFE ID and selector for a trusted AI model.
type TrustedModel struct {
	SPIFFEID string
	Selector string // e.g., "aflock:model:claude-opus-4-5-20251101"
}

// TrustedModels maps Claude model names to their SPIFFE IDs and selectors.
var TrustedModels = map[string]TrustedModel{
	"claude-opus-4-5-20251101": {
		SPIFFEID: "spiffe://aflock.ai/agent/claude-opus-4-5",
		Selector: "aflock:model:claude-opus-4-5-20251101",
	},
	"claude-sonnet-4-20250514": {
		SPIFFEID: "spiffe://aflock.ai/agent/claude-sonnet-4",
		Selector: "aflock:model:claude-sonnet-4-20250514",
	},
	"claude-3-5-haiku-20241022": {
		SPIFFEID: "spiffe://aflock.ai/agent/claude-haiku-3-5",
		Selector: "aflock:model:claude-3-5-haiku-20241022",
	},
	"claude-opus-4-6": {
		SPIFFEID: "spiffe://aflock.ai/agent/claude-opus-4-6",
		Selector: "aflock:model:claude-opus-4-6",
	},
}

// SpireClient connects to a SPIRE agent for workload identity.
type SpireClient struct {
	socketPath string
	client     *workloadapi.Client
}

// NewSpireClient creates a new SPIRE workload API client.
func NewSpireClient(socketPath string) *SpireClient {
	if socketPath == "" {
		socketPath = os.Getenv(EnvSocketPath)
	}
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return &SpireClient{
		socketPath: socketPath,
	}
}

// Connect establishes connection to the SPIRE workload API.
func (c *SpireClient) Connect(ctx context.Context) error {
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(c.socketPath))
	if err != nil {
		return fmt.Errorf("failed to connect to SPIRE workload API: %w", err)
	}
	c.client = client
	return nil
}

// Close closes the connection.
func (c *SpireClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// FetchX509SVID fetches an X.509 SVID from SPIRE.
func (c *SpireClient) FetchX509SVID(ctx context.Context) (*x509svid.SVID, error) {
	if c.client == nil {
		return nil, fmt.Errorf("client not connected")
	}
	return c.client.FetchX509SVID(ctx)
}

// FetchX509Context fetches the full X.509 context including trust bundles.
func (c *SpireClient) FetchX509Context(ctx context.Context) (*workloadapi.X509Context, error) {
	if c.client == nil {
		return nil, fmt.Errorf("client not connected")
	}
	return c.client.FetchX509Context(ctx)
}

// WatchX509Context watches for X.509 SVID updates.
func (c *SpireClient) WatchX509Context(ctx context.Context, watcher workloadapi.X509ContextWatcher) error {
	if c.client == nil {
		return fmt.Errorf("client not connected")
	}
	return c.client.WatchX509Context(ctx, watcher)
}

// Identity represents a resolved agent identity from SPIRE.
type Identity struct {
	SPIFFEID    spiffeid.ID
	Certificate *x509.Certificate
	PrivateKey  interface{}
	TrustBundle []*x509.Certificate
	ExpiresAt   time.Time
}

// GetIdentity fetches and returns the current workload identity.
func (c *SpireClient) GetIdentity(ctx context.Context) (*Identity, error) {
	x509Ctx, err := c.FetchX509Context(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch X509 context: %w", err)
	}

	svid := x509Ctx.DefaultSVID()
	if svid == nil {
		return nil, fmt.Errorf("no SVID available")
	}

	certs := svid.Certificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in SVID")
	}

	// Get trust bundle for the SPIFFE ID's trust domain
	bundle, ok := x509Ctx.Bundles.Get(svid.ID.TrustDomain())
	if !ok {
		return nil, fmt.Errorf("no trust bundle for trust domain %s", svid.ID.TrustDomain())
	}

	return &Identity{
		SPIFFEID:    svid.ID,
		Certificate: certs[0],
		PrivateKey:  svid.PrivateKey,
		TrustBundle: bundle.X509Authorities(),
		ExpiresAt:   certs[0].NotAfter,
	}, nil
}

// IsAvailable checks if SPIRE workload API is available.
func (c *SpireClient) IsAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := c.Connect(ctx); err != nil {
		return false
	}
	defer func() { _ = c.Close() }()

	_, err := c.FetchX509SVID(ctx)
	return err == nil
}

// MustHaveSPIRE returns an error if SPIRE is not available.
func MustHaveSPIRE() error {
	client := NewSpireClient("")
	if !client.IsAvailable() {
		return fmt.Errorf("SPIRE workload API not available at %s (set %s to override)",
			client.socketPath, EnvSocketPath)
	}
	return nil
}

// IsTrustedModel checks if the given model name is in the trusted models list.
func IsTrustedModel(modelName string) bool {
	_, ok := TrustedModels[modelName]
	return ok
}
