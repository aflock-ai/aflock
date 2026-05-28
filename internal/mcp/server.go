// Package mcp implements an MCP server for aflock policy enforcement.
package mcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/aflock-ai/aflock/internal/attestation"
	"github.com/aflock-ai/aflock/internal/auth"
	"github.com/aflock-ai/aflock/internal/identity"
	"github.com/aflock-ai/aflock/internal/identity/peercred"
	"github.com/aflock-ai/aflock/internal/policy"
	"github.com/aflock-ai/aflock/internal/state"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Server is the aflock MCP server.
type Server struct {
	mcpServer     *server.MCPServer
	stateManager  *state.Manager
	policy        *aflock.Policy
	policyPath    string
	agentIdentity *identity.AgentIdentity
	sessionID     string

	// (`mu` + `materials` were dead code after issue #61 / M7 removed the
	// duplicate in-memory data-flow evaluation in handleBash. Removed
	// entirely to satisfy golangci-lint's unused check.)
	signer         *attestation.Signer
	signingEnabled bool
	signingMode    string     // "spire", "fulcio", "ephemeral", or "" — set by initSigning, read by initAuth (#71)
	attestDir      string     // Directory for storing step attestations by git tree hash
	sessionMu      sync.Mutex // Protects session state access for dataFlow tracking

	// JWT authorization
	tokenIssuer *auth.TokenIssuer

	// authActive is set to true the moment any goroutine starts processing
	// a get_token request, so concurrent tool-call goroutines can no longer
	// observe a stale "no token issued" state from disk. Closes the TOCTOU
	// race in issue #59 / H11. atomic.Bool gives us a lock-free fast path
	// for every validateJWT call.
	authActive atomic.Bool

	// requireToken, when true, denies any tool call that arrives without a
	// valid JWT — even before the first get_token call. Toggled via the
	// AFLOCK_REQUIRE_TOKEN=1 env var. Closes the unauthenticated bootstrap
	// window (issue #59 / M10). Default false for backward compatibility.
	requireToken bool

	// transportMode records which Serve* method was invoked: "stdio", "unix",
	// or "http". get_token's bootstrap-secret gate (issue #42) is scoped to
	// "http" because stdio inherits process-tree isolation and unix has
	// SO_PEERCRED + UID-match at accept time — both already prove same-UID
	// without an extra secret. Empty until a Serve* method runs.
	transportMode string

	// httpBootstrapSecret is the random secret a caller must present (via the
	// _bootstrap arg) to get_token in HTTP transport mode (issue #42). It's
	// generated when ServeHTTP starts, written to a 0600 file under the
	// session dir so only the same-UID caller can read it, and cleared from
	// memory + disk once consumed (one-time use).
	httpBootstrapSecret      string
	httpBootstrapSecretPath  string
	httpBootstrapSecretMu    sync.Mutex
}

// NewServer creates a new aflock MCP server.
func NewServer() *Server {
	// Default attestation directory: ~/.aflock/attestations
	homeDir, _ := os.UserHomeDir()
	attestDir := filepath.Join(homeDir, ".aflock", "attestations")

	s := &Server{
		stateManager: state.NewManager(""),
		sessionID:    fmt.Sprintf("mcp-%s", uuid.New().String()),
		attestDir:    attestDir,
		requireToken: os.Getenv("AFLOCK_REQUIRE_TOKEN") == "1",
	}

	// Create the MCP server
	s.mcpServer = server.NewMCPServer(
		"aflock",
		"0.1.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, false),
	)

	// Register tools
	s.registerTools()

	return s
}

// registerTools registers all aflock MCP tools.
func (s *Server) registerTools() {
	// get_identity - Return the agent's derived identity
	s.mcpServer.AddTool(
		mcp.NewTool("get_identity",
			mcp.WithDescription("Get the derived agent identity including model, environment, and policy"),
		),
		s.handleGetIdentity,
	)

	// get_policy - Return the loaded policy
	s.mcpServer.AddTool(
		mcp.NewTool("get_policy",
			mcp.WithDescription("Get the currently loaded .aflock policy"),
		),
		s.handleGetPolicy,
	)

	// check_tool - Check if a tool call would be allowed
	s.mcpServer.AddTool(
		mcp.NewTool("check_tool",
			mcp.WithDescription("Check if a tool call would be allowed by the policy"),
			mcp.WithString("tool_name", mcp.Required(), mcp.Description("Name of the tool to check")),
			mcp.WithObject("tool_input", mcp.Description("Tool input parameters")),
		),
		s.handleCheckTool,
	)

	// bash - Execute a command with policy enforcement and attestation
	s.mcpServer.AddTool(
		mcp.NewTool("bash",
			mcp.WithDescription("Execute a bash command with policy enforcement. Set attest=true for validation commands to create attestations."),
			mcp.WithString("command", mcp.Required(), mcp.Description("The command to execute")),
			mcp.WithNumber("timeout", mcp.Description("Timeout in seconds (default: 30)")),
			mcp.WithString("workdir", mcp.Description("Working directory for command execution")),
			mcp.WithBoolean("attest", mcp.Description("Set true for validation commands (lint, test, build) to create attestation")),
			mcp.WithString("step", mcp.Description("Step name for policy verification (e.g., 'lint', 'test', 'build'). Required if attest=true")),
			mcp.WithString("reason", mcp.Description("Why this command is being attested (for audit trail)")),
		),
		s.handleBash,
	)

	// read_file - Read a file with policy enforcement
	s.mcpServer.AddTool(
		mcp.NewTool("read_file",
			mcp.WithDescription("Read a file with policy enforcement"),
			mcp.WithString("path", mcp.Required(), mcp.Description("Path to the file to read")),
		),
		s.handleReadFile,
	)

	// write_file - Write a file with policy enforcement
	s.mcpServer.AddTool(
		mcp.NewTool("write_file",
			mcp.WithDescription("Write content to a file with policy enforcement"),
			mcp.WithString("path", mcp.Required(), mcp.Description("Path to the file to write")),
			mcp.WithString("content", mcp.Required(), mcp.Description("Content to write")),
		),
		s.handleWriteFile,
	)

	// get_session - Get current session info
	s.mcpServer.AddTool(
		mcp.NewTool("get_session",
			mcp.WithDescription("Get current session information including metrics"),
		),
		s.handleGetSession,
	)

	// get_token - Get a JWT for authenticated MCP calls
	s.mcpServer.AddTool(
		mcp.NewTool("get_token",
			mcp.WithDescription("Get a JWT authorization token for this session. The token encodes agent identity, policy scope, and allowed tools."),
		),
		s.handleGetToken,
	)

	// sign_attestation - Sign an attestation for arbitrary data
	s.mcpServer.AddTool(
		mcp.NewTool("sign_attestation",
			mcp.WithDescription("Sign an attestation for arbitrary data using SPIRE identity"),
			mcp.WithString("predicate_type", mcp.Required(), mcp.Description("Predicate type URI (e.g., https://example.com/predicate/v1)")),
			mcp.WithObject("predicate", mcp.Required(), mcp.Description("Predicate data to attest")),
			mcp.WithObject("subject", mcp.Description("Subject to bind attestation to (name and digest)")),
		),
		s.handleSignAttestation,
	)

	// Paper-named tools (issue #117, paper §3.3). aflock_authorize and
	// aflock_attest are aliases of check_tool and sign_attestation so
	// readers of the paper can probe the server with the names the paper
	// uses. check_tool and sign_attestation remain registered for
	// backward compatibility.

	// aflock_authorize - Paper §3.3 alias of check_tool.
	s.mcpServer.AddTool(
		mcp.NewTool("aflock_authorize",
			mcp.WithDescription("Request authorization for an action (paper §3.3). Alias of check_tool."),
			mcp.WithString("tool_name", mcp.Required(), mcp.Description("Name of the tool to check")),
			mcp.WithObject("tool_input", mcp.Description("Tool input parameters")),
		),
		s.handleCheckTool,
	)

	// aflock_attest - Paper §3.3 alias of sign_attestation.
	s.mcpServer.AddTool(
		mcp.NewTool("aflock_attest",
			mcp.WithDescription("Record an action — server signs attestation (paper §3.3). Alias of sign_attestation."),
			mcp.WithString("predicate_type", mcp.Required(), mcp.Description("Predicate type URI")),
			mcp.WithObject("predicate", mcp.Required(), mcp.Description("Predicate data to attest")),
			mcp.WithObject("subject", mcp.Description("Subject to bind attestation to (name and digest)")),
		),
		s.handleSignAttestation,
	)

	// aflock_check_limits - Paper §3.3, returns remaining budget per limit.
	s.mcpServer.AddTool(
		mcp.NewTool("aflock_check_limits",
			mcp.WithDescription("Query remaining budget against each declared policy limit (paper §3.3)."),
		),
		s.handleCheckLimits,
	)

	// aflock_delegate - Paper §3.3, creates a sublayout binding for a sub-agent.
	s.mcpServer.AddTool(
		mcp.NewTool("aflock_delegate",
			mcp.WithDescription("Create a sublayout binding for a sub-agent (paper §3.3). Validates the named sublayout against parent attenuation, writes a propagation record, and returns an attenuated child JWT."),
			mcp.WithString("sublayout_name", mcp.Required(), mcp.Description("Name of a sublayout declared in the parent policy")),
			mcp.WithString("child_session_id", mcp.Description("Optional pre-bound child session ID; one is generated if omitted")),
		),
		s.handleDelegate,
	)
}

// Serve starts the MCP server on stdio.
func (s *Server) Serve(policyPath string) error {
	s.transportMode = "stdio"
	// Load policy if path provided
	if policyPath != "" {
		pol, path, err := policy.Load(policyPath)
		if err != nil {
			return fmt.Errorf("load policy: %w", err)
		}
		s.policy = pol
		s.policyPath = path
	} else {
		// Try to load from current directory
		cwd, _ := os.Getwd()
		pol, path, err := policy.Load(cwd)
		if err == nil {
			s.policy = pol
			s.policyPath = path
		}
	}

	// Refuse to start with an already-expired policy (#136). Mirrors hooks
	// mode (handler.go) and verify CLI; MCP mode previously skipped this and
	// served past Expires.
	if err := s.errPolicyExpired(); err != nil {
		return err
	}

	// Identity discovery + policy-digest binding per paper §3.1.
	s.initAgentIdentity()

	// Initialize attestation signing with 3-tier fallback (SPIRE → Fulcio → ephemeral).
	s.initSigning()

	// Initialize JWT authorization
	if err := s.initAuth(); err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: JWT auth unavailable: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "[aflock] JWT authorization enabled\n")
	}

	// Initialize session state if we have a policy
	if s.policy != nil {
		sessionState := s.stateManager.Initialize(s.sessionID, s.policy, s.policyPath)
		if err := s.stateManager.Save(sessionState); err != nil {
			fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to save session: %v\n", err)
		}
		fmt.Fprintf(os.Stderr, "[aflock] MCP server started with policy: %s\n", s.policy.Name)
	} else {
		fmt.Fprintf(os.Stderr, "[aflock] MCP server started (no policy loaded)\n")
	}

	// Serve on stdio
	return server.ServeStdio(s.mcpServer)
}

// projectRoot returns the directory containing the policy file.
func (s *Server) projectRoot() string {
	if s.policyPath != "" {
		return filepath.Dir(s.policyPath)
	}
	cwd, _ := os.Getwd()
	return cwd
}

// ServeHTTP starts the MCP server on HTTP with SSE transport.
// This keeps the server running so session state persists across calls.
//
// SECURITY (issue #42): unlike stdio (process-tree isolation) and Unix-domain
// (SO_PEERCRED + UID check at accept), HTTP/SSE has no kernel-attested peer
// identity — any local process at any UID could reach 127.0.0.1:port and
// mint a JWT via get_token. To close that bootstrap gap, ServeHTTP writes a
// random secret to a 0600 file under the session dir. get_token in HTTP
// mode requires the caller to present this secret via the _bootstrap arg;
// since the file is same-UID-only by FS permission, this matches the trust
// boundary the other transports get for free. The secret is one-time-use
// and removed after the first successful get_token.
func (s *Server) ServeHTTP(policyPath string, port int) error {
	s.transportMode = "http"
	// Load policy if path provided
	if policyPath != "" {
		pol, path, err := policy.Load(policyPath)
		if err != nil {
			return fmt.Errorf("load policy: %w", err)
		}
		s.policy = pol
		s.policyPath = path
	} else {
		// Try to load from current directory
		cwd, _ := os.Getwd()
		pol, path, err := policy.Load(cwd)
		if err == nil {
			s.policy = pol
			s.policyPath = path
		}
	}

	// Refuse to start with an already-expired policy (#136).
	if err := s.errPolicyExpired(); err != nil {
		return err
	}

	// Identity discovery + policy-digest binding per paper §3.1. Mirrors
	// Serve() — previously missing on the HTTP transport, which caused JWTs
	// issued via SSE to have empty identity_hash and attestations to miss
	// the agent-identity predicate. Caught in PR #67 review.
	s.initAgentIdentity()

	// Initialize attestation signing with 3-tier fallback (SPIRE → Fulcio → ephemeral).
	s.initSigning()

	// Initialize JWT authorization
	if err := s.initAuth(); err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: JWT auth unavailable: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "[aflock] JWT authorization enabled\n")
	}

	// Initialize session state if we have a policy
	if s.policy != nil {
		sessionState := s.stateManager.Initialize(s.sessionID, s.policy, s.policyPath)
		if err := s.stateManager.Save(sessionState); err != nil {
			fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to save session: %v\n", err)
		}
		fmt.Fprintf(os.Stderr, "[aflock] HTTP MCP server starting with policy: %s\n", s.policy.Name)
	} else {
		fmt.Fprintf(os.Stderr, "[aflock] HTTP MCP server starting (no policy loaded)\n")
	}

	// Issue #42: HTTP transport has no kernel-attested peer, so guard
	// get_token behind a same-UID-readable bootstrap secret. Refuse to start
	// if the secret can't be written — failing closed beats running an
	// unauthenticated token dispenser.
	if err := s.initHTTPBootstrapSecret(); err != nil {
		return fmt.Errorf("init HTTP bootstrap secret: %w", err)
	}

	// Create SSE server
	sseServer := server.NewSSEServer(s.mcpServer)

	// Set up HTTP handler
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Fprintf(os.Stderr, "[aflock] MCP server listening on http://%s/sse\n", addr)
	fmt.Fprintf(os.Stderr, "[aflock] Session ID: %s (state will persist across calls)\n", s.sessionID)
	fmt.Fprintf(os.Stderr, "[aflock] HTTP bootstrap secret: %s (0600 — pass via _bootstrap arg on get_token)\n", s.httpBootstrapSecretPath)

	return http.ListenAndServe(addr, sseServer) //nolint:gosec // G114: HTTP server with no timeout is acceptable for local MCP
}

// initHTTPBootstrapSecret generates a 32-byte random secret and writes it to
// a 0600 file under the session dir (issue #42). Returns an error if the
// secret cannot be generated or persisted — ServeHTTP fails closed rather
// than running without the gate. The path is recorded on the Server so
// handleGetToken can read it back, compare in constant time, and remove the
// file on first successful use.
func (s *Server) initHTTPBootstrapSecret() error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("generate bootstrap secret: %w", err)
	}
	secret := hex.EncodeToString(raw)

	sessionDir := s.stateManager.SessionDir(s.sessionID)
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}
	path := filepath.Join(sessionDir, "http-bootstrap-secret")
	if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
		return fmt.Errorf("write bootstrap secret: %w", err)
	}

	s.httpBootstrapSecretMu.Lock()
	s.httpBootstrapSecret = secret
	s.httpBootstrapSecretPath = path
	s.httpBootstrapSecretMu.Unlock()
	return nil
}

// verifyHTTPBootstrapSecret performs a constant-time comparison between the
// presented secret and the in-memory secret WITHOUT clearing on match. The
// caller is expected to clear via clearHTTPBootstrapSecret only after the
// downstream operation (token issuance) succeeds — otherwise a transient
// IssueToken failure would burn the only credential the client has, locking
// the session out until server restart (Copilot review on PR #109).
func (s *Server) verifyHTTPBootstrapSecret(presented string) bool {
	s.httpBootstrapSecretMu.Lock()
	defer s.httpBootstrapSecretMu.Unlock()
	if s.httpBootstrapSecret == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.httpBootstrapSecret)) == 1
}

// clearHTTPBootstrapSecret zeroes the in-memory secret and removes the
// on-disk file. Idempotent. Called only after a successful get_token
// issuance so that a one-time-use guarantee holds without burning the
// credential on retriable failures.
func (s *Server) clearHTTPBootstrapSecret() {
	s.httpBootstrapSecretMu.Lock()
	defer s.httpBootstrapSecretMu.Unlock()
	s.httpBootstrapSecret = ""
	if s.httpBootstrapSecretPath != "" {
		_ = os.Remove(s.httpBootstrapSecretPath)
		s.httpBootstrapSecretPath = ""
	}
}

// ServeUnix starts the MCP server on a Unix-domain-socket transport with
// kernel-attested peer-credential identity (issue #63).
//
// On accept, the server extracts the connecting peer's PID via SO_PEERCRED
// (Linux) or LOCAL_PEERPID (macOS), drives identity discovery from that PID
// (rather than os.Getppid()), and serves a single MCP session as JSON-RPC
// over the connection. The socket is created with 0600 permissions and
// removed on shutdown. Refuses to start if the socket path already exists,
// to avoid a hijack race against an attacker who pre-creates it.
//
// The parent directory of socketPath MUST be owned by the current UID and
// have mode 0700; otherwise we refuse to bind. This closes the
// Lstat→Listen window where a local attacker on a world-writable parent
// (e.g. /tmp) could pre-create the socket between our existence check
// and net.Listen. Operators should pass a path under a private dir like
// `~/.aflock/aflock.sock` rather than `/tmp/aflock.sock`.
//
// Single-session-per-process by design: the connection itself is the MCP
// session, and the kernel-attested PID is bound to that session's
// identity. After the peer disconnects, this function returns; a second
// client requires the operator to re-run `aflock serve --unix`. This
// matches the stdio transport's lifecycle.
func (s *Server) ServeUnix(policyPath, socketPath string) error {
	s.transportMode = "unix"
	if socketPath == "" {
		return fmt.Errorf("socket path is required")
	}

	// Load policy if path provided
	if policyPath != "" {
		pol, path, err := policy.Load(policyPath)
		if err != nil {
			return fmt.Errorf("load policy: %w", err)
		}
		s.policy = pol
		s.policyPath = path
	} else {
		cwd, _ := os.Getwd()
		pol, path, err := policy.Load(cwd)
		if err == nil {
			s.policy = pol
			s.policyPath = path
		}
	}

	// Refuse to start with an already-expired policy (#136).
	if err := s.errPolicyExpired(); err != nil {
		return err
	}

	// Refuse to start if the socket path already exists. Lstat (not Stat)
	// so a dangling symlink also blocks us — an attacker pre-creating either
	// a file or a symlink at the path could otherwise win the bind race.
	if _, err := os.Lstat(socketPath); err == nil {
		return fmt.Errorf("socket path %q already exists; refusing to bind (avoid hijack race)", socketPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat socket path: %w", err)
	}

	parentDir := filepath.Dir(socketPath)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}

	// MkdirAll is a no-op on existing directories — it does NOT tighten
	// existing perms. Verify the parent is 0700 and owned by us before
	// binding; otherwise the Lstat→Listen window can be won by a local
	// attacker on a world-writable parent (PR #88 review, colek42).
	if err := assertParentDirSecure(parentDir); err != nil {
		return fmt.Errorf("refusing to bind under insecure parent dir: %w", err)
	}

	// Set umask 0077 around the bind so the socket is created with 0600
	// permissions from the very first instant it exists on disk — closes
	// the window where the umask-default-permissioned socket would be
	// reachable before our explicit Chmod fires.
	restoreUmask := withRestrictiveUmask()
	listener, err := net.Listen("unix", socketPath)
	restoreUmask()
	if err != nil {
		return fmt.Errorf("listen unix: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()

	// Defense in depth: explicitly Chmod 0600 in case a future refactor
	// drops the umask wrapper. With umask 0077 above, the bind already
	// created the socket as 0600.
	if err := os.Chmod(socketPath, 0600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[aflock] MCP server listening on unix://%s (peer-cred identity)\n", socketPath)

	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Stop accepting further connections once we have one — single-session
	// model. Closing the listener also unlinks-on-defer above.
	_ = listener.Close()

	pc, err := peercred.FromConn(conn)
	if err != nil {
		return fmt.Errorf("extract peer credentials: %w", err)
	}

	// Defense in depth: refuse cross-UID connections explicitly. The 0600
	// socket and same-UID requirement of /proc/<pid>/environ already make
	// this fail in practice on Linux, but an explicit check makes the
	// trust boundary unambiguous and keeps the property intact if UDS
	// perms are ever loosened (PR #88 review, colek42).
	//nolint:gosec // G115: os.Getuid() is non-negative on unix
	if pc.UID != uint32(os.Getuid()) {
		return fmt.Errorf("peer uid %d does not match server uid %d (refusing cross-UID connection)", pc.UID, os.Getuid())
	}

	fmt.Fprintf(os.Stderr, "[aflock] peer credentials: pid=%d uid=%d gid=%d\n", pc.PID, pc.UID, pc.GID)

	// Identity discovery + policy-digest binding from kernel-attested peer
	// credentials. PID, UID, and GID all come from the kernel — and the
	// peer's binary digest, container ID, and environment are read from
	// the peer's PID directly, not from aflock's own process state.
	//
	// Fail closed: if peer-binary attestation fails (e.g. PID recycled
	// between SO_PEERCRED and our /proc/<pid>/exe read on Linux, or peer
	// already gone on Darwin), refuse to serve rather than silently fall
	// back to a heuristic identity. The whole point of the UDS transport
	// is that we don't lie about who's connected.
	if err := s.initAgentIdentityFromPeer(pc); err != nil {
		return fmt.Errorf("peer identity attestation failed (refusing to serve): %w", err)
	}

	s.initSigning()
	if err := s.initAuth(); err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: JWT auth unavailable: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "[aflock] JWT authorization enabled\n")
	}

	if s.policy != nil {
		sessionState := s.stateManager.Initialize(s.sessionID, s.policy, s.policyPath)
		if err := s.stateManager.Save(sessionState); err != nil {
			fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to save session: %v\n", err)
		}
		fmt.Fprintf(os.Stderr, "[aflock] MCP server started with policy: %s\n", s.policy.Name)
	} else {
		fmt.Fprintf(os.Stderr, "[aflock] MCP server started (no policy loaded)\n")
	}

	// Serve a single MCP session as JSON-RPC over the UDS connection. The
	// connection is both Reader and Writer — same framing the stdio transport
	// uses, just over a socket whose peer is kernel-attested.
	stdioServer := server.NewStdioServer(s.mcpServer)
	return stdioServer.Listen(context.Background(), conn, conn)
}

// errPolicyExpired returns a formatted error if the loaded policy has passed
// its Expires deadline. Returns nil if no policy is loaded or no Expires is
// set. Used at server startup (Serve/ServeHTTP/ServeUnix) to fail closed
// before any session state is initialized, and inside long-lived handlers
// (get_token, check_tool) so a policy that expires mid-session stops serving.
//
// Hooks mode and the verify CLI enforce Expires elsewhere (handler.go,
// verifier.go); without this check, MCP mode silently served expired
// policies — issue #136.
func (s *Server) errPolicyExpired() error {
	if s.policy == nil || !s.policy.IsExpired() {
		return nil
	}
	return fmt.Errorf("policy %q expired at %s", s.policy.Name, s.policy.Expires.Format(time.RFC3339))
}

// computePolicyDigest returns the SHA-256 digest of the loaded policy.
//
// Prefers s.policy.RawDigest (set by policy.Load from the on-disk bytes) so
// the digest binds to the exact file the user signed/reviewed rather than a
// re-marshaled copy of the parsed struct (issue #61 / L5). Falls back to
// marshaling for in-memory policies used in tests.
func (s *Server) computePolicyDigest() string {
	if s.policy == nil {
		return ""
	}
	if s.policy.RawDigest != "" {
		return s.policy.RawDigest
	}
	data, err := json.Marshal(s.policy)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// initAgentIdentity discovers the connecting process's identity, binds it to
// the current policy's digest, and derives the paper §3.1 identity hash
//
//	SHA256(model ‖ env ‖ tools ‖ policyDigest ‖ parent).
//
// Called from both Serve() (stdio) and ServeHTTP() (SSE) so both transports
// produce identically identity-bound JWTs and attestations. Before this was
// extracted, ServeHTTP silently skipped the block, which meant HTTP sessions
// had empty identity_hash in their JWTs and missing agentIdentity in
// attestation predicates (caught in PR #67 review).
//
// A discovery failure is a warning, not a fatal — the process may not be
// under a Claude Code tree yet. Caller is responsible for deciding whether
// to fail closed via policy.identity.allowedModels.
func (s *Server) initAgentIdentity() {
	s.applyAgentIdentity(identity.DiscoverAgentIdentity)
}

// initAgentIdentityFromPeer is the kernel-attested counterpart of
// initAgentIdentity used by the UDS transport. The PID, UID, and GID all
// come from SO_PEERCRED (Linux) or LOCAL_PEERPID + LOCAL_PEERCRED (macOS)
// on the accepted connection — they are not derived from os.Getppid() or
// os.Getuid() and cannot be spoofed by a process renaming itself "claude"
// in a parent slot. The peer's binary path/digest, container ID, and
// environment are also read from the peer's PID directly per paper §3.1.
//
// Returns an error if peer-binary attestation fails. Unlike the
// stdio/HTTP heuristic path, the UDS path treats this as fatal: serving
// a session with an unattestable identity defeats the purpose of the
// kernel-attested transport.
func (s *Server) initAgentIdentityFromPeer(pc peercred.PeerCred) error {
	agentID, err := identity.DiscoverAgentIdentityFromPeer(pc.PID, pc.UID, pc.GID)
	if err != nil {
		return err
	}
	s.agentIdentity = agentID
	if s.policy != nil {
		s.agentIdentity.PolicyDigest = s.computePolicyDigest()
		s.agentIdentity.DeriveIdentity()
	}
	return nil
}

func (s *Server) applyAgentIdentity(discover func() (*identity.AgentIdentity, error)) {
	agentID, err := discover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to discover identity: %v\n", err)
		return
	}
	s.agentIdentity = agentID
	if s.policy != nil {
		s.agentIdentity.PolicyDigest = s.computePolicyDigest()
		s.agentIdentity.DeriveIdentity() // Recompute identity hash with policy
	}
}

// initSigning initializes attestation signing with a 3-tier fallback chain
// matching the hooks mode behavior (handler.go:547-562):
//
//  1. SPIRE — delegated identity from a SPIRE agent (strongest, infrastructure-backed)
//  2. Fulcio — keyless signing via OIDC tokens (CI/CD environments)
//  3. Ephemeral — fresh ECDSA P-256 key (always available, weakest)
//
// The model=unknown check that previously disabled signing is removed —
// an unknown model is recorded in the attestation predicate without
// preventing signing (issue #55).
func (s *Server) initSigning() {
	s.signer = attestation.NewSigner("")
	ctx := context.Background()

	identityHash := ""
	if s.agentIdentity != nil {
		identityHash = s.agentIdentity.IdentityHash
	}

	if err := s.signer.Initialize(ctx); err == nil {
		s.signingEnabled = true
		s.signingMode = "spire"
		fmt.Fprintf(os.Stderr, "[aflock] Attestation signing: SPIRE\n")
		// Note: trusted-model enforcement happens in the policy evaluator via
		// identity.allowedModels at SessionStart (issue #67 review). We no
		// longer call a signer-side SetModel that returned an error but did
		// not actually gate signing — that was dead misleading code.
		return
	}

	if err := s.signer.InitializeFulcio(ctx); err == nil {
		s.signingEnabled = true
		s.signingMode = "fulcio"
		fmt.Fprintf(os.Stderr, "[aflock] Attestation signing: Fulcio (keyless)\n")
		return
	}

	if err := s.signer.InitializeEphemeral(identityHash); err == nil {
		s.signingEnabled = true
		s.signingMode = "ephemeral"
		fmt.Fprintf(os.Stderr, "[aflock] Attestation signing: ephemeral key\n")
		return
	}

	s.signingEnabled = false
	s.signingMode = ""
	fmt.Fprintf(os.Stderr, "[aflock] Warning: attestation signing unavailable (SPIRE, Fulcio, and ephemeral all failed)\n")
}

// initAuth initializes the JWT token issuer. When SPIRE is the active
// signing source, the SVID's ECDSA P-256 key is reused so the JWT shares
// the agent's SPIFFE identity (paper §3.2, issue #71). Fulcio is skipped
// because its cert TTL (~10 min) is shorter than typical JWT TTLs. The
// ephemeral attestation key is process-scoped just like a fresh JWT key,
// so a separate ephemeral key is fine there.
func (s *Server) initAuth() error {
	if s.signingMode == "spire" && s.signer != nil {
		if id, _ := s.signer.GetSigningIdentity(); id != nil {
			if priv, ok := id.PrivateKey.(crypto.Signer); ok {
				if ecPub, ok := priv.Public().(*ecdsa.PublicKey); ok && ecPub.Curve == elliptic.P256() {
					s.tokenIssuer = auth.NewTokenIssuerFromSigner(priv, id.SPIFFEID.String())
					return nil
				}
				fmt.Fprintf(os.Stderr, "[aflock] JWT: SPIRE SVID is not ECDSA P-256, falling back to ephemeral JWT key\n")
			}
		}
	}
	issuer, err := auth.NewTokenIssuer()
	if err != nil {
		return fmt.Errorf("create token issuer: %w", err)
	}
	s.tokenIssuer = issuer
	return nil
}

// handleGetToken issues a JWT for the current session.
//
// In HTTP transport mode (issue #42) the caller must prove same-UID either by
// presenting the bootstrap secret (_bootstrap) on the first call OR by
// presenting a valid existing JWT (_token) on subsequent calls. Either path
// lets the legitimate client refresh tokens after expiry without a server
// restart (Copilot review on PR #109). The bootstrap secret is consumed only
// after a successful IssueToken — a transient signing failure must not burn
// the credential.
//
// stdio and unix transports already prove same-UID via process-tree
// isolation / SO_PEERCRED, so they skip this gate.
func (s *Server) handleGetToken(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.tokenIssuer == nil {
		return mcp.NewToolResultError("Token issuer not initialized"), nil
	}

	// Refuse to mint a token once the policy has expired (#136). The JWT TTL
	// alone is not enough: a long-lived HTTP server can outlive the policy
	// itself, and we must not extend authorization past Expires.
	if err := s.errPolicyExpired(); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Track whether this call authenticated via bootstrap, so we can clear
	// the secret if and only if IssueToken succeeds below.
	usedBootstrap := false
	if s.transportMode == "http" {
		args := request.GetArguments()
		validRefresh := false
		if existing, _ := args["_token"].(string); existing != "" {
			if _, err := s.tokenIssuer.ValidateTokenForSessionAndPolicy(
				existing, s.sessionID, s.computePolicyDigest()); err == nil {
				validRefresh = true
			}
		}
		if !validRefresh {
			presented, _ := args["_bootstrap"].(string)
			if presented == "" {
				return mcp.NewToolResultError("missing _bootstrap arg; HTTP transport requires the secret written at server start (or a valid _token for refresh)"), nil
			}
			if !s.verifyHTTPBootstrapSecret(presented) {
				return mcp.NewToolResultError("invalid or already-consumed bootstrap secret"), nil
			}
			usedBootstrap = true
		}
	}

	ttl := 1 * time.Hour
	if s.policy != nil && s.policy.Limits != nil && s.policy.Limits.MaxWallTimeSeconds != nil {
		ttl = time.Duration(s.policy.Limits.MaxWallTimeSeconds.Value) * time.Second
	}

	agentID := "unknown"
	identityHash := ""
	if s.agentIdentity != nil {
		if spiffeID, err := s.agentIdentity.ToSPIFFEID("aflock.ai"); err == nil {
			agentID = spiffeID.String()
		}
		identityHash = s.agentIdentity.IdentityHash
	}

	// Issue the token BEFORE flipping authActive. If this returns an error,
	// we must leave authActive=false so clients can retry get_token without
	// being locked into require-token mode by a prior failure (PR #67 review
	// finding — originally introduced by the H11 fix in #59).
	tokenStr, err := s.tokenIssuer.IssueToken(
		s.sessionID,
		agentID,
		identityHash,
		s.policy,
		ttl,
	)
	if err != nil {
		// Bootstrap secret stays intact — a retry after fixing the signer
		// must be able to use the same credential (Copilot review on PR #109).
		return mcp.NewToolResultError(fmt.Sprintf("Failed to issue token: %v", err)), nil
	}

	if usedBootstrap {
		s.clearHTTPBootstrapSecret()
	}

	// Persist the token AND flip authActive under sessionMu so concurrent
	// validateJWT observers see a consistent pair:
	//   - before: authActive=false AND no AuthToken on disk (pass, graceful)
	//   - after:  authActive=true  AND AuthToken on disk (require token)
	// There is no intermediate state a racing caller can exploit. This keeps
	// the H11 TOCTOU guarantee intact while fixing the DoS lockout when
	// IssueToken returns an error.
	s.sessionMu.Lock()
	sessionState, _ := s.stateManager.Load(s.sessionID)
	if sessionState != nil {
		sessionState.AuthToken = tokenStr
		_ = s.stateManager.Save(sessionState)
	}
	s.authActive.Store(true)
	s.sessionMu.Unlock()

	result := map[string]any{
		"token":     tokenStr,
		"expiresIn": ttl.String(),
		"sessionId": s.sessionID,
	}
	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// validateJWT validates a JWT token from a tool call request.
//
// Returns the claims if valid, nil if auth is not active, or an error if the
// token is present but invalid.
//
// Enforcement model:
//   - If s.requireToken is true, every call must carry a valid token from the
//     start. Closes the unauthenticated bootstrap window (issue #59 / M10).
//   - Otherwise, "graceful adoption" applies: tool calls without a token are
//     permitted UNTIL the first get_token completes, after which all calls
//     must carry a token. The trigger for "after" is the in-process atomic
//     flag s.authActive, which is set synchronously at the top of
//     handleGetToken — eliminating the TOCTOU race where a stale disk read
//     could miss a freshly issued token (issue #59 / H11).
func (s *Server) validateJWT(request mcp.CallToolRequest) (*auth.AflockClaims, error) {
	if s.tokenIssuer == nil {
		return nil, nil // Auth not initialized, skip validation
	}

	tokenStr, _ := request.GetArguments()["_token"].(string)
	if tokenStr == "" {
		if s.requireToken {
			return nil, fmt.Errorf("missing auth token (_token parameter); server is in require-token mode")
		}
		if s.authActive.Load() {
			return nil, fmt.Errorf("missing auth token (_token parameter)")
		}
		return nil, nil // graceful adoption: no token issued yet
	}

	// Bind validation to the current policy digest so a token issued under a
	// permissive policy does not survive a policy tightening (issue #59 / M11).
	claims, err := s.tokenIssuer.ValidateTokenForSessionAndPolicy(
		tokenStr, s.sessionID, s.computePolicyDigest())
	if err != nil {
		return nil, fmt.Errorf("auth failed: %w", err)
	}

	return claims, nil
}

// signAndStoreAttestation creates a signed attestation for an action and stores it to disk.
//
// jwtBinding is required once authActive is true — i.e., after the first
// successful get_token. Before that ("graceful adoption"), nil is accepted
// to preserve the documented pre-bootstrap window. This closes the issue
// #40 gap where any caller could mint an attestation regardless of JWT
// scope as long as it happened to bypass the tool-handler validation path.
func (s *Server) signAndStoreAttestation(ctx context.Context, record aflock.ActionRecord, jwtBinding *attestation.JWTBinding) error {
	if !s.signingEnabled {
		return fmt.Errorf("attestation signing unavailable (SPIRE, Fulcio, and ephemeral all failed)")
	}
	if jwtBinding == nil && s.authActive.Load() {
		return fmt.Errorf("JWT required for attestation signing once auth is active (issue #40)")
	}

	// Get session metrics
	var metrics *aflock.SessionMetrics
	sessionState, err := s.stateManager.Load(s.sessionID)
	if err == nil && sessionState != nil {
		metrics = sessionState.Metrics
	}

	// Create and sign attestation
	envelope, err := s.signer.CreateActionAttestation(ctx, record, s.sessionID, metrics, s.agentIdentity,
		&attestation.AttestationContext{JWT: jwtBinding})
	if err != nil {
		return fmt.Errorf("create attestation: %w", err)
	}

	// Store to disk
	return s.storeAttestation(envelope, record.ToolUseID)
}

// buildJWTBinding constructs an attestation predicate binding from the
// validated claims and the token presented on the wire. Returns nil if
// either is missing — the attestation is still produced, just without
// JWT context, marking it as a graceful-adoption call (issue #40).
func (s *Server) buildJWTBinding(request mcp.CallToolRequest, claims *auth.AflockClaims) *attestation.JWTBinding {
	if claims == nil {
		return nil
	}
	tokenStr, _ := request.GetArguments()["_token"].(string)
	if tokenStr == "" {
		return nil
	}
	digest := sha256.Sum256([]byte(tokenStr))
	binding := &attestation.JWTBinding{
		SessionID:    s.sessionID,
		JTI:          claims.ID,
		PolicyDigest: claims.PolicyDigest,
		TokenSHA256:  hex.EncodeToString(digest[:]),
		AllowedTools: claims.AllowedTools,
		DeniedTools:  claims.DeniedTools,
	}
	if s.tokenIssuer != nil {
		binding.KeyID = s.tokenIssuer.KeyID()
	}
	return binding
}

// storeAttestation writes an attestation envelope to the session's attestations directory.
func (s *Server) storeAttestation(envelope *attestation.Envelope, toolUseID string) error {
	dir := s.stateManager.AttestationsDir(s.sessionID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create attestations dir: %w", err)
	}

	// Generate filename with timestamp and tool use ID prefix
	idPrefix := toolUseID
	if len(idPrefix) > 8 {
		idPrefix = idPrefix[:8]
	}
	filename := fmt.Sprintf("%s-%s.intoto.json", time.Now().Format("20060102-150405"), idPrefix)
	path := filepath.Join(dir, filename)

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write attestation: %w", err)
	}

	return nil
}

// handleGetIdentity returns the agent's derived identity.
func (s *Server) handleGetIdentity(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.agentIdentity == nil {
		return mcp.NewToolResultError("No identity discovered"), nil
	}

	result := map[string]any{
		"model":        s.agentIdentity.Model,
		"modelVersion": s.agentIdentity.ModelVersion,
		"identityHash": s.agentIdentity.IdentityHash,
	}

	if s.agentIdentity.Binary != nil {
		result["binary"] = map[string]string{
			"name":    s.agentIdentity.Binary.Name,
			"version": s.agentIdentity.Binary.Version,
			"digest":  s.agentIdentity.Binary.Digest,
		}
	}

	if s.agentIdentity.Environment != nil {
		result["environment"] = s.agentIdentity.Environment
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// handleGetPolicy returns the loaded policy.
func (s *Server) handleGetPolicy(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.policy == nil {
		return mcp.NewToolResultError("No policy loaded"), nil
	}

	data, _ := json.MarshalIndent(s.policy, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// handleCheckTool checks if a tool call would be allowed.
func (s *Server) handleCheckTool(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	toolName := request.GetString("tool_name", "")
	toolInputMap := request.GetArguments()["tool_input"]

	if s.policy == nil {
		return mcp.NewToolResultText(`{"allowed": true, "reason": "No policy loaded"}`), nil
	}

	// Expired policies deny everything (#136). Without this, an expired
	// policy still evaluates its rules and returns allow for tools in the
	// allowlist — which silently extends authorization past Expires.
	if err := s.errPolicyExpired(); err != nil {
		result := map[string]any{
			"allowed":  false,
			"decision": string(aflock.DecisionDeny),
			"reason":   err.Error(),
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	}

	inputJSON, _ := json.Marshal(toolInputMap)
	evaluator := policy.NewEvaluator(s.policy, s.projectRoot())
	decision, reason := evaluator.EvaluatePreToolUse(toolName, inputJSON)

	result := map[string]any{
		"allowed":  decision == aflock.DecisionAllow,
		"decision": string(decision),
		"reason":   reason,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// handleBash executes a command with policy enforcement.
func (s *Server) handleBash(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) { //nolint:gocognit,gocyclo,funlen // bash handler requires complex policy + execution logic
	// JWT authorization check
	claims, err := s.validateJWT(request)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
	}
	if claims != nil && !auth.IsToolAllowed("Bash", claims.AllowedTools, claims.DeniedTools) {
		return mcp.NewToolResultError("Authorization denied: tool 'Bash' not permitted by token scope"), nil
	}
	jwtBinding := s.buildJWTBinding(request, claims)

	command := request.GetString("command", "")
	timeoutSec := request.GetFloat("timeout", 30)
	workdir := request.GetString("workdir", "")
	attest := request.GetBool("attest", false)
	step := request.GetString("step", "")
	reason := request.GetString("reason", "")

	// Validate: step is required if attest=true
	if attest && step == "" {
		return mcp.NewToolResultError("step parameter is required when attest=true"), nil
	}

	// Validate: step must not contain path separators (prevent path traversal)
	if strings.ContainsAny(step, "/\\") || strings.Contains(step, "..") {
		return mcp.NewToolResultError("step name must not contain path separators or '..'"), nil
	}

	// Generate tool use ID for this invocation
	toolUseID := uuid.New().String()
	inputJSON, _ := json.Marshal(map[string]any{
		"command": command,
		"attest":  attest,
		"step":    step,
		"reason":  reason,
	})

	// Check policy
	if s.policy != nil { //nolint:nestif
		evaluator := policy.NewEvaluator(s.policy, s.projectRoot())
		decision, policyReason := evaluator.EvaluatePreToolUse("Bash", inputJSON)

		if decision == aflock.DecisionDeny {
			// Create and sign denial attestation
			record := aflock.ActionRecord{
				Timestamp: time.Now(),
				ToolName:  "Bash",
				ToolUseID: toolUseID,
				ToolInput: inputJSON,
				Decision:  string(aflock.DecisionDeny),
				Reason:    policyReason,
			}
			s.recordAction("Bash", "deny", policyReason)
			if err := s.signAndStoreAttestation(ctx, record, jwtBinding); err != nil {
				fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to sign attestation: %v\n", err)
			}
			return mcp.NewToolResultError(fmt.Sprintf("Policy denied: %s", policyReason)), nil
		}

		if decision == aflock.DecisionAsk {
			s.recordAction("Bash", "ask", policyReason)
			record := aflock.ActionRecord{
				Timestamp: time.Now(),
				ToolName:  "Bash",
				ToolUseID: toolUseID,
				ToolInput: inputJSON,
				Decision:  string(aflock.DecisionAsk),
				Reason:    policyReason,
			}
			if err := s.signAndStoreAttestation(ctx, record, jwtBinding); err != nil {
				fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to sign attestation: %v\n", err)
			}
			return mcp.NewToolResultError(fmt.Sprintf("Policy requires approval: %s", policyReason)), nil
		}

		// Check dataFlow rules - this prevents exfiltration (protected by mutex)
		s.sessionMu.Lock()
		sessionState, loadErr := s.stateManager.Load(s.sessionID)
		var flowBlocked bool
		var flowReason string
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "[aflock] DEBUG: Failed to load session: %v\n", loadErr)
		} else if sessionState == nil {
			fmt.Fprintf(os.Stderr, "[aflock] DEBUG: Session state is nil\n")
		} else {
			fmt.Fprintf(os.Stderr, "[aflock] DEBUG: Session has %d materials\n", len(sessionState.Materials))
			for i, m := range sessionState.Materials {
				fmt.Fprintf(os.Stderr, "[aflock] DEBUG: Material[%d]: label=%s source=%s\n", i, m.Label, m.Source)
			}
		}
		if sessionState != nil && len(sessionState.Materials) > 0 {
			fmt.Fprintf(os.Stderr, "[aflock] DEBUG: Evaluating dataFlow for Bash command: %s\n", command)
			flowDecision, reason, _ := evaluator.EvaluateDataFlow("Bash", inputJSON, sessionState.Materials)
			fmt.Fprintf(os.Stderr, "[aflock] DEBUG: DataFlow decision=%s reason=%s\n", flowDecision, reason)
			if flowDecision == aflock.DecisionDeny {
				flowBlocked = true
				flowReason = reason
			}
		}
		s.sessionMu.Unlock()

		if flowBlocked {
			record := aflock.ActionRecord{
				Timestamp: time.Now(),
				ToolName:  "Bash",
				ToolUseID: toolUseID,
				ToolInput: inputJSON,
				Decision:  string(aflock.DecisionDeny),
				Reason:    flowReason,
			}
			s.recordAction("Bash", "deny", flowReason)
			if err := s.signAndStoreAttestation(ctx, record, jwtBinding); err != nil {
				fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to sign attestation: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "[aflock] BLOCKED data exfiltration: %s\n", flowReason)
			return mcp.NewToolResultError(fmt.Sprintf("DataFlow policy denied: %s", flowReason)), nil
		}
		// (Removed the duplicate evaluator.EvaluateDataFlow against s.materials.
		// Persisted sessionState.Materials is the single source of truth — issue
		// #61 / M7. The in-memory s.materials slice could drift out of sync with
		// disk between concurrent MCP requests, producing inconsistent decisions.)
	}

	// If attest=true, use attestors for full attestation
	if attest {
		return s.executeWithAttestation(ctx, command, workdir, step, reason, timeoutSec, toolUseID, inputJSON)
	}

	// Standard execution without attestation
	return s.executeCommand(ctx, command, workdir, timeoutSec, toolUseID, inputJSON, jwtBinding)
}

// executeCommand executes a command without attestation.
func (s *Server) executeCommand(ctx context.Context, command, workdir string, timeoutSec float64, toolUseID string, inputJSON []byte, jwtBinding *attestation.JWTBinding) (*mcp.CallToolResult, error) {
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "bash", "-c", command) //nolint:gosec // G204: command from attested step, policy-checked
	if workdir != "" {
		cmd.Dir = workdir
	}
	output, err := cmd.CombinedOutput()

	// Create action record
	record := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Bash",
		ToolUseID: toolUseID,
		ToolInput: inputJSON,
		Decision:  string(aflock.DecisionAllow),
	}

	// Record action in session state
	s.recordAction("Bash", "allow", "")

	// Sign and store attestation
	if signErr := s.signAndStoreAttestation(ctx, record, jwtBinding); signErr != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to sign attestation: %v\n", signErr)
	}

	exitCode := -1
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	result := map[string]any{
		"output":   strings.TrimSpace(string(output)),
		"exitCode": exitCode,
	}

	if err != nil {
		result["error"] = err.Error()
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// executeWithAttestation executes a command with attestors and stores by git tree hash + step.
func (s *Server) executeWithAttestation(ctx context.Context, command, workdir, step, reason string, _ float64, _ string, _ []byte) (*mcp.CallToolResult, error) {
	// Get git tree hash for organizing attestations
	treeHash, err := attestation.GetGitTreeHash(workdir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: could not get git tree hash: %v\n", err)
		treeHash = "unknown"
	}

	// Run attestors around the command
	cmdSlice := []string{"bash", "-c", command}
	runResult, runErr := attestation.RunAttestors(ctx, step, cmdSlice, workdir)
	if runResult == nil {
		return mcp.NewToolResultError(fmt.Sprintf("Attestation failed: %v", runErr)), nil
	}

	// Record action in session state
	s.recordAction("Bash", "allow", reason)

	result := map[string]any{
		"output":   strings.TrimSpace(string(runResult.Output)),
		"exitCode": runResult.ExitCode,
		"step":     step,
		"duration": runResult.Duration.String(),
	}

	if runResult.Error != nil {
		result["error"] = runResult.Error.Error()
	}

	// Sign and store the attestation collection if signing is enabled
	if s.signingEnabled { //nolint:nestif
		envelope, signErr := s.signer.SignCollection(ctx, runResult.Collection)
		if signErr != nil {
			fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to sign collection: %v\n", signErr)
		} else {
			// Store attestation by git tree hash + step name
			if storeErr := s.storeStepAttestation(envelope, treeHash, step); storeErr != nil {
				fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to store attestation: %v\n", storeErr)
			} else {
				attestPath := attestation.AttestationPath(s.attestDir, treeHash, step)
				result["attestation"] = attestPath
			}
		}
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// storeStepAttestation stores a DSSE envelope for a step in the attestation directory.
func (s *Server) storeStepAttestation(envelope any, treeHash, step string) error {
	// Ensure directory exists
	if err := attestation.EnsureAttestationDir(s.attestDir, treeHash); err != nil {
		return fmt.Errorf("create attestation dir: %w", err)
	}

	path := attestation.AttestationPath(s.attestDir, treeHash, step)

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write attestation: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[aflock] Attestation stored: %s\n", path)
	return nil
}

// handleReadFile reads a file with policy enforcement.
func (s *Server) handleReadFile(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// JWT authorization check
	claims, err := s.validateJWT(request)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
	}
	if claims != nil && !auth.IsToolAllowed("Read", claims.AllowedTools, claims.DeniedTools) {
		return mcp.NewToolResultError("Authorization denied: tool 'Read' not permitted by token scope"), nil
	}
	jwtBinding := s.buildJWTBinding(request, claims)

	filePath := request.GetString("path", "")

	// Resolve path
	if !filepath.IsAbs(filePath) {
		cwd, _ := os.Getwd()
		filePath = filepath.Join(cwd, filePath)
	}

	// Generate tool use ID for this invocation
	toolUseID := uuid.New().String()
	inputJSON, _ := json.Marshal(map[string]string{"file_path": filePath})

	// Check policy
	if s.policy != nil { //nolint:nestif
		evaluator := policy.NewEvaluator(s.policy, s.projectRoot())
		decision, reason := evaluator.EvaluatePreToolUse("Read", inputJSON)

		if decision == aflock.DecisionDeny {
			record := aflock.ActionRecord{
				Timestamp: time.Now(),
				ToolName:  "Read",
				ToolUseID: toolUseID,
				ToolInput: inputJSON,
				Decision:  string(aflock.DecisionDeny),
				Reason:    reason,
			}
			s.recordAction("Read", "deny", reason)
			if err := s.signAndStoreAttestation(ctx, record, jwtBinding); err != nil {
				fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to sign attestation: %v\n", err)
			}
			return mcp.NewToolResultError(fmt.Sprintf("Policy denied: %s", reason)), nil
		}

		if decision == aflock.DecisionAsk {
			s.recordAction("Read", "ask", reason)
			return mcp.NewToolResultError(fmt.Sprintf("Policy requires approval: %s", reason)), nil
		}

		// Check dataFlow rules and track materials (protected by mutex for concurrent access)
		s.sessionMu.Lock()
		sessionState, _ := s.stateManager.Load(s.sessionID)
		if sessionState != nil {
			_, _, newMaterial := evaluator.EvaluateDataFlow("Read", inputJSON, sessionState.Materials)
			if newMaterial != nil {
				// Track the new material classification
				newMaterial.Timestamp = time.Now()
				sessionState.Materials = append(sessionState.Materials, *newMaterial)
				if err := s.stateManager.Save(sessionState); err != nil {
					fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to save session: %v\n", err)
				}
				fmt.Fprintf(os.Stderr, "[aflock] Tracked sensitive material: %s from %s\n", newMaterial.Label, filePath)
			}
		}
		s.sessionMu.Unlock()
	}

	// Read file
	content, err := os.ReadFile(filePath) //nolint:gosec // G304: file path from tool request, policy-checked
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Read failed: %v", err)), nil
	}

	// Create action record
	record := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Read",
		ToolUseID: toolUseID,
		ToolInput: inputJSON,
		Decision:  string(aflock.DecisionAllow),
	}

	// Record action
	s.recordAction("Read", "allow", "")
	s.trackFile("Read", filePath)

	// Sign and store attestation
	if err := s.signAndStoreAttestation(ctx, record, jwtBinding); err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to sign attestation: %v\n", err)
	}

	return mcp.NewToolResultText(string(content)), nil
}

// handleWriteFile writes content to a file with policy enforcement.
func (s *Server) handleWriteFile(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) { //nolint:gocognit,funlen // file write handler has complex policy + attestation logic
	// JWT authorization check
	claims, err := s.validateJWT(request)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
	}
	if claims != nil && !auth.IsToolAllowed("Write", claims.AllowedTools, claims.DeniedTools) {
		return mcp.NewToolResultError("Authorization denied: tool 'Write' not permitted by token scope"), nil
	}
	jwtBinding := s.buildJWTBinding(request, claims)

	filePath := request.GetString("path", "")
	content := request.GetString("content", "")

	// Resolve path
	if !filepath.IsAbs(filePath) {
		cwd, _ := os.Getwd()
		filePath = filepath.Join(cwd, filePath)
	}

	// Generate tool use ID for this invocation
	toolUseID := uuid.New().String()
	inputJSON, _ := json.Marshal(map[string]string{"file_path": filePath, "content_length": fmt.Sprintf("%d", len(content))})

	// Check policy
	if s.policy != nil { //nolint:nestif
		evaluator := policy.NewEvaluator(s.policy, s.projectRoot())
		decision, reason := evaluator.EvaluatePreToolUse("Write", inputJSON)

		if decision == aflock.DecisionDeny {
			record := aflock.ActionRecord{
				Timestamp: time.Now(),
				ToolName:  "Write",
				ToolUseID: toolUseID,
				ToolInput: inputJSON,
				Decision:  string(aflock.DecisionDeny),
				Reason:    reason,
			}
			s.recordAction("Write", "deny", reason)
			if err := s.signAndStoreAttestation(ctx, record, jwtBinding); err != nil {
				fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to sign attestation: %v\n", err)
			}
			return mcp.NewToolResultError(fmt.Sprintf("Policy denied: %s", reason)), nil
		}

		if decision == aflock.DecisionAsk {
			s.recordAction("Write", "ask", reason)
			return mcp.NewToolResultError(fmt.Sprintf("Policy requires approval: %s", reason)), nil
		}

		// Check dataFlow rules for writes to classified destinations (protected by mutex)
		s.sessionMu.Lock()
		sessionState, _ := s.stateManager.Load(s.sessionID)
		var flowBlocked bool
		var flowReason string
		if sessionState != nil && len(sessionState.Materials) > 0 {
			flowDecision, reason, _ := evaluator.EvaluateDataFlow("Write", inputJSON, sessionState.Materials)
			if flowDecision == aflock.DecisionDeny {
				flowBlocked = true
				flowReason = reason
			}
		}
		s.sessionMu.Unlock()

		if flowBlocked {
			record := aflock.ActionRecord{
				Timestamp: time.Now(),
				ToolName:  "Write",
				ToolUseID: toolUseID,
				ToolInput: inputJSON,
				Decision:  string(aflock.DecisionDeny),
				Reason:    flowReason,
			}
			s.recordAction("Write", "deny", flowReason)
			if err := s.signAndStoreAttestation(ctx, record, jwtBinding); err != nil {
				fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to sign attestation: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "[aflock] BLOCKED data exfiltration: %s\n", flowReason)
			return mcp.NewToolResultError(fmt.Sprintf("DataFlow policy denied: %s", flowReason)), nil
		}
	}

	// Write file
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Write failed: %v", err)), nil
	}

	// Create action record
	record := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Write",
		ToolUseID: toolUseID,
		ToolInput: inputJSON,
		Decision:  string(aflock.DecisionAllow),
	}

	// Record action
	s.recordAction("Write", "allow", "")
	s.trackFile("Write", filePath)

	// Sign and store attestation
	if err := s.signAndStoreAttestation(ctx, record, jwtBinding); err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to sign attestation: %v\n", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf("Wrote %d bytes to %s", len(content), filePath)), nil
}

// handleGetSession returns current session information.
func (s *Server) handleGetSession(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sessionState, err := s.stateManager.Load(s.sessionID)
	if err != nil {
		return nil, fmt.Errorf("load session: %w", err)
	}
	if sessionState == nil {
		noData := map[string]string{"sessionId": s.sessionID, "status": "no session data"}
		noDataJSON, _ := json.MarshalIndent(noData, "", "  ")
		return mcp.NewToolResultText(string(noDataJSON)), nil
	}

	policyName := ""
	if sessionState.Policy != nil {
		policyName = sessionState.Policy.Name
	}

	metrics := map[string]any{
		"turns":              0,
		"toolCalls":          0,
		"tokensIn":           0,
		"tokensOut":          0,
		"cacheReadTokens":    0,
		"cacheWrite5mTokens": 0,
		"cacheWrite1hTokens": 0,
		"costUSD":            0.0,
		"costMeasured":       false,
		"usageSource":        "",
		"filesRead":          0,
		"filesWritten":       0,
	}
	if sessionState.Metrics != nil {
		metrics["turns"] = sessionState.Metrics.Turns
		metrics["toolCalls"] = sessionState.Metrics.ToolCalls
		metrics["tokensIn"] = sessionState.Metrics.TokensIn
		metrics["tokensOut"] = sessionState.Metrics.TokensOut
		metrics["cacheReadTokens"] = sessionState.Metrics.CacheReadTokens
		metrics["cacheWrite5mTokens"] = sessionState.Metrics.CacheWrite5mTokens
		metrics["cacheWrite1hTokens"] = sessionState.Metrics.CacheWrite1hTokens
		metrics["costUSD"] = sessionState.Metrics.CostUSD
		metrics["costMeasured"] = sessionState.Metrics.CostMeasured
		metrics["usageSource"] = sessionState.Metrics.UsageSource
		metrics["filesRead"] = len(sessionState.Metrics.FilesRead)
		metrics["filesWritten"] = len(sessionState.Metrics.FilesWritten)
	}

	result := map[string]any{
		"sessionId":    s.sessionID,
		"policyName":   policyName,
		"startedAt":    sessionState.StartedAt,
		"authMode":     sessionState.AuthMode,
		"metrics":      metrics,
		"actionsCount": len(sessionState.Actions),
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// handleSignAttestation signs an attestation for arbitrary data.
func (s *Server) handleSignAttestation(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) { //nolint:gocognit // attestation signing requires complex validation
	// JWT authorization check — signing is the most sensitive operation.
	// Issue #40: once authActive is true, claims must be present (no
	// graceful-adoption escape for the explicit signing tool).
	claims, err := s.validateJWT(request)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
	}
	// Use the actually-invoked tool name so the paper-named alias
	// (aflock_attest) and the legacy name (sign_attestation) both
	// authorize correctly when present in a policy allowlist
	// (Copilot review on PR #149).
	invoked := request.Params.Name
	if invoked == "" {
		invoked = "sign_attestation"
	}
	if claims == nil && s.authActive.Load() {
		return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %s requires a valid JWT once auth is active (issue #40)", invoked)), nil
	}
	if claims != nil && !auth.IsToolAllowed(invoked, claims.AllowedTools, claims.DeniedTools) {
		return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: tool %q not permitted by token scope", invoked)), nil
	}

	if !s.signingEnabled {
		return mcp.NewToolResultError("Attestation signing not available (SPIRE, Fulcio, and ephemeral key all failed during initialization)"), nil
	}

	predicateType := request.GetString("predicate_type", "")
	if predicateType == "" {
		return mcp.NewToolResultError("predicate_type is required"), nil
	}

	predicateArg := request.GetArguments()["predicate"]
	if predicateArg == nil {
		return mcp.NewToolResultError("predicate is required"), nil
	}

	// Build subject
	var subjects []attestation.Subject
	subjectArg := request.GetArguments()["subject"]
	if subjectArg != nil { //nolint:nestif
		if subjectMap, ok := subjectArg.(map[string]interface{}); ok {
			name, _ := subjectMap["name"].(string)
			digest := make(map[string]string)
			if digestMap, ok := subjectMap["digest"].(map[string]interface{}); ok {
				for k, v := range digestMap {
					if vs, ok := v.(string); ok {
						digest[k] = vs
					}
				}
			}
			subjects = append(subjects, attestation.Subject{
				Name:   name,
				Digest: digest,
			})
		}
	} else {
		// Default subject using session ID
		subjects = append(subjects, attestation.Subject{
			Name: fmt.Sprintf("session:%s/attestation:%s", s.sessionID, uuid.New().String()[:8]),
			Digest: map[string]string{
				"sha256": computePredicateDigest(predicateArg),
			},
		})
	}

	// Build statement
	statement := attestation.Statement{
		Type:          attestation.StatementType,
		Subject:       subjects,
		PredicateType: predicateType,
		Predicate:     predicateArg,
	}

	// Sign statement
	envelope, err := s.signer.Sign(ctx, statement)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to sign attestation: %v", err)), nil
	}

	// Store to disk
	attestationID := uuid.New().String()[:8]
	if err := s.storeAttestation(envelope, attestationID); err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to store attestation: %v\n", err)
	}

	data, _ := json.MarshalIndent(envelope, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// handleCheckLimits returns the configured resource limits alongside
// their current consumption and remaining budget. Paper §3.3 names
// this `aflock_check_limits`. Read-only: no JWT required, since this
// just exposes data already returned by `get_session` and the loaded
// policy. Omits any limit category the policy hasn't declared.
func (s *Server) handleCheckLimits(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.policy == nil || s.policy.Limits == nil {
		return mcp.NewToolResultText(`{"limits": {}}`), nil
	}

	sessionState, err := s.stateManager.Load(s.sessionID)
	if err != nil {
		return nil, fmt.Errorf("load session: %w", err)
	}

	var (
		costUSD   float64
		tokensIn  int64
		tokensOut int64
		turns     int
		toolCalls int
	)
	startedAt := time.Now()
	if sessionState != nil {
		startedAt = sessionState.StartedAt
		if sessionState.Metrics != nil {
			costUSD = sessionState.Metrics.CostUSD
			tokensIn = sessionState.Metrics.TokensIn
			tokensOut = sessionState.Metrics.TokensOut
			turns = sessionState.Metrics.Turns
			toolCalls = sessionState.Metrics.ToolCalls
		}
	}

	limits := map[string]any{}
	addFloat := func(name string, lim *aflock.Limit, used float64) {
		if lim == nil {
			return
		}
		remaining := lim.Value - used
		if remaining < 0 {
			remaining = 0
		}
		limits[name] = map[string]any{
			"value":       lim.Value,
			"used":        used,
			"remaining":   remaining,
			"enforcement": lim.Enforcement,
		}
	}
	addInt := func(name string, lim *aflock.Limit, used int64) {
		if lim == nil {
			return
		}
		remaining := int64(lim.Value) - used
		if remaining < 0 {
			remaining = 0
		}
		limits[name] = map[string]any{
			"value":       int64(lim.Value),
			"used":        used,
			"remaining":   remaining,
			"enforcement": lim.Enforcement,
		}
	}

	pol := s.policy.Limits
	addFloat("maxSpendUSD", pol.MaxSpendUSD, costUSD)
	addInt("maxTokensIn", pol.MaxTokensIn, tokensIn)
	addInt("maxTokensOut", pol.MaxTokensOut, tokensOut)
	addInt("maxTurns", pol.MaxTurns, int64(turns))
	addInt("maxToolCalls", pol.MaxToolCalls, int64(toolCalls))
	if pol.MaxWallTimeSeconds != nil {
		elapsed := time.Since(startedAt).Seconds()
		if elapsed < 0 {
			elapsed = 0
		}
		addFloat("maxWallTimeSeconds", pol.MaxWallTimeSeconds, elapsed)
	}

	result := map[string]any{"limits": limits}
	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// handleDelegate creates a sublayout binding for a sub-agent. Paper
// §3.3 names this `aflock_delegate`. JWT-gated (parent agent must be
// authorized). Validates the named sublayout exists, checks
// attenuation, writes a propagation record, and mints an attenuated
// child JWT.
//
// This mirrors, in MCP mode, the spawn-time binding that
// internal/hooks/handler.go performs at PreToolUse when Claude Code's
// Task/Agent tool is invoked.
func (s *Server) handleDelegate(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// aflock_delegate is sensitive (issues child JWTs + writes propagation),
	// so we require a validated JWT unconditionally rather than honoring
	// the graceful-adoption fallback used by less-privileged tools.
	claims, err := s.validateJWT(request)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
	}
	if claims == nil {
		return mcp.NewToolResultError("Authorization denied: aflock_delegate requires a valid JWT"), nil
	}
	// Tool-scope check: a token issued under a policy allowlist that
	// does not include the invoked name must not be able to mint child
	// JWTs (Copilot review on PR #149). Use the actually-invoked name
	// so the same handler covers any future alias.
	invoked := request.Params.Name
	if !auth.IsToolAllowed(invoked, claims.AllowedTools, claims.DeniedTools) {
		return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: tool %q not permitted by token scope", invoked)), nil
	}
	if s.tokenIssuer == nil {
		return mcp.NewToolResultError("aflock_delegate: token issuer not initialized"), nil
	}

	if s.policy == nil {
		return mcp.NewToolResultError("aflock_delegate: no policy loaded"), nil
	}
	if err := s.errPolicyExpired(); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	sublayoutName := request.GetString("sublayout_name", "")
	if sublayoutName == "" {
		return mcp.NewToolResultError("sublayout_name is required"), nil
	}

	var matched *aflock.Sublayout
	for i := range s.policy.Sublayouts {
		if s.policy.Sublayouts[i].Name == sublayoutName {
			matched = &s.policy.Sublayouts[i]
			break
		}
	}
	if matched == nil {
		return mcp.NewToolResultError(fmt.Sprintf("aflock_delegate: sublayout %q not declared in policy", sublayoutName)), nil
	}

	if violations := policy.AttenuationViolations(s.policy.Limits, matched.Limits); len(violations) > 0 {
		return mcp.NewToolResultError(fmt.Sprintf("aflock_delegate: sublayout %q violates parent attenuation: %s",
			sublayoutName, strings.Join(violations, "; "))), nil
	}

	parentState, err := s.stateManager.Load(s.sessionID)
	if err != nil {
		return nil, fmt.Errorf("load parent session: %w", err)
	}
	if parentState == nil {
		return mcp.NewToolResultError("aflock_delegate: no parent session state; call get_token / start a session first"), nil
	}

	// Caller-supplied child_session_id must be a safe identifier the
	// state manager and downstream tooling can use as a filename
	// component. We allow alphanumerics, hyphen, and underscore;
	// anything else is rejected so a malformed id can't slip through
	// to a JWT and then fail at state-load time.
	childSessionID := request.GetString("child_session_id", "")
	if childSessionID == "" {
		childSessionID = fmt.Sprintf("delegate-%s", uuid.New().String())
	} else if !validSessionID(childSessionID) {
		return mcp.NewToolResultError(
			"aflock_delegate: child_session_id must be 1-128 chars of [a-zA-Z0-9_-]"), nil
	}

	// Mint the JWT first. If minting fails, no propagation record is
	// written — failed delegations have no observable side effects.
	//
	// IMPORTANT (Copilot review on PR #149): the minted token is bound
	// to the child session ID and the attenuated child policy digest.
	// It is NOT usable against THIS server's validateJWT, which checks
	// every call against the parent session/policy. The intended
	// consumer is a downstream aflock instance that loads the child
	// policy and runs the child session. Callers handing this token
	// back to the parent socket will be rejected — by design.
	agentID := ""
	identityHash := ""
	if s.agentIdentity != nil {
		if spiffeID, sErr := s.agentIdentity.ToSPIFFEID("aflock.ai"); sErr == nil {
			agentID = spiffeID.String()
		}
		identityHash = s.agentIdentity.IdentityHash
	}
	childJWT, err := s.tokenIssuer.MintChildToken(s.policy, matched, childSessionID, agentID, identityHash, time.Hour)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("aflock_delegate: mint child JWT: %v", err)), nil
	}

	if err := s.stateManager.WritePropagationForSublayout(parentState, matched); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("aflock_delegate: write propagation: %v", err)), nil
	}

	result := map[string]any{
		"ok":               true,
		"sublayout":        matched.Name,
		"parent_session":   s.sessionID,
		"child_session_id": childSessionID,
		"child_jwt":        childJWT,
		"child_jwt_note":   "Token is bound to child_session_id + attenuated child policy. Present it to a downstream aflock instance loaded with the child policy, not to this server.",
		"limits":           matched.Limits,
	}
	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// validSessionID enforces the safe-identifier rule for caller-supplied
// child_session_id values: 1-128 chars, restricted to [a-zA-Z0-9_-].
// Keeps malformed IDs from reaching the state manager (where they'd
// become filename components) and from being baked into a JWT that
// downstream tooling can't load.
func validSessionID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// computePredicateDigest computes SHA256 of predicate data.
func computePredicateDigest(predicate interface{}) string {
	data, _ := json.Marshal(predicate)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// recordAction records an action in the session state.
//
// Acquires both the in-process sessionMu (serializing concurrent MCP request
// handlers in this process) and an exclusive file lock via LockSession
// (serializing against other aflock processes — e.g. concurrent hook
// invocations sharing the same state directory). This closes the TOCTOU race
// on the state file described in issue #58 / M6.
func (s *Server) recordAction(toolName, decision, reason string) {
	if s.policy == nil {
		return
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	unlock, err := s.stateManager.LockSession(s.sessionID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to lock session state: %v\n", err)
		return
	}
	defer unlock()
	sessionState, _ := s.stateManager.Load(s.sessionID)
	if sessionState == nil {
		return
	}
	record := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  toolName,
		Decision:  decision,
		Reason:    reason,
	}
	s.stateManager.RecordAction(sessionState, record)
	_ = s.stateManager.Save(sessionState)
}

// trackFile tracks a file access in the session state.
//
// Acquires both the in-process sessionMu and an exclusive cross-process file
// lock, mirroring recordAction. See issue #58 / M6.
func (s *Server) trackFile(toolName, filePath string) {
	if s.policy == nil {
		return
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	unlock, err := s.stateManager.LockSession(s.sessionID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to lock session state: %v\n", err)
		return
	}
	defer unlock()
	sessionState, _ := s.stateManager.Load(s.sessionID)
	if sessionState == nil {
		return
	}
	s.stateManager.TrackFile(sessionState, toolName, filePath)
	_ = s.stateManager.Save(sessionState)
}
