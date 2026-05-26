// Package mcp implements an MCP server for aflock policy enforcement.
package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
}

// Serve starts the MCP server on stdio.
func (s *Server) Serve(policyPath string) error {
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
func (s *Server) ServeHTTP(policyPath string, port int) error {
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

	// Create SSE server
	sseServer := server.NewSSEServer(s.mcpServer)

	// Set up HTTP handler
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Fprintf(os.Stderr, "[aflock] MCP server listening on http://%s/sse\n", addr)
	fmt.Fprintf(os.Stderr, "[aflock] Session ID: %s (state will persist across calls)\n", s.sessionID)

	return http.ListenAndServe(addr, sseServer) //nolint:gosec // G114: HTTP server with no timeout is acceptable for local MCP
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
	agentID, err := identity.DiscoverAgentIdentity()
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
		fmt.Fprintf(os.Stderr, "[aflock] Attestation signing: SPIRE\n")
		// Note: trusted-model enforcement happens in the policy evaluator via
		// identity.allowedModels at SessionStart (issue #67 review). We no
		// longer call a signer-side SetModel that returned an error but did
		// not actually gate signing — that was dead misleading code.
		return
	}

	if err := s.signer.InitializeFulcio(ctx); err == nil {
		s.signingEnabled = true
		fmt.Fprintf(os.Stderr, "[aflock] Attestation signing: Fulcio (keyless)\n")
		return
	}

	if err := s.signer.InitializeEphemeral(identityHash); err == nil {
		s.signingEnabled = true
		fmt.Fprintf(os.Stderr, "[aflock] Attestation signing: ephemeral key\n")
		return
	}

	s.signingEnabled = false
	fmt.Fprintf(os.Stderr, "[aflock] Warning: attestation signing unavailable (SPIRE, Fulcio, and ephemeral all failed)\n")
}

// initAuth initializes the JWT token issuer. If SPIRE is available and provides
// a signing key, it is used; otherwise an ephemeral ECDSA P-256 key is generated.
func (s *Server) initAuth() error {
	// For now, always use ephemeral key. When SPIRE integration provides a
	// crypto.Signer, use auth.NewTokenIssuerFromSigner instead.
	issuer, err := auth.NewTokenIssuer()
	if err != nil {
		return fmt.Errorf("create token issuer: %w", err)
	}
	s.tokenIssuer = issuer
	return nil
}

// handleGetToken issues a JWT for the current session.
func (s *Server) handleGetToken(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.tokenIssuer == nil {
		return mcp.NewToolResultError("Token issuer not initialized"), nil
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
		return mcp.NewToolResultError(fmt.Sprintf("Failed to issue token: %v", err)), nil
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
func (s *Server) signAndStoreAttestation(ctx context.Context, record aflock.ActionRecord) error {
	if !s.signingEnabled {
		return fmt.Errorf("attestation signing unavailable (SPIRE, Fulcio, and ephemeral all failed)")
	}

	// Get session metrics
	var metrics *aflock.SessionMetrics
	sessionState, err := s.stateManager.Load(s.sessionID)
	if err == nil && sessionState != nil {
		metrics = sessionState.Metrics
	}

	// Create and sign attestation
	envelope, err := s.signer.CreateActionAttestation(ctx, record, s.sessionID, metrics, s.agentIdentity)
	if err != nil {
		return fmt.Errorf("create attestation: %w", err)
	}

	// Store to disk
	return s.storeAttestation(envelope, record.ToolUseID)
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
	if claims, err := s.validateJWT(request); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
	} else if claims != nil && !auth.IsToolAllowed("Bash", claims.AllowedTools, claims.DeniedTools) {
		return mcp.NewToolResultError("Authorization denied: tool 'Bash' not permitted by token scope"), nil
	}

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
			if err := s.signAndStoreAttestation(ctx, record); err != nil {
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
			if err := s.signAndStoreAttestation(ctx, record); err != nil {
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
			if err := s.signAndStoreAttestation(ctx, record); err != nil {
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
	return s.executeCommand(ctx, command, workdir, timeoutSec, toolUseID, inputJSON)
}

// executeCommand executes a command without attestation.
func (s *Server) executeCommand(ctx context.Context, command, workdir string, timeoutSec float64, toolUseID string, inputJSON []byte) (*mcp.CallToolResult, error) {
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
	if signErr := s.signAndStoreAttestation(ctx, record); signErr != nil {
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
	if claims, err := s.validateJWT(request); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
	} else if claims != nil && !auth.IsToolAllowed("Read", claims.AllowedTools, claims.DeniedTools) {
		return mcp.NewToolResultError("Authorization denied: tool 'Read' not permitted by token scope"), nil
	}

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
			if err := s.signAndStoreAttestation(ctx, record); err != nil {
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
	if err := s.signAndStoreAttestation(ctx, record); err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to sign attestation: %v\n", err)
	}

	return mcp.NewToolResultText(string(content)), nil
}

// handleWriteFile writes content to a file with policy enforcement.
func (s *Server) handleWriteFile(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) { //nolint:gocognit,funlen // file write handler has complex policy + attestation logic
	// JWT authorization check
	if claims, err := s.validateJWT(request); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
	} else if claims != nil && !auth.IsToolAllowed("Write", claims.AllowedTools, claims.DeniedTools) {
		return mcp.NewToolResultError("Authorization denied: tool 'Write' not permitted by token scope"), nil
	}

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
			if err := s.signAndStoreAttestation(ctx, record); err != nil {
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
			if err := s.signAndStoreAttestation(ctx, record); err != nil {
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
	if err := s.signAndStoreAttestation(ctx, record); err != nil {
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
		"turns":        0,
		"toolCalls":    0,
		"tokensIn":     0,
		"tokensOut":    0,
		"costUSD":      0.0,
		"filesRead":    0,
		"filesWritten": 0,
	}
	if sessionState.Metrics != nil {
		metrics["turns"] = sessionState.Metrics.Turns
		metrics["toolCalls"] = sessionState.Metrics.ToolCalls
		metrics["tokensIn"] = sessionState.Metrics.TokensIn
		metrics["tokensOut"] = sessionState.Metrics.TokensOut
		metrics["costUSD"] = sessionState.Metrics.CostUSD
		metrics["filesRead"] = len(sessionState.Metrics.FilesRead)
		metrics["filesWritten"] = len(sessionState.Metrics.FilesWritten)
	}

	result := map[string]any{
		"sessionId":    s.sessionID,
		"policyName":   policyName,
		"startedAt":    sessionState.StartedAt,
		"metrics":      metrics,
		"actionsCount": len(sessionState.Actions),
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// handleSignAttestation signs an attestation for arbitrary data.
func (s *Server) handleSignAttestation(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) { //nolint:gocognit // attestation signing requires complex validation
	// JWT authorization check — signing is the most sensitive operation
	if claims, err := s.validateJWT(request); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Authorization denied: %v", err)), nil
	} else if claims != nil && !auth.IsToolAllowed("sign_attestation", claims.AllowedTools, claims.DeniedTools) {
		return mcp.NewToolResultError("Authorization denied: tool 'sign_attestation' not permitted by token scope"), nil
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
