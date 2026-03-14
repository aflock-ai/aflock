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
	"time"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/aflock-ai/aflock/internal/attestation"
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

	// In-memory data flow tracking (thread-safe for concurrent MCP requests)
	mu             sync.Mutex
	materials      []aflock.MaterialClassification
	signer         *attestation.Signer
	signingEnabled bool
	attestDir      string     // Directory for storing step attestations by git tree hash
	sessionMu      sync.Mutex // Protects session state access for dataFlow tracking
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

	// Discover agent identity
	agentID, err := identity.DiscoverAgentIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to discover identity: %v\n", err)
	} else {
		s.agentIdentity = agentID
	}

	// Compute policy digest and add to agent identity
	if s.policy != nil && s.agentIdentity != nil {
		s.agentIdentity.PolicyDigest = s.computePolicyDigest()
		s.agentIdentity.DeriveIdentity() // Recompute identity hash with policy
	}

	// Initialize attestation signer with SPIRE
	s.signer = attestation.NewSigner("") // Uses default SPIRE socket
	ctx := context.Background()
	if err := s.signer.Initialize(ctx); err != nil { //nolint:nestif
		fmt.Fprintf(os.Stderr, "[aflock] Warning: SPIRE not available, attestation signing disabled: %v\n", err)
		s.signingEnabled = false
	} else {
		s.signingEnabled = true
		fmt.Fprintf(os.Stderr, "[aflock] SPIRE attestation signing enabled\n")

		// Try to get delegated identity for the AI agent
		// Model name comes from PID-based discovery (via agentIdentity)
		if s.agentIdentity != nil && s.agentIdentity.Model != "" && s.agentIdentity.Model != "unknown" {
			if err := s.signer.SetModel(ctx, s.agentIdentity.Model); err != nil {
				fmt.Fprintf(os.Stderr, "[aflock] Warning: %v\n", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "[aflock] Warning: No model discovered from PID trace - attestation signing disabled\n")
			s.signingEnabled = false
		}
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

// computePolicyDigest computes the SHA256 digest of the loaded policy.
func (s *Server) computePolicyDigest() string {
	if s.policy == nil {
		return ""
	}
	data, err := json.Marshal(s.policy)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// signAndStoreAttestation creates a signed attestation for an action and stores it to disk.
func (s *Server) signAndStoreAttestation(ctx context.Context, record aflock.ActionRecord) error {
	if !s.signingEnabled {
		return nil // Signing not available, skip silently
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

		// Evaluate data flow — Bash is a write operation, check flow rules
		s.mu.Lock()
		flowDecision, flowReason, _ := evaluator.EvaluateDataFlow("Bash", inputJSON, s.materials)
		s.mu.Unlock()
		if flowDecision == aflock.DecisionDeny {
			s.recordAction("Bash", "deny", flowReason)
			return mcp.NewToolResultError(fmt.Sprintf("Data flow violation: %s", flowReason)), nil
		}
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
	if !s.signingEnabled {
		return mcp.NewToolResultError("Attestation signing not available (SPIRE not connected)"), nil
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
// Must hold sessionMu or be called from a context where session state
// is not concurrently accessed.
func (s *Server) recordAction(toolName, decision, reason string) {
	if s.policy == nil {
		return
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
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
// Must hold sessionMu or be called from a context where session state
// is not concurrently accessed.
func (s *Server) trackFile(toolName, filePath string) {
	if s.policy == nil {
		return
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	sessionState, _ := s.stateManager.Load(s.sessionID)
	if sessionState == nil {
		return
	}
	s.stateManager.TrackFile(sessionState, toolName, filePath)
	_ = s.stateManager.Save(sessionState)
}
