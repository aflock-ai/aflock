// Package hooks handles Claude Code hook events.
package hooks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aflock-ai/aflock/internal/attestation"
	"github.com/aflock-ai/aflock/internal/auth"
	"github.com/aflock-ai/aflock/internal/identity"
	"github.com/aflock-ai/aflock/internal/output"
	"github.com/aflock-ai/aflock/internal/policy"
	"github.com/aflock-ai/aflock/internal/state"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// Handler processes Claude Code hook events.
type Handler struct {
	stateManager *state.Manager
}

// NewHandler creates a new hook handler.
func NewHandler() *Handler {
	return &Handler{
		stateManager: state.NewManager(""),
	}
}

// maxStdinSize is the maximum bytes we'll read from stdin for hook input.
// Hook inputs are JSON with tool names, inputs, and session metadata. 10 MB
// is generous for any legitimate hook invocation. This prevents OOM from
// adversarial stdin (e.g., piped /dev/urandom).
const maxStdinSize = 10 * 1024 * 1024 // 10 MB

// Handle reads input from stdin and dispatches to the appropriate handler.
func (h *Handler) Handle(hookName string) error {
	// Read input from stdin with size limit to prevent OOM
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxStdinSize+1))
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	if len(data) > maxStdinSize {
		return fmt.Errorf("stdin input too large (> %d bytes)", maxStdinSize)
	}

	var input aflock.HookInput
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("parse input: %w", err)
	}

	// Dispatch to appropriate handler
	switch aflock.HookEventName(hookName) {
	case aflock.HookSessionStart:
		return h.handleSessionStart(&input)
	case aflock.HookPreToolUse:
		return h.handlePreToolUse(&input)
	case aflock.HookPostToolUse:
		return h.handlePostToolUse(&input)
	case aflock.HookPermissionRequest:
		return h.handlePermissionRequest(&input)
	case aflock.HookUserPromptSubmit:
		return h.handleUserPromptSubmit(&input)
	case aflock.HookStop:
		return h.handleStop(&input)
	case aflock.HookSubagentStop:
		return h.handleSubagentStop(&input)
	case aflock.HookSessionEnd:
		return h.handleSessionEnd(&input)
	case aflock.HookNotification:
		return h.handleNotification(&input)
	case aflock.HookPreCompact:
		return h.handlePreCompact(&input)
	default:
		return fmt.Errorf("unknown hook: %s", hookName)
	}
}

// handleSessionStart initializes session state and loads policy.
func (h *Handler) handleSessionStart(input *aflock.HookInput) error {
	// Try to load policy from cwd or env
	var pol *aflock.Policy
	var policyPath string
	var err error

	// First try AFLOCK_POLICY env var
	if envPolicy := os.Getenv("AFLOCK_POLICY"); envPolicy != "" {
		pol, policyPath, err = policy.Load(envPolicy)
	} else if input.Cwd != "" {
		// Try to find policy in cwd
		pol, policyPath, err = policy.Load(input.Cwd)
	}

	if err != nil {
		if errors.Is(err, policy.ErrPolicyNotFound) {
			// No policy file exists — opt-in model, allow everything
			return output.WriteEmpty()
		}
		// Policy file exists but is malformed — fail closed
		output.ExitWithError(fmt.Sprintf("[aflock] Failed to load policy: %v", err))
		return nil
	}

	if pol != nil && pol.IsExpired() {
		output.ExitWithError(fmt.Sprintf("[aflock] Policy '%s' has expired (expired at %s)", pol.Name, pol.Expires.Format(time.RFC3339)))
		return nil
	}

	// Discover agent identity
	agentIdentity, err := identity.DiscoverAgentIdentity()
	if err != nil {
		output.ExitWithWarning(fmt.Sprintf("Failed to discover agent identity: %v", err))
		return nil
	}

	// Validate identity against policy constraints (skip if model is unknown in development)
	if pol.Identity != nil && len(pol.Identity.AllowedModels) > 0 {
		if agentIdentity.Model != "unknown" && !agentIdentity.Matches(pol.Identity.AllowedModels, nil) {
			output.ExitWithError(fmt.Sprintf("[aflock] Agent model '%s' not in allowed models: %v",
				agentIdentity.Model, pol.Identity.AllowedModels))
			return nil
		}
	}

	// Initialize session state
	sessionState := h.stateManager.Initialize(input.SessionID, pol, policyPath)

	// Save agent identity metadata for reuse in PostToolUse attestations
	sessionState.AgentIdentityMeta = &aflock.AgentIdentityMeta{
		Model:        agentIdentity.Model,
		ModelVersion: agentIdentity.ModelVersion,
		IdentityHash: agentIdentity.IdentityHash,
		PolicyDigest: agentIdentity.PolicyDigest,
		Environment: func() string {
			if agentIdentity.Environment != nil {
				return agentIdentity.Environment.Type
			}
			return ""
		}(),
	}
	if agentIdentity.Binary != nil {
		sessionState.AgentIdentityMeta.BinaryName = agentIdentity.Binary.Name
		sessionState.AgentIdentityMeta.BinaryVer = agentIdentity.Binary.Version
		sessionState.AgentIdentityMeta.BinaryDigest = agentIdentity.Binary.Digest
	}

	// Check for propagation from a parent session (sublayout delegation).
	// If found, inherit materials and attenuate limits.
	if prop, propErr := h.stateManager.ReadPropagation(policyPath); propErr != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to read propagation: %v\n", propErr)
	} else if prop != nil {
		sessionState.ParentSessionID = prop.ParentSessionID
		sessionState.Materials = prop.Materials
		if prop.ParentLimits != nil && prop.ParentMetrics != nil {
			sessionState.Policy.Limits = attenuateLimits(
				sessionState.Policy.Limits, prop.ParentLimits, prop.ParentMetrics)
		}
		fmt.Fprintf(os.Stderr, "[aflock] Inherited %d materials from parent session %s\n",
			len(prop.Materials), prop.ParentSessionID)
	}

	// Issue JWT for this session — binds agent identity, policy, and grants
	issuer, jwtErr := auth.NewTokenIssuer()
	if jwtErr != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to create token issuer: %v\n", jwtErr)
	} else {
		ttl := 1 * time.Hour
		if pol.Limits != nil && pol.Limits.MaxWallTimeSeconds != nil {
			ttl = time.Duration(pol.Limits.MaxWallTimeSeconds.Value) * time.Second
		}

		agentSPIFFEID := "unknown"
		if spiffeID, spiffeErr := agentIdentity.ToSPIFFEID("aflock.ai"); spiffeErr == nil {
			agentSPIFFEID = spiffeID.String()
		}
		token, tokenErr := issuer.IssueToken(
			input.SessionID,
			agentSPIFFEID,
			agentIdentity.IdentityHash,
			pol,
			ttl,
		)
		if tokenErr != nil {
			fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to issue JWT: %v\n", tokenErr)
		} else {
			sessionState.AuthToken = token
			fmt.Fprintf(os.Stderr, "[aflock] JWT issued for session %s (ttl=%s)\n", input.SessionID, ttl)
		}
	}

	if err := h.stateManager.Save(sessionState); err != nil {
		output.ExitWithWarning(fmt.Sprintf("Failed to save session state: %v", err))
		return nil
	}

	// Build context to inject
	context := h.buildPolicyContext(pol, agentIdentity)
	return output.Write(output.SessionStartContext(context))
}

// buildPolicyContext creates context string describing the active policy.
func (h *Handler) buildPolicyContext(pol *aflock.Policy, agentIdentity *identity.AgentIdentity) string { //nolint:gocognit // policy context assembly requires many checks
	ctx := fmt.Sprintf("# aflock Policy Active: %s\n\n", pol.Name)

	if agentIdentity != nil {
		ctx += "## Agent Identity\n"
		ctx += fmt.Sprintf("- Model: %s@%s\n", agentIdentity.Model, agentIdentity.ModelVersion)
		if agentIdentity.Binary != nil {
			ctx += fmt.Sprintf("- Binary: %s@%s\n", agentIdentity.Binary.Name, agentIdentity.Binary.Version)
		}
		idHash := agentIdentity.IdentityHash
		if len(idHash) > 16 {
			idHash = idHash[:16]
		}
		ctx += fmt.Sprintf("- Identity Hash: %s\n\n", idHash)
	}

	if pol.Limits != nil {
		ctx += "## Limits\n"
		if pol.Limits.MaxSpendUSD != nil {
			ctx += fmt.Sprintf("- Max spend: $%.2f (%s)\n", pol.Limits.MaxSpendUSD.Value, pol.Limits.MaxSpendUSD.Enforcement)
		}
		if pol.Limits.MaxTokensIn != nil {
			ctx += fmt.Sprintf("- Max tokens in: %.0f (%s)\n", pol.Limits.MaxTokensIn.Value, pol.Limits.MaxTokensIn.Enforcement)
		}
		if pol.Limits.MaxTurns != nil {
			ctx += fmt.Sprintf("- Max turns: %.0f (%s)\n", pol.Limits.MaxTurns.Value, pol.Limits.MaxTurns.Enforcement)
		}
		ctx += "\n"
	}

	if pol.Tools != nil {
		ctx += "## Tool Restrictions\n"
		if len(pol.Tools.Allow) > 0 {
			ctx += fmt.Sprintf("- Allowed: %v\n", pol.Tools.Allow)
		}
		if len(pol.Tools.Deny) > 0 {
			ctx += fmt.Sprintf("- Denied: %v\n", pol.Tools.Deny)
		}
		if len(pol.Tools.RequireApproval) > 0 {
			ctx += fmt.Sprintf("- Require approval: %v\n", pol.Tools.RequireApproval)
		}
		ctx += "\n"
	}

	if pol.Files != nil {
		ctx += "## File Restrictions\n"
		if len(pol.Files.Deny) > 0 {
			ctx += fmt.Sprintf("- Denied patterns: %v\n", pol.Files.Deny)
		}
		if len(pol.Files.ReadOnly) > 0 {
			ctx += fmt.Sprintf("- Read-only: %v\n", pol.Files.ReadOnly)
		}
		ctx += "\n"
	}

	return ctx
}

// handlePreToolUse evaluates policy before tool execution.
func (h *Handler) handlePreToolUse(input *aflock.HookInput) error {
	// Load session state. If session ID is empty or invalid, treat as no
	// session state and fall through to ephemeral policy loading below.
	var sessionState *aflock.SessionState
	if input.SessionID != "" {
		var err error
		sessionState, err = h.stateManager.Load(input.SessionID)
		if err != nil {
			output.ExitWithWarning(fmt.Sprintf("Failed to load session state: %v", err))
			return nil
		}
	}

	// If no session state, try to load policy directly (for when SessionStart wasn't run)
	if sessionState == nil || sessionState.Policy == nil {
		var pol *aflock.Policy
		var policyPath string
		var loadErr error

		// First try AFLOCK_POLICY env var (same as SessionStart)
		if envPolicy := os.Getenv("AFLOCK_POLICY"); envPolicy != "" {
			pol, policyPath, loadErr = policy.Load(envPolicy)
		} else {
			pol, policyPath, loadErr = policy.Load(input.Cwd)
		}

		if loadErr != nil {
			if errors.Is(loadErr, policy.ErrPolicyNotFound) {
				// No policy file exists — opt-in model, allow everything
				return output.Write(output.PreToolUseAllow())
			}
			// Policy file exists but is malformed — fail closed
			return output.Write(output.PreToolUseDeny(
				fmt.Sprintf("[aflock] Failed to load policy: %v", loadErr)))
		}
		// Deny if policy has identity constraints but SessionStart was skipped —
		// identity was never verified, so we cannot trust the agent.
		if pol.Identity != nil && len(pol.Identity.AllowedModels) > 0 {
			return output.Write(output.PreToolUseDeny(
				"[aflock] BLOCKED: policy requires identity verification but SessionStart was not called"))
		}
		if pol.IsExpired() {
			return output.Write(output.PreToolUseDeny(fmt.Sprintf("[aflock] BLOCKED: policy '%s' expired at %s", pol.Name, pol.Expires.Format(time.RFC3339))))
		}
		// Create ephemeral session state
		sessionState = h.stateManager.Initialize(input.SessionID, pol, policyPath)
	}

	pol := sessionState.Policy
	if pol.IsExpired() {
		return output.Write(output.PreToolUseDeny(fmt.Sprintf("[aflock] BLOCKED: policy '%s' expired at %s", pol.Name, pol.Expires.Format(time.RFC3339))))
	}
	// Use cwd as projectRoot when policy path is outside cwd (e.g., AFLOCK_POLICY env var
	// pointing to a tenant-specific policy in a subdirectory). Otherwise use the policy
	// file's directory (standard case where .aflock is at project root).
	projectRoot := filepath.Dir(sessionState.PolicyPath)
	if input.Cwd != "" {
		absCwd, _ := filepath.Abs(input.Cwd)
		absPolicyDir, _ := filepath.Abs(projectRoot)
		// If the policy dir is inside the cwd, patterns are likely relative to cwd
		if absCwd != absPolicyDir {
			relPolicyDir, err := filepath.Rel(absCwd, absPolicyDir)
			if err == nil && !filepath.IsAbs(relPolicyDir) && relPolicyDir != "." {
				// Policy is in a subdirectory — use cwd as project root
				projectRoot = absCwd
			}
		}
	}
	evaluator := policy.NewEvaluator(pol, projectRoot)

	// First evaluate tool/file access
	decision, reason := evaluator.EvaluatePreToolUse(input.ToolName, input.ToolInput)

	// If tool is allowed, check grants enforcement
	if decision == aflock.DecisionAllow && pol.Grants != nil {
		grantsDecision, grantsReason := evaluator.EvaluateGrants(input.ToolName, input.ToolInput)
		if grantsDecision != aflock.DecisionAllow {
			decision = grantsDecision
			reason = grantsReason
		}
	}

	// If tool is allowed, also check data flow rules
	if decision == aflock.DecisionAllow {
		flowDecision, flowReason, newMaterial := evaluator.EvaluateDataFlow(
			input.ToolName, input.ToolInput, sessionState.Materials)

		if flowDecision == aflock.DecisionDeny {
			decision = flowDecision
			reason = flowReason
		} else if newMaterial != nil {
			// Track the new material classification
			newMaterial.Timestamp = time.Now()
			sessionState.Materials = append(sessionState.Materials, *newMaterial)
		}
	}

	// Record the action
	h.stateManager.RecordAction(sessionState, aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  input.ToolName,
		ToolUseID: input.ToolUseID,
		ToolInput: input.ToolInput,
		Decision:  string(decision),
		Reason:    reason,
	})

	if err := h.stateManager.Save(sessionState); err != nil {
		output.ExitWithWarning(fmt.Sprintf("Failed to save session state: %v", err))
	}

	// If this is a subagent spawn, write propagation file so the child
	// session inherits materials and attenuated limits (Section 5: sublayout delegation).
	if isSubagentSpawn(input.ToolName) && sessionState.PolicyPath != "" {
		if err := h.stateManager.WritePropagation(sessionState); err != nil {
			fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to write propagation: %v\n", err)
		}
	}

	// Return decision as proper JSON response
	switch decision {
	case aflock.DecisionDeny:
		return output.Write(output.PreToolUseDeny(fmt.Sprintf("[aflock] BLOCKED: %s", reason)))
	case aflock.DecisionAsk:
		return output.Write(output.PreToolUseAsk(reason))
	default:
		return output.Write(output.PreToolUseAllow())
	}
}

// handlePostToolUse records tool execution and updates metrics.
func (h *Handler) handlePostToolUse(input *aflock.HookInput) error {
	// Load session state. Skip loading if no session ID (ephemeral session).
	var sessionState *aflock.SessionState
	if input.SessionID != "" {
		var err error
		sessionState, err = h.stateManager.Load(input.SessionID)
		if err != nil {
			output.ExitWithWarning(fmt.Sprintf("Failed to load session state: %v", err))
			return nil
		}
	}

	if sessionState == nil {
		return output.WriteEmpty()
	}

	// Track file access
	if isFileOperation(input.ToolName) {
		var fileInput aflock.FileToolInput
		if err := json.Unmarshal(input.ToolInput, &fileInput); err == nil {
			h.stateManager.TrackFile(sessionState, input.ToolName, fileInput.FilePath)
		}
	}

	// Save updated state
	if err := h.stateManager.Save(sessionState); err != nil {
		output.ExitWithWarning(fmt.Sprintf("Failed to save session state: %v", err))
	}

	// Check fail-fast limits after tool execution
	if sessionState.Policy != nil && sessionState.Policy.Limits != nil {
		evaluator := policy.NewEvaluator(sessionState.Policy, filepath.Dir(sessionState.PolicyPath))
		exceeded, limitName, msg := evaluator.CheckLimits(sessionState.Metrics, "fail-fast")
		if exceeded {
			return output.Write(output.PostToolUseBlock(
				fmt.Sprintf("[aflock] Limit exceeded: %s - %s", limitName, msg)))
		}
	}

	// Create and store attestation for this tool call
	h.createAttestation(sessionState, input)

	return output.WriteEmpty()
}

// createAttestation creates a signed attestation for a tool call and stores it on disk.
// Failures are logged as warnings — attestation is evidence, not enforcement.
// Uses identity metadata saved in session state from SessionStart to avoid
// re-discovering identity (and the noisy PID-walking warnings) on every tool call.
func (h *Handler) createAttestation(sessionState *aflock.SessionState, input *aflock.HookInput) {
	if sessionState == nil || sessionState.Policy == nil {
		return
	}

	// Reconstruct agent identity from session state (saved at SessionStart)
	// instead of re-discovering via PID walking on every PostToolUse call.
	// If the saved model is "unknown", try re-discovering — SessionStart may
	// have failed to find the model (e.g., new project with no session files)
	// but PostToolUse might succeed if Claude session files now exist.
	var agentIdentity *identity.AgentIdentity
	if meta := sessionState.AgentIdentityMeta; meta != nil && meta.Model != "" && meta.Model != "unknown" {
		agentIdentity = &identity.AgentIdentity{
			Model:        meta.Model,
			ModelVersion: meta.ModelVersion,
			IdentityHash: meta.IdentityHash,
			PolicyDigest: meta.PolicyDigest,
		}
		if meta.BinaryName != "" {
			agentIdentity.Binary = &identity.BinaryIdentity{
				Name:    meta.BinaryName,
				Version: meta.BinaryVer,
				Digest:  meta.BinaryDigest,
			}
		}
		if meta.Environment != "" {
			agentIdentity.Environment = &identity.EnvironmentIdentity{
				Type: meta.Environment,
			}
		}
	} else {
		// Saved identity has unknown model — try fresh discovery
		agentIdentity, _ = identity.DiscoverAgentIdentity()

		// Persist re-discovered identity back to session state so state.json
		// stays consistent with attestations (fixes "unknown" model lingering).
		if agentIdentity != nil && agentIdentity.Model != "" && agentIdentity.Model != "unknown" {
			sessionState.AgentIdentityMeta = &aflock.AgentIdentityMeta{
				Model:        agentIdentity.Model,
				ModelVersion: agentIdentity.ModelVersion,
				IdentityHash: agentIdentity.IdentityHash,
				PolicyDigest: agentIdentity.PolicyDigest,
				Environment: func() string {
					if agentIdentity.Environment != nil {
						return agentIdentity.Environment.Type
					}
					return ""
				}(),
			}
			if agentIdentity.Binary != nil {
				sessionState.AgentIdentityMeta.BinaryName = agentIdentity.Binary.Name
				sessionState.AgentIdentityMeta.BinaryVer = agentIdentity.Binary.Version
				sessionState.AgentIdentityMeta.BinaryDigest = agentIdentity.Binary.Digest
			}
			if err := h.stateManager.Save(sessionState); err != nil {
				fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to persist re-discovered identity: %v\n", err)
			}
		}
	}

	// Create signer — try SPIRE first, then Fulcio keyless, fall back to ephemeral key
	signer := attestation.NewSigner("")
	if err := signer.Initialize(context.Background()); err != nil {
		// SPIRE not available — try Fulcio keyless (CI/CD environments with OIDC)
		if fulcioErr := signer.InitializeFulcio(context.Background()); fulcioErr != nil {
			// Fulcio not available — use ephemeral key
			identityHash := ""
			if agentIdentity != nil {
				identityHash = agentIdentity.IdentityHash
			}
			if err := signer.InitializeEphemeral(identityHash); err != nil {
				fmt.Fprintf(os.Stderr, "[aflock] Warning: attestation signing unavailable: %v\n", err)
				return
			}
		}
	}
	defer signer.Close() //nolint:errcheck // best-effort cleanup

	// Build action record
	toolUseID := input.ToolUseID
	if toolUseID == "" {
		toolUseID = fmt.Sprintf("%s-%d", input.ToolName, time.Now().UnixNano())
	}

	record := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  input.ToolName,
		ToolUseID: toolUseID,
		ToolInput: input.ToolInput,
		Decision:  "allow",
	}

	// Create signed attestation
	envelope, err := signer.CreateActionAttestation(
		context.Background(),
		record,
		sessionState.SessionID,
		sessionState.Metrics,
		agentIdentity,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: attestation creation failed: %v\n", err)
		return
	}

	// Store attestation to disk
	attestDir := h.stateManager.AttestationsDir(sessionState.SessionID)
	if err := os.MkdirAll(attestDir, 0750); err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: create attestation dir: %v\n", err)
		return
	}

	ts := time.Now().Format("20060102-150405")
	prefix := toolUseID
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	filename := fmt.Sprintf("%s-%s.intoto.json", ts, prefix)
	path := filepath.Join(attestDir, filename)

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: marshal attestation: %v\n", err)
		return
	}

	if err := os.WriteFile(path, data, 0640); err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Warning: write attestation: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stderr, "[aflock] Attestation signed: %s\n", filename)
}

// handlePermissionRequest auto-approves or denies based on policy.
func (h *Handler) handlePermissionRequest(input *aflock.HookInput) error {
	// Load session state
	sessionState, err := h.stateManager.Load(input.SessionID)
	if err != nil {
		return output.WriteEmpty()
	}

	if sessionState == nil || sessionState.Policy == nil {
		return output.WriteEmpty()
	}

	// For now, let the user decide - don't auto-approve
	// Future: could auto-approve based on policy allowlists
	return output.WriteEmpty()
}

// handleUserPromptSubmit validates prompt against policy.
func (h *Handler) handleUserPromptSubmit(input *aflock.HookInput) error {
	// Load session state
	sessionState, err := h.stateManager.Load(input.SessionID)
	if err != nil {
		return output.WriteEmpty()
	}

	if sessionState == nil || sessionState.Policy == nil {
		return output.WriteEmpty()
	}

	// Increment turns on each user prompt
	h.stateManager.IncrementTurns(sessionState)
	if err := h.stateManager.Save(sessionState); err != nil {
		output.ExitWithWarning(fmt.Sprintf("Failed to save session state: %v", err))
	}

	return output.WriteEmpty()
}

// handleStop checks if required attestations are complete.
func (h *Handler) handleStop(input *aflock.HookInput) error {
	sessionState, err := h.stateManager.Load(input.SessionID)
	if err != nil {
		// Fail-closed: if we can't load state, we can't verify attestations
		return output.Write(output.StopBlock(
			fmt.Sprintf("[aflock] Cannot stop: failed to load session state: %v", err)))
	}

	if sessionState == nil || sessionState.Policy == nil {
		return output.Write(output.StopAllow())
	}

	// Check required attestations — only for tools that were actually used.
	// Policy constrains what must be attested, it doesn't instruct the agent
	// to use tools it wasn't asked to use. If the user never used Bash,
	// don't block Stop for a missing Bash attestation.
	if len(sessionState.Policy.RequiredAttestations) > 0 {
		usedTools := make(map[string]bool)
		for _, action := range sessionState.Actions {
			if action.Decision == "allow" {
				usedTools[action.ToolName] = true
			}
		}

		attestDir := h.stateManager.AttestationsDir(input.SessionID)
		var missing []string
		for _, required := range sessionState.Policy.RequiredAttestations {
			if usedTools[required] && !findAttestation(attestDir, required) {
				missing = append(missing, required)
			}
		}
		if len(missing) > 0 {
			return output.Write(output.StopBlock(
				fmt.Sprintf("[aflock] Cannot stop: missing attestations for used tools: %v", missing)))
		}
	}

	return output.Write(output.StopAllow())
}

// handleSubagentStop merges the child session's actions, metrics, and materials
// back into the parent session and checks post-hoc limits on the child.
func (h *Handler) handleSubagentStop(input *aflock.HookInput) error {
	// Load child session state
	if input.SessionID == "" {
		return output.Write(output.StopAllow())
	}
	childState, err := h.stateManager.Load(input.SessionID)
	if err != nil || childState == nil {
		return output.Write(output.StopAllow())
	}

	// If child has a parent, merge results back
	if childState.ParentSessionID != "" {
		parentState, loadErr := h.stateManager.Load(childState.ParentSessionID)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to load parent session %s: %v\n",
				childState.ParentSessionID, loadErr)
		} else if parentState != nil {
			mergeChildIntoParent(parentState, childState)
			if saveErr := h.stateManager.Save(parentState); saveErr != nil {
				fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to save parent session: %v\n", saveErr)
			}
		}
	}

	// Check post-hoc limits on the child session
	if childState.Policy != nil && childState.Policy.Limits != nil {
		evaluator := policy.NewEvaluator(childState.Policy, filepath.Dir(childState.PolicyPath))
		exceeded, limitName, msg := evaluator.CheckLimits(childState.Metrics, "post-hoc")
		if exceeded {
			return output.Write(output.StopBlock(
				fmt.Sprintf("[aflock] Subagent limit exceeded: %s - %s", limitName, msg)))
		}
	}

	return output.Write(output.StopAllow())
}

// handleSessionEnd finalizes attestations and runs verification.
func (h *Handler) handleSessionEnd(input *aflock.HookInput) error {
	sessionState, err := h.stateManager.Load(input.SessionID)
	if err != nil {
		return output.WriteEmpty()
	}

	if sessionState == nil || sessionState.Policy == nil {
		return output.WriteEmpty()
	}

	// Check post-hoc limits
	if sessionState.Policy.Limits != nil {
		evaluator := policy.NewEvaluator(sessionState.Policy, filepath.Dir(sessionState.PolicyPath))
		exceeded, limitName, msg := evaluator.CheckLimits(sessionState.Metrics, "post-hoc")
		if exceeded {
			fmt.Fprintf(os.Stderr, "[aflock] Post-hoc limit exceeded: %s - %s\n", limitName, msg)
			// Record the violation in session state for audit trail
			h.stateManager.RecordAction(sessionState, aflock.ActionRecord{
				Timestamp: time.Now(),
				ToolName:  "SessionEnd",
				Decision:  string(aflock.DecisionDeny),
				Reason:    fmt.Sprintf("post-hoc limit exceeded: %s - %s", limitName, msg),
			})
			if err := h.stateManager.Save(sessionState); err != nil {
				fmt.Fprintf(os.Stderr, "[aflock] Warning: failed to save session state: %v\n", err)
			}
		}
	}

	// Log final metrics
	fmt.Fprintf(os.Stderr, "[aflock] Session ended. Metrics: turns=%d, toolCalls=%d\n",
		sessionState.Metrics.Turns, sessionState.Metrics.ToolCalls)

	return output.WriteEmpty()
}

// handleNotification logs notifications.
func (h *Handler) handleNotification(_ *aflock.HookInput) error {
	// Just acknowledge
	return output.WriteEmpty()
}

// handlePreCompact records compaction event.
func (h *Handler) handlePreCompact(_ *aflock.HookInput) error {
	// Just acknowledge
	return output.WriteEmpty()
}

// findAttestation checks if a structurally valid attestation file exists for the given name.
// It first checks for exact filename matches (name.json, name.intoto.json),
// then scans all .intoto.json files in the directory and checks if any
// attestation's tool name matches the required name. Files must pass
// structural validation (valid DSSE envelope with non-empty signatures).
func findAttestation(dir, name string) bool {
	// First try exact filename match
	exactPaths := []string{
		filepath.Join(dir, name+".json"),
		filepath.Join(dir, name+".intoto.json"),
	}
	for _, p := range exactPaths {
		if _, err := os.Stat(p); err == nil {
			if validateAttestationIntegrity(p) {
				return true
			}
			fmt.Fprintf(os.Stderr, "[aflock] Warning: attestation file %s exists but failed structural validation\n", p)
		}
	}

	// Scan attestation files and check their content for matching tool names.
	// This handles the case where filenames are timestamp-prefixed (e.g., 20260210-143022-ab3def12.intoto.json)
	// but the required attestation is a logical name (e.g., "Bash").
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if entry.IsDir() || !isAttestationFile(entry.Name()) {
			continue
		}
		p := filepath.Join(dir, entry.Name())
		if attestationMatchesName(p, name) {
			if validateAttestationIntegrity(p) {
				return true
			}
			fmt.Fprintf(os.Stderr, "[aflock] Warning: attestation file %s matches name %q but failed structural validation\n", p, name)
		}
	}

	return false
}

// validateAttestationIntegrity performs structural validation on an attestation file.
// It checks that the file is a valid DSSE envelope with:
//   - A non-empty "payload" field
//   - A non-empty "payloadType" field
//   - A non-empty "signatures" array
//
// This does NOT perform cryptographic signature verification (that requires
// trusted roots), but prevents accepting fake/empty/malformed attestation files.
func validateAttestationIntegrity(path string) bool {
	data, err := os.ReadFile(path) //nolint:gosec // G304: attestation file path from state directory
	if err != nil {
		return false
	}

	var envelope struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return false
	}

	if envelope.Payload == "" {
		return false
	}
	if envelope.PayloadType == "" {
		return false
	}
	if len(envelope.Signatures) == 0 {
		return false
	}

	return true
}

// isAttestationFile checks if a filename looks like an attestation file.
func isAttestationFile(name string) bool {
	return strings.HasSuffix(name, ".intoto.json") || strings.HasSuffix(name, ".json")
}

// attestationMatchesName checks if an attestation file's content matches the required name.
// It looks at the predicate's toolName field in action attestations.
func attestationMatchesName(path, name string) bool {
	data, err := os.ReadFile(path) //nolint:gosec // G304: attestation file path from state directory
	if err != nil {
		return false
	}

	// Parse envelope to get payload
	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return false
	}

	// Parse statement to get predicate
	var statement struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &statement); err != nil {
		return false
	}

	// Check if the predicate's toolName matches
	var predicate struct {
		ToolName string `json:"toolName"`
		Action   string `json:"action"`
	}
	if err := json.Unmarshal(statement.Predicate, &predicate); err != nil {
		return false
	}

	return strings.EqualFold(predicate.ToolName, name) || strings.EqualFold(predicate.Action, name)
}

// isSubagentSpawn returns true if the tool triggers a subagent spawn.
func isSubagentSpawn(toolName string) bool {
	return toolName == "Agent" || toolName == "Task"
}

// attenuateLimits computes effective limits for a child session.
// For each limit field: child effective = min(child policy limit, parent remaining).
// If a parent has exhausted its budget, the child gets 0.
func attenuateLimits(childLimits, parentLimits *aflock.LimitsPolicy, parentMetrics *aflock.SessionMetrics) *aflock.LimitsPolicy {
	if parentLimits == nil {
		return childLimits
	}

	result := &aflock.LimitsPolicy{}
	if childLimits != nil {
		*result = *childLimits
	}

	attenuate := func(childLimit, parentLimit *aflock.Limit, parentUsed float64) *aflock.Limit {
		if parentLimit == nil {
			return childLimit
		}
		remaining := parentLimit.Value - parentUsed
		if remaining < 0 {
			remaining = 0
		}
		enforcement := parentLimit.Enforcement
		if childLimit != nil {
			if childLimit.Value < remaining {
				remaining = childLimit.Value
			}
			if childLimit.Enforcement != "" {
				enforcement = childLimit.Enforcement
			}
		}
		return &aflock.Limit{Value: remaining, Enforcement: enforcement}
	}

	result.MaxSpendUSD = attenuate(result.MaxSpendUSD, parentLimits.MaxSpendUSD, parentMetrics.CostUSD)
	result.MaxTokensIn = attenuate(result.MaxTokensIn, parentLimits.MaxTokensIn, float64(parentMetrics.TokensIn))
	result.MaxTokensOut = attenuate(result.MaxTokensOut, parentLimits.MaxTokensOut, float64(parentMetrics.TokensOut))
	result.MaxTurns = attenuate(result.MaxTurns, parentLimits.MaxTurns, float64(parentMetrics.Turns))
	result.MaxToolCalls = attenuate(result.MaxToolCalls, parentLimits.MaxToolCalls, float64(parentMetrics.ToolCalls))
	// MaxWallTimeSeconds is per-session, not inherited
	if childLimits != nil {
		result.MaxWallTimeSeconds = childLimits.MaxWallTimeSeconds
	}

	return result
}

// mergeChildIntoParent merges the child session's actions, metrics, and
// materials back into the parent session state.
func mergeChildIntoParent(parent, child *aflock.SessionState) {
	// Annotate and append child actions
	for _, action := range child.Actions {
		annotated := action
		annotated.Reason = fmt.Sprintf("[subagent:%s] %s", child.SessionID, action.Reason)
		parent.Actions = append(parent.Actions, annotated)
	}

	// Add child metrics to parent
	if child.Metrics != nil && parent.Metrics != nil {
		parent.Metrics.TokensIn += child.Metrics.TokensIn
		parent.Metrics.TokensOut += child.Metrics.TokensOut
		parent.Metrics.CostUSD += child.Metrics.CostUSD
		parent.Metrics.ToolCalls += child.Metrics.ToolCalls
		for tool, count := range child.Metrics.Tools {
			if parent.Metrics.Tools == nil {
				parent.Metrics.Tools = make(map[string]int)
			}
			parent.Metrics.Tools[tool] += count
		}
	}

	// Merge child materials into parent (deduplicated by label+source)
	existing := make(map[string]bool)
	for _, m := range parent.Materials {
		existing[m.Label+"\x00"+m.Source] = true
	}
	for _, m := range child.Materials {
		key := m.Label + "\x00" + m.Source
		if !existing[key] {
			parent.Materials = append(parent.Materials, m)
			existing[key] = true
		}
	}

	// Track child session ID
	parent.ChildSessionIDs = append(parent.ChildSessionIDs, child.SessionID)
}

func isFileOperation(toolName string) bool {
	switch toolName {
	case "Read", "Write", "Edit", "Glob", "Grep", "NotebookEdit":
		return true
	default:
		return false
	}
}
