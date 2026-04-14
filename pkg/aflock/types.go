// Package aflock provides types for the aflock policy enforcement system.
package aflock

import (
	"encoding/json"
	"strings"
	"time"
)

// HookEventName represents the type of hook event from Claude Code.
type HookEventName string

const (
	HookSessionStart      HookEventName = "SessionStart"
	HookPreToolUse        HookEventName = "PreToolUse"
	HookPostToolUse       HookEventName = "PostToolUse"
	HookPermissionRequest HookEventName = "PermissionRequest"
	HookUserPromptSubmit  HookEventName = "UserPromptSubmit"
	HookStop              HookEventName = "Stop"
	HookSubagentStop      HookEventName = "SubagentStop"
	HookSessionEnd        HookEventName = "SessionEnd"
	HookNotification      HookEventName = "Notification"
	HookPreCompact        HookEventName = "PreCompact"
)

// HookInput represents the JSON input from Claude Code hooks.
type HookInput struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	Cwd            string          `json:"cwd"`
	PermissionMode string          `json:"permission_mode,omitempty"`
	HookEventName  HookEventName   `json:"hook_event_name"`
	ToolName       string          `json:"tool_name,omitempty"`
	ToolInput      json.RawMessage `json:"tool_input,omitempty"`
	ToolResponse   json.RawMessage `json:"tool_response,omitempty"`
	ToolUseID      string          `json:"tool_use_id,omitempty"`
	Prompt         string          `json:"prompt,omitempty"`
	StopHookActive bool            `json:"stop_hook_active,omitempty"`
	Source         string          `json:"source,omitempty"`
	Reason         string          `json:"reason,omitempty"`
	Trigger        string          `json:"trigger,omitempty"`
}

// BashToolInput represents the input for the Bash tool.
type BashToolInput struct {
	Command     string `json:"command"`
	Description string `json:"description,omitempty"`
	Timeout     int    `json:"timeout,omitempty"`
}

// FileToolInput represents the input for Read/Write/Edit tools.
type FileToolInput struct {
	FilePath  string `json:"file_path"`
	Content   string `json:"content,omitempty"`
	OldString string `json:"old_string,omitempty"`
	NewString string `json:"new_string,omitempty"`
}

// TaskToolInput represents the input for the Task tool.
type TaskToolInput struct {
	Prompt       string `json:"prompt"`
	SubagentType string `json:"subagent_type,omitempty"`
}

// GlobToolInput represents the input for the Glob tool.
type GlobToolInput struct {
	Pattern string `json:"pattern"`
	Path    string `json:"path,omitempty"`
}

// GrepToolInput represents the input for the Grep tool.
type GrepToolInput struct {
	Pattern string `json:"pattern"`
	Path    string `json:"path,omitempty"`
	Glob    string `json:"glob,omitempty"`
}

// WebFetchToolInput represents the input for the WebFetch tool.
type WebFetchToolInput struct {
	URL    string `json:"url"`
	Prompt string `json:"prompt,omitempty"`
}

// WebSearchToolInput represents the input for the WebSearch tool.
type WebSearchToolInput struct {
	Query string `json:"query"`
}

// NotebookEditToolInput represents the input for the NotebookEdit tool.
type NotebookEditToolInput struct {
	NotebookPath string `json:"notebook_path"`
}

// PermissionDecision represents the decision for PreToolUse hooks.
type PermissionDecision string

const (
	DecisionAllow PermissionDecision = "allow"
	DecisionDeny  PermissionDecision = "deny"
	DecisionAsk   PermissionDecision = "ask"
)

// HookOutput represents the JSON output to Claude Code.
type HookOutput struct {
	Continue           bool                `json:"continue,omitempty"`
	StopReason         string              `json:"stopReason,omitempty"`
	SuppressOutput     bool                `json:"suppressOutput,omitempty"`
	SystemMessage      string              `json:"systemMessage,omitempty"`
	Decision           string              `json:"decision,omitempty"`
	Reason             string              `json:"reason,omitempty"`
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

// HookSpecificOutput contains hook-specific output fields.
type HookSpecificOutput struct {
	HookEventName            HookEventName      `json:"hookEventName"`
	PermissionDecision       PermissionDecision `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string             `json:"permissionDecisionReason,omitempty"`
	UpdatedInput             json.RawMessage    `json:"updatedInput,omitempty"`
	AdditionalContext        string             `json:"additionalContext,omitempty"`
	Decision                 *DecisionOutput    `json:"decision,omitempty"`
}

// DecisionOutput represents a permission request decision.
type DecisionOutput struct {
	Behavior     string          `json:"behavior"` // "allow" or "deny"
	UpdatedInput json.RawMessage `json:"updatedInput,omitempty"`
	Message      string          `json:"message,omitempty"`
	Interrupt    bool            `json:"interrupt,omitempty"`
}

// Policy represents an .aflock policy file.
// It combines attestation verification policy with real-time tool execution rules.
type Policy struct {
	// Metadata
	Version string     `json:"version"`
	Name    string     `json:"name"`
	Expires *time.Time `json:"expires,omitempty"`

	// Attestation verification fields (evaluated at verification time)
	Roots map[string]Root `json:"roots,omitempty"` // CA roots for signature verification
	Steps map[string]Step `json:"steps,omitempty"` // Required steps with functionaries and attestations

	// Real-time tool execution rules (evaluated during MCP calls)
	Identity   *IdentityPolicy `json:"identity,omitempty"`
	Grants     *GrantsPolicy   `json:"grants,omitempty"`
	Limits     *LimitsPolicy   `json:"limits,omitempty"`
	Tools      *ToolsPolicy    `json:"tools,omitempty"`
	Files      *FilesPolicy    `json:"files,omitempty"`
	Domains    *DomainsPolicy  `json:"domains,omitempty"`
	DataFlow   *DataFlowPolicy `json:"dataFlow,omitempty"`
	Hooks      *HooksConfig    `json:"hooks,omitempty"`
	Sublayouts []Sublayout     `json:"sublayouts,omitempty"`

	// Legacy fields (kept for backwards compatibility)
	RequiredAttestations []string          `json:"requiredAttestations,omitempty"`
	AttestationDir       string            `json:"attestationDir,omitempty"`
	AttestationsFrom     []string          `json:"attestationsFrom,omitempty"`
	MaterialsFrom        *MaterialsPolicy  `json:"materialsFrom,omitempty"`
	Evaluators           *EvaluatorsPolicy `json:"evaluators,omitempty"`
	Functionaries        []Functionary     `json:"functionaries,omitempty"` // Legacy, use Steps.Functionaries instead

	// RawDigest is the SHA-256 hex digest of the raw policy file bytes captured
	// at load time. Stored here (json:"-") so callers can bind tokens and
	// attestations to the exact file the user reviewed/signed, rather than
	// re-marshaling the parsed struct (which can normalize formatting and
	// produce a different digest for byte-identical input — issue #61 / L5).
	RawDigest string `json:"-"`
}

// Root represents a trust anchor (CA certificate) for signature verification.
type Root struct {
	Certificate string `json:"certificate"` // Base64-encoded PEM certificate
}

// Step represents a verification step in the supply chain.
type Step struct {
	Name          string            `json:"name"`
	Functionaries []StepFunctionary `json:"functionaries"`
	Attestations  []StepAttestation `json:"attestations"`
	ArtifactsFrom []string          `json:"artifactsFrom,omitempty"` // Steps whose products become this step's materials
}

// StepFunctionary defines who can sign attestations for a step.
type StepFunctionary struct {
	Type           string          `json:"type"` // "root", "publickey", "keyless"
	CertConstraint *CertConstraint `json:"certConstraint,omitempty"`
	PublicKeyID    string          `json:"publickeyid,omitempty"`

	// Keyless/Sigstore verification constraints (for type: "keyless")
	// Issuer is the expected OIDC issuer URL embedded in the Fulcio certificate
	// (e.g., "https://token.actions.githubusercontent.com")
	Issuer string `json:"issuer,omitempty"`
	// Subject is the expected OIDC subject (email or URI SAN), supports glob patterns
	// (e.g., "https://github.com/aflock-ai/aflock/.github/workflows/*")
	Subject string `json:"subject,omitempty"`
	// FulcioExtensions constrains Fulcio-specific certificate extensions (GitHub Actions fields)
	FulcioExtensions *FulcioExtensions `json:"fulcioExtensions,omitempty"`
}

// FulcioExtensions defines constraints on Fulcio certificate extensions.
// All non-empty fields must match (AND logic). Supports glob patterns.
type FulcioExtensions struct {
	Issuer                   string `json:"issuer,omitempty"`
	BuildTrigger             string `json:"buildTrigger,omitempty"`
	SourceRepositoryURI      string `json:"sourceRepositoryURI,omitempty"`
	SourceRepositoryRef      string `json:"sourceRepositoryRef,omitempty"`
	SourceRepositoryOwnerURI string `json:"sourceRepositoryOwnerURI,omitempty"`
	RunnerEnvironment        string `json:"runnerEnvironment,omitempty"`
	BuildSignerURI           string `json:"buildSignerURI,omitempty"`
	BuildSignerDigest        string `json:"buildSignerDigest,omitempty"`
}

// CertConstraint defines constraints on certificate attributes.
type CertConstraint struct {
	CommonName string   `json:"commonName,omitempty"`
	URIs       []string `json:"uris,omitempty"` // SPIFFE ID patterns
}

// StepAttestation defines required attestation types for a step.
type StepAttestation struct {
	Type         string       `json:"type"` // Attestation type URI
	RegoPolicies []RegoPolicy `json:"regopolicies,omitempty"`
}

// RegoPolicy defines a Rego policy for attestation validation.
type RegoPolicy struct {
	Name   string `json:"name"`
	Module string `json:"module"` // Base64-encoded Rego module
}

// IsExpired checks if the policy has expired.
func (p *Policy) IsExpired() bool {
	if p.Expires == nil {
		return false
	}
	return time.Now().After(*p.Expires)
}

// IdentityPolicy defines agent identity constraints.
type IdentityPolicy struct {
	AllowedModels       []string `json:"allowedModels,omitempty"`
	AllowedEnvironments []string `json:"allowedEnvironments,omitempty"`
	RequiredTools       []string `json:"requiredTools,omitempty"`
}

// GrantsPolicy defines resource access grants.
type GrantsPolicy struct {
	Secrets *AllowDenyPolicy `json:"secrets,omitempty"`
	APIs    *AllowDenyPolicy `json:"apis,omitempty"`
	Storage *AllowDenyPolicy `json:"storage,omitempty"`
}

// AllowDenyPolicy defines allow/deny patterns.
type AllowDenyPolicy struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// LimitsPolicy defines resource consumption limits.
type LimitsPolicy struct {
	MaxSpendUSD        *Limit `json:"maxSpendUSD,omitempty"`
	MaxTokensIn        *Limit `json:"maxTokensIn,omitempty"`
	MaxTokensOut       *Limit `json:"maxTokensOut,omitempty"`
	MaxTurns           *Limit `json:"maxTurns,omitempty"`
	MaxWallTimeSeconds *Limit `json:"maxWallTimeSeconds,omitempty"`
	MaxToolCalls       *Limit `json:"maxToolCalls,omitempty"`
}

// Limit represents a limit with optional enforcement mode.
type Limit struct {
	Value       float64 `json:"value"`
	Enforcement string  `json:"enforcement,omitempty"` // "fail-fast" or "post-hoc"
}

// UnmarshalJSON handles both number and object forms of limits.
func (l *Limit) UnmarshalJSON(data []byte) error {
	// Try number first
	var num float64
	if err := json.Unmarshal(data, &num); err == nil {
		l.Value = num
		l.Enforcement = "fail-fast"
		return nil
	}

	// Try object
	type limitObj struct {
		Value       float64 `json:"value"`
		Enforcement string  `json:"enforcement,omitempty"`
	}
	var obj limitObj
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	l.Value = obj.Value
	l.Enforcement = obj.Enforcement
	if l.Enforcement == "" {
		l.Enforcement = "fail-fast"
	}
	return nil
}

// ToolsPolicy defines tool access controls.
type ToolsPolicy struct {
	Allow           []string `json:"allow,omitempty"`
	Deny            []string `json:"deny,omitempty"`
	RequireApproval []string `json:"requireApproval,omitempty"`
}

// FilesPolicy defines file access controls.
type FilesPolicy struct {
	Allow    []string `json:"allow,omitempty"`
	Deny     []string `json:"deny,omitempty"`
	ReadOnly []string `json:"readOnly,omitempty"`
}

// DomainsPolicy defines network access controls.
type DomainsPolicy struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// MaterialsPolicy defines materials binding for provenance.
type MaterialsPolicy struct {
	Session   *SessionMaterial   `json:"session,omitempty"`
	Git       *GitMaterial       `json:"git,omitempty"`
	Artifacts []ArtifactMaterial `json:"artifacts,omitempty"`
}

// SessionMaterial defines session JSONL binding.
type SessionMaterial struct {
	Path       string `json:"path,omitempty"`
	MerkleRoot string `json:"merkleRoot,omitempty"`
	Algorithm  string `json:"algorithm,omitempty"`
}

// GitMaterial defines git tree binding.
type GitMaterial struct {
	TreeHash string `json:"treeHash,omitempty"`
	Branch   string `json:"branch,omitempty"`
}

// ArtifactMaterial defines additional artifact bindings.
type ArtifactMaterial struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest,omitempty"`
	URI    string            `json:"uri,omitempty"`
}

// EvaluatorsPolicy defines verification evaluators.
type EvaluatorsPolicy struct {
	Rego []RegoEvaluator `json:"rego,omitempty"`
	AI   []AIEvaluator   `json:"ai,omitempty"`
	GRPC []GRPCEvaluator `json:"grpc,omitempty"`
}

// RegoEvaluator defines a Rego policy evaluator.
type RegoEvaluator struct {
	Name   string `json:"name"`
	Policy string `json:"policy"`
}

// AIEvaluator defines an AI-based evaluator.
type AIEvaluator struct {
	Name     string `json:"name"`
	Prompt   string `json:"prompt"`
	Model    string `json:"model,omitempty"`
	Backend  string `json:"backend,omitempty"`  // "anthropic" (default) or "ollama"
	Endpoint string `json:"endpoint,omitempty"` // Ollama server URL (default: http://localhost:11434)
}

// GRPCEvaluator defines a gRPC-based evaluator.
type GRPCEvaluator struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

// Functionary defines an authorized signer.
type Functionary struct {
	Type        string `json:"type"` // "keyless", "publickey", "x509", "spiffe"
	Issuer      string `json:"issuer,omitempty"`
	Subject     string `json:"subject,omitempty"`
	PublicKeyID string `json:"publickeyid,omitempty"`

	// SPIFFE ID constraints (for type: "spiffe")
	// SPIFFEID is an exact SPIFFE ID match (e.g., "spiffe://aflock.ai/agent/claude-opus/4.5/abc123")
	SPIFFEID string `json:"spiffeId,omitempty"`

	// SPIFFEIDPattern is a glob pattern for matching SPIFFE IDs
	// (e.g., "spiffe://aflock.ai/agent/claude-opus/*")
	SPIFFEIDPattern string `json:"spiffeIdPattern,omitempty"`

	// TrustDomain constrains the allowed trust domains
	TrustDomain string `json:"trustDomain,omitempty"`

	// ModelConstraint limits to specific model prefixes (e.g., "claude-opus-*")
	ModelConstraint string `json:"modelConstraint,omitempty"`

	// VersionConstraint limits to specific model versions (e.g., ">=4.5.0")
	VersionConstraint string `json:"versionConstraint,omitempty"`
}

// Sublayout defines a sub-agent policy delegation.
type Sublayout struct {
	Name              string            `json:"name"`
	Policy            string            `json:"policy"`
	PolicyDigest      map[string]string `json:"policyDigest,omitempty"`
	Functionaries     []Functionary     `json:"functionaries,omitempty"`
	Limits            *LimitsPolicy     `json:"limits,omitempty"`
	Inherit           []string          `json:"inherit,omitempty"`
	AttestationPrefix string            `json:"attestationPrefix,omitempty"`
}

// HooksConfig defines hook-specific configuration.
type HooksConfig struct {
	Timeout           int    `json:"timeout,omitempty"`
	OnPolicyViolation string `json:"onPolicyViolation,omitempty"` // "block" or "warn"
	InjectContext     bool   `json:"injectContext,omitempty"`
}

// DataFlowPolicy defines data flow restrictions to prevent exfiltration.
// Integrates with materialsFrom to track data provenance.
type DataFlowPolicy struct {
	// Classify maps sensitivity labels to tool/MCP patterns
	// When a matching tool is used for reading, the label is added to materials taint
	Classify map[string][]string `json:"classify,omitempty"`

	// FlowRules defines blocked data flows (e.g., "internal->public")
	FlowRules []DataFlowRule `json:"flowRules,omitempty"`
}

// DataFlowRule defines a data flow restriction.
type DataFlowRule struct {
	// Deny specifies a blocked flow in format "source->sink" (e.g., "internal->public")
	Deny string `json:"deny"`

	// Message is shown when this rule is violated
	Message string `json:"message,omitempty"`
}

// ParseDataFlowRule parses a rule like "internal->public" into source and sink labels.
func ParseDataFlowRule(rule string) (source, sink string, ok bool) {
	parts := strings.Split(rule, "->")
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

// MaterialClassification tracks which materials have been accessed and their sensitivity.
type MaterialClassification struct {
	// Label is the sensitivity classification (e.g., "internal", "pii", "public")
	Label string `json:"label"`

	// Source is the tool/pattern that was matched
	Source string `json:"source"`

	// Timestamp when this material was accessed
	Timestamp time.Time `json:"timestamp"`

	// Digest of the material content (for provenance)
	Digest map[string]string `json:"digest,omitempty"`
}

// SessionState represents the runtime state for a session.
type SessionState struct {
	SessionID  string          `json:"session_id"`
	StartedAt  time.Time       `json:"started_at"`
	Policy     *Policy         `json:"policy,omitempty"`
	PolicyPath string          `json:"policy_path,omitempty"`
	Metrics    *SessionMetrics `json:"metrics"`
	Actions    []ActionRecord  `json:"actions,omitempty"`
	// Materials tracks accessed data sources with their classifications for provenance
	Materials []MaterialClassification `json:"materials,omitempty"`
	// ParentSessionID is set when this session was spawned by a parent agent
	ParentSessionID string `json:"parent_session_id,omitempty"`
	// ChildSessionIDs tracks subagent sessions spawned from this session
	ChildSessionIDs []string `json:"child_session_ids,omitempty"`
	// AgentIdentityMeta stores identity discovered at SessionStart for reuse in PostToolUse
	AgentIdentityMeta *AgentIdentityMeta `json:"agent_identity_meta,omitempty"`
	// AuthToken is the JWT issued at SessionStart for request-level authorization.
	// Scoped to the session, agent identity, and policy grants.
	AuthToken string `json:"auth_token,omitempty"`
}

// AgentIdentityMeta stores agent identity metadata in session state.
// This is a serializable subset of identity.AgentIdentity, saved at SessionStart
// and reused in PostToolUse to avoid re-discovering identity per tool call.
type AgentIdentityMeta struct {
	Model        string `json:"model"`
	ModelVersion string `json:"model_version,omitempty"`
	BinaryName   string `json:"binary_name,omitempty"`
	BinaryVer    string `json:"binary_version,omitempty"`
	BinaryDigest string `json:"binary_digest,omitempty"`
	Environment  string `json:"environment,omitempty"`
	PolicyDigest string `json:"policy_digest,omitempty"`
	IdentityHash string `json:"identity_hash"`
}

// PropagationRecord is written by a parent session's PreToolUse(Agent) hook
// and consumed by the child session's SessionStart hook, enabling material
// and limit inheritance across subagent boundaries.
type PropagationRecord struct {
	ParentSessionID string                   `json:"parent_session_id"`
	PolicyPath      string                   `json:"policy_path"`
	Materials       []MaterialClassification `json:"materials"`
	ParentMetrics   *SessionMetrics          `json:"parent_metrics"`
	ParentLimits    *LimitsPolicy            `json:"parent_limits,omitempty"`
	CreatedAt       time.Time                `json:"created_at"`
}

// IsExpiredPropagation checks if the propagation record has exceeded the given TTL.
func (p *PropagationRecord) IsExpiredPropagation(ttl time.Duration) bool {
	return time.Since(p.CreatedAt) > ttl
}

// SessionMetrics tracks cumulative metrics.
type SessionMetrics struct {
	TokensIn     int64          `json:"tokensIn"`
	TokensOut    int64          `json:"tokensOut"`
	CostUSD      float64        `json:"costUSD"`
	Turns        int            `json:"turns"`
	ToolCalls    int            `json:"toolCalls"`
	Tools        map[string]int `json:"tools"`
	FilesRead    []string       `json:"filesRead,omitempty"`
	FilesWritten []string       `json:"filesWritten,omitempty"`
}

// ActionRecord represents a recorded action.
type ActionRecord struct {
	Timestamp time.Time       `json:"timestamp"`
	ToolName  string          `json:"tool_name"`
	ToolUseID string          `json:"tool_use_id"`
	ToolInput json.RawMessage `json:"tool_input,omitempty"`
	Decision  string          `json:"decision"` // "allow", "deny", "ask"
	Reason    string          `json:"reason,omitempty"`
}
