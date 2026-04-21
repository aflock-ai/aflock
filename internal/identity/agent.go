// Package identity provides agent identity derivation based on transitive workload identity.
package identity

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// AgentIdentity represents the cryptographic identity of an AI agent.
// Identity is derived from the transitive chain: model → tools → policy → parent.
type AgentIdentity struct {
	// Model identifier with version (e.g., "claude-opus-4-5-20251101")
	Model string `json:"model"`

	// ModelVersion is the semantic version of the model (e.g., "4.5.20251101")
	ModelVersion string `json:"modelVersion,omitempty"`

	// Binary is the agent binary path and version
	Binary *BinaryIdentity `json:"binary"`

	// Environment describes the execution environment
	Environment *EnvironmentIdentity `json:"environment"`

	// Tools available to the agent
	Tools []string `json:"tools"`

	// PolicyDigest is the SHA256 of the .aflock policy
	PolicyDigest string `json:"policyDigest"`

	// SessionID binds to the current session
	SessionID string `json:"sessionId,omitempty"`

	// SessionPath is the path to the Claude session file
	SessionPath string `json:"sessionPath,omitempty"`

	// ClaudePID is the PID of the Claude process
	ClaudePID int `json:"claudePid,omitempty"`

	// ProcessChain is the full chain of processes from aflock to init
	ProcessChain []ProcessInfo `json:"processChain,omitempty"`

	// ParentIdentity is the identity of the parent agent (for sublayouts)
	ParentIdentity string `json:"parentIdentity,omitempty"`

	// IdentityHash is the computed transitive identity hash
	IdentityHash string `json:"identityHash,omitempty"`

	// SPIFFEID is the SPIFFE ID derived from this identity
	SPIFFEID spiffeid.ID `json:"-"`

	// mu protects mutable derived fields (IdentityHash, SPIFFEID) from
	// concurrent access. Methods that compute or read these fields must
	// hold the appropriate lock.
	mu sync.RWMutex `json:"-"`
}

// BinaryIdentity describes the agent binary.
type BinaryIdentity struct {
	// Path to the binary (e.g., "/usr/local/bin/claude")
	Path string `json:"path"`

	// Name of the binary (e.g., "claude-code")
	Name string `json:"name"`

	// Version in semver format (e.g., "1.0.26")
	Version string `json:"version"`

	// Digest is the SHA256 of the binary (optional, for stricter verification)
	Digest string `json:"digest,omitempty"`
}

// EnvironmentIdentity describes the execution environment.
type EnvironmentIdentity struct {
	// Type of environment: "local", "container", "kubernetes"
	Type string `json:"type"`

	// UserID on the system
	UserID int `json:"userId,omitempty"`

	// Hostname
	Hostname string `json:"hostname,omitempty"`

	// ContainerID if running in a container
	ContainerID string `json:"containerId,omitempty"`

	// ImageDigest if running in a container
	ImageDigest string `json:"imageDigest,omitempty"`

	// Namespace if running in Kubernetes
	Namespace string `json:"namespace,omitempty"`

	// PodName if running in Kubernetes
	PodName string `json:"podName,omitempty"`
}

// DeriveIdentity computes the transitive identity hash per the aflock paper
// (Section 3.1, Equation 1):
//
//	AgentIdentity = SHA256(model ‖ env ‖ tools ‖ policyDigest ‖ parent)
//
// The five top-level components are joined with "|" in fixed order. The "env"
// component bundles all PID-introspected properties the paper attributes to
// it: binary path/name/version/digest, OS user/group, hostname, container ID,
// container image digest, and Kubernetes namespace/pod. Bundling preserves
// the security guarantees of binding the hash to binary and runtime
// properties while matching the paper's 5-component formula (issue #61 / M16).
func (a *AgentIdentity) DeriveIdentity() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.deriveIdentityLocked()
}

// canonicalEnv serializes the env component as
//
//	env:<type>;<k1>=<v1>;<k2>=<v2>;...
//
// Sub-fields are emitted in a fixed order and only when non-empty so the
// canonical string is deterministic and minimally surprising. Binary fields
// nest here per the paper (binary path is one of the PID-introspected env
// properties listed in §3.1).
func (a *AgentIdentity) canonicalEnv() string {
	parts := []string{"env:"}
	if a.Environment != nil {
		parts[0] = "env:" + a.Environment.Type
	}

	add := func(key, value string) {
		if value != "" {
			parts = append(parts, fmt.Sprintf("%s=%s", key, value))
		}
	}

	if a.Binary != nil {
		add("binary", a.Binary.Name+"@"+a.Binary.Version)
		add("binary_path", a.Binary.Path)
		add("binary_digest", a.Binary.Digest)
	}
	if a.Environment != nil {
		if a.Environment.UserID != 0 {
			add("user", fmt.Sprintf("%d", a.Environment.UserID))
		}
		add("hostname", a.Environment.Hostname)
		add("container", a.Environment.ContainerID)
		add("image", a.Environment.ImageDigest)
		add("namespace", a.Environment.Namespace)
		add("pod", a.Environment.PodName)
	}
	return strings.Join(parts, ";")
}

// deriveIdentityLocked computes the identity hash. Caller must hold a.mu.
func (a *AgentIdentity) deriveIdentityLocked() string {
	// Build canonical representation per paper §3.1:
	// SHA256(model ‖ env ‖ tools ‖ policyDigest ‖ parent)
	sortedTools := make([]string, len(a.Tools))
	copy(sortedTools, a.Tools)
	sort.Strings(sortedTools)

	components := []string{
		fmt.Sprintf("model:%s@%s", a.Model, a.ModelVersion),
		a.canonicalEnv(),
		fmt.Sprintf("tools:%s", strings.Join(sortedTools, ",")),
		fmt.Sprintf("policy:%s", a.PolicyDigest),
		fmt.Sprintf("parent:%s", a.ParentIdentity),
	}

	canonical := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(canonical))
	a.IdentityHash = hex.EncodeToString(hash[:])

	return a.IdentityHash
}

// ToSPIFFEID converts the agent identity to a SPIFFE ID.
// Format: spiffe://<trust-domain>/agent/<model>/<version>/<identity-hash>
func (a *AgentIdentity) ToSPIFFEID(trustDomain string) (spiffeid.ID, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.IdentityHash == "" {
		a.deriveIdentityLocked()
	}

	// Build path components
	modelPath := sanitizeSPIFFEPath(a.Model)
	versionPath := sanitizeSPIFFEPath(a.ModelVersion)
	hashPrefix := a.IdentityHash[:16] // Use first 16 chars for brevity

	path := fmt.Sprintf("/agent/%s/%s/%s", modelPath, versionPath, hashPrefix)

	id, err := spiffeid.FromSegments(spiffeid.RequireTrustDomainFromString(trustDomain), strings.Split(path, "/")[1:]...)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("invalid SPIFFE ID: %w", err)
	}

	a.SPIFFEID = id
	return id, nil
}

// DiscoverAgentIdentity discovers the current agent's identity from the environment.
// Uses PID-based discovery to trace the Claude process and session.
func DiscoverAgentIdentity() (*AgentIdentity, error) {
	identity := &AgentIdentity{}

	// Use comprehensive PID-based discovery
	model, meta, err := DiscoverFromMCPSocket()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] PID-based discovery failed: %v\n", err)
		identity.Model = "unknown"
	} else {
		identity.Model = model
		identity.SessionID = meta.SessionID
		identity.SessionPath = meta.SessionPath
		identity.ClaudePID = meta.ClaudePID
		identity.ProcessChain = meta.ProcessChain
	}

	identity.ModelVersion = parseModelVersion(identity.Model)

	// Discover binary
	identity.Binary = discoverBinary()

	// Discover environment
	identity.Environment = discoverEnvironment()

	// Compute identity hash
	identity.DeriveIdentity()

	return identity, nil
}

// parseModelVersion extracts semantic version from model identifier.
func parseModelVersion(model string) string {
	// Pattern: model-name-X-Y-YYYYMMDD or model-name-X.Y.Z
	patterns := []string{
		`(\d+)-(\d+)-(\d{8})$`, // claude-opus-4-5-20251101
		`(\d+)\.(\d+)\.(\d+)$`, // claude-opus-4.5.0
		`(\d+)-(\d+)$`,         // claude-opus-4-5
		`(\d+)$`,               // claude-opus-4
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(model); len(matches) > 0 {
			switch len(matches) {
			case 4: // Full version with date
				return fmt.Sprintf("%s.%s.%s", matches[1], matches[2], matches[3])
			case 3: // Major.Minor
				return fmt.Sprintf("%s.%s.0", matches[1], matches[2])
			case 2: // Major only
				return fmt.Sprintf("%s.0.0", matches[1])
			}
		}
	}

	return "0.0.0"
}

// discoverBinary discovers the agent binary information including SHA256 digest.
func discoverBinary() *BinaryIdentity {
	binary := &BinaryIdentity{}

	// Get binary path from environment or common locations
	if path := os.Getenv("CLAUDE_BINARY"); path != "" {
		binary.Path = path
	} else {
		// Try to find claude binary
		if claudePath, err := exec.LookPath("claude"); err == nil {
			binary.Path = claudePath
		}
	}

	// Get version and compute digest
	if binary.Path != "" {
		binary.Name = "claude-code"

		// Get version
		if out, err := exec.Command(binary.Path, "--version").Output(); err == nil { //nolint:gosec // G204: command constructed from config, not user taint
			versionPattern := regexp.MustCompile(`(\d+\.\d+\.\d+)`)
			if matches := versionPattern.FindStringSubmatch(string(out)); len(matches) > 1 {
				binary.Version = matches[1]
			}
		}

		// Resolve to the actual executable (follows symlinks and shell wrappers)
		actualPath := resolveActualBinary(binary.Path)
		binary.Digest = computeBinaryDigest(actualPath)
	}

	if binary.Version == "" {
		binary.Version = "0.0.0"
	}

	return binary
}

// resolveActualBinary follows symlinks and shell script wrappers to find the actual binary.
func resolveActualBinary(path string) string {
	return resolveActualBinaryDepth(path, 0, nil)
}

// resolveActualBinaryDepth follows exec chains with depth limit and cycle detection.
const maxResolveDepth = 10
const maxScriptSize = 1 << 20 // 1 MiB — shell wrappers should be small

func resolveActualBinaryDepth(path string, depth int, seen map[string]bool) string {
	if depth >= maxResolveDepth {
		return path
	}
	if seen == nil {
		seen = make(map[string]bool)
	}

	// First resolve symlinks
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}

	// Cycle detection
	if seen[resolved] {
		return resolved
	}
	seen[resolved] = true

	// Check file size before reading to avoid OOM on large or special files
	info, err := os.Stat(resolved)
	if err != nil || info.Size() > maxScriptSize || info.IsDir() {
		return resolved
	}

	// Check if it's a shell script wrapper
	content, err := os.ReadFile(resolved)
	if err != nil {
		return resolved
	}

	// Look for exec patterns in shell scripts
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Match patterns like: exec "/path/to/binary" "$@"
		if strings.HasPrefix(line, "exec ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				target := strings.Trim(parts[1], "\"'")
				if strings.HasPrefix(target, "/") {
					return resolveActualBinaryDepth(target, depth+1, seen)
				}
			}
		}
	}

	return resolved
}

// computeBinaryDigest computes the SHA256 digest of a binary file using cryptoutil.
func computeBinaryDigest(path string) string {
	// Resolve symlinks to get the actual binary
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolvedPath = path
	}

	// Use cryptoutil for consistent digest calculation
	sha256Digest := cryptoutil.DigestValue{Hash: crypto.SHA256}
	digestSet, err := cryptoutil.CalculateDigestSetFromFile(resolvedPath, []cryptoutil.DigestValue{sha256Digest})
	if err != nil {
		return ""
	}

	// Get SHA256 from the digest set
	digestMap, err := digestSet.ToNameMap()
	if err != nil {
		return ""
	}

	return digestMap["sha256"]
}

// discoverEnvironment discovers the execution environment.
func discoverEnvironment() *EnvironmentIdentity { //nolint:gocognit,nestif // environment discovery is inherently complex with nested checks
	env := &EnvironmentIdentity{}

	// Check for container environment
	if _, err := os.Stat("/.dockerenv"); err == nil { //nolint:nestif
		env.Type = "container"
		// Try to get container ID from cgroup
		if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.Contains(line, "docker") || strings.Contains(line, "containerd") {
					parts := strings.Split(line, "/")
					if len(parts) > 0 {
						containerID := parts[len(parts)-1]
						if len(containerID) > 12 {
							containerID = containerID[:12]
						}
						env.ContainerID = containerID
						break
					}
				}
			}
		}
	} else if _, err := os.Stat("/var/run/secrets/kubernetes.io"); err == nil {
		env.Type = "kubernetes"
		if ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
			env.Namespace = strings.TrimSpace(string(ns))
		}
		if hostname, err := os.Hostname(); err == nil {
			env.PodName = hostname
		}
	} else {
		env.Type = "local"
	}

	env.UserID = os.Getuid()
	if hostname, err := os.Hostname(); err == nil {
		env.Hostname = hostname
	}

	return env
}

// sanitizeSPIFFEPath sanitizes a string for use in SPIFFE ID path.
func sanitizeSPIFFEPath(s string) string {
	// Replace non-alphanumeric with dashes, lowercase
	re := regexp.MustCompile(`[^a-zA-Z0-9]+`)
	return strings.ToLower(re.ReplaceAllString(s, "-"))
}

// MarshalJSON implements custom JSON marshaling.
func (a *AgentIdentity) MarshalJSON() ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	type Alias AgentIdentity
	return json.Marshal(&struct {
		SPIFFEID string `json:"spiffeId,omitempty"`
		*Alias
	}{
		SPIFFEID: a.SPIFFEID.String(),
		Alias:    (*Alias)(a),
	})
}

// String returns a human-readable representation of the identity.
func (a *AgentIdentity) String() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.IdentityHash == "" {
		a.deriveIdentityLocked()
	}
	return fmt.Sprintf("agent:%s@%s#%s", a.Model, a.ModelVersion, a.IdentityHash[:16])
}

// Matches checks if this identity matches constraints in a policy.
func (a *AgentIdentity) Matches(allowedModels []string, allowedVersions []string) bool {
	// Check model
	modelMatch := false
	for _, allowed := range allowedModels {
		if matchGlob(allowed, a.Model) {
			modelMatch = true
			break
		}
	}
	if !modelMatch && len(allowedModels) > 0 {
		return false
	}

	// Check version (semver range matching)
	if len(allowedVersions) > 0 {
		versionMatch := false
		for _, allowed := range allowedVersions {
			if matchSemver(allowed, a.ModelVersion) {
				versionMatch = true
				break
			}
		}
		if !versionMatch {
			return false
		}
	}

	return true
}

// matchGlob performs simple glob matching with * wildcard.
func matchGlob(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	}
	return pattern == value
}

// matchSemver performs simple semver range matching.
// Supports: exact (1.2.3), major (1.x), minor (1.2.x), gte (>=1.2.3)
func matchSemver(pattern, version string) bool {
	if pattern == "*" || pattern == "x" {
		return true
	}

	// Handle >=
	if strings.HasPrefix(pattern, ">=") {
		return compareSemver(version, pattern[2:]) >= 0
	}

	// Handle x wildcard
	if strings.Contains(pattern, "x") {
		parts := strings.Split(pattern, ".")
		vparts := strings.Split(version, ".")
		for i, p := range parts {
			if p == "x" {
				continue
			}
			if i >= len(vparts) || vparts[i] != p {
				return false
			}
		}
		return true
	}

	return pattern == version
}

// compareSemver compares two semver strings.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareSemver(a, b string) int {
	apartsStr := strings.Split(a, ".")
	bpartsStr := strings.Split(b, ".")

	for i := 0; i < 3; i++ {
		var aval, bval int
		if i < len(apartsStr) {
			_, _ = fmt.Sscanf(apartsStr[i], "%d", &aval)
		}
		if i < len(bpartsStr) {
			_, _ = fmt.Sscanf(bpartsStr[i], "%d", &bval)
		}
		if aval < bval {
			return -1
		}
		if aval > bval {
			return 1
		}
	}
	return 0
}

// Functionary represents an authorized signer for policy verification.
type Functionary struct {
	Type              string `json:"type"` // "keyless", "publickey", "x509", "spiffe"
	Issuer            string `json:"issuer,omitempty"`
	Subject           string `json:"subject,omitempty"`
	PublicKeyID       string `json:"publickeyid,omitempty"`
	SPIFFEID          string `json:"spiffeId,omitempty"`
	SPIFFEIDPattern   string `json:"spiffeIdPattern,omitempty"`
	TrustDomain       string `json:"trustDomain,omitempty"`
	ModelConstraint   string `json:"modelConstraint,omitempty"`
	VersionConstraint string `json:"versionConstraint,omitempty"`
}

// MatchesFunctionary checks if this agent identity matches a functionary constraint.
// Note: keyless functionaries are verified at the attestation/signature level
// (Fulcio cert extensions checked during DSSE signature verification in verify/keyless.go),
// not at the agent identity level. This method only handles identity-based matching.
func (a *AgentIdentity) MatchesFunctionary(f Functionary) bool {
	// Check SPIFFE type functionary
	if f.Type == "spiffe" {
		return a.matchesSPIFFEFunctionary(f)
	}

	// For other types (keyless, publickey, x509), matching happens at the
	// signature/certificate level, not the agent identity level.
	return false
}

// matchesSPIFFEFunctionary checks SPIFFE-based functionary constraints.
func (a *AgentIdentity) matchesSPIFFEFunctionary(f Functionary) bool {
	// Check exact SPIFFE ID match
	if f.SPIFFEID != "" {
		if a.SPIFFEID.String() != f.SPIFFEID {
			return false
		}
	}

	// Check SPIFFE ID pattern match
	if f.SPIFFEIDPattern != "" {
		if !matchGlob(f.SPIFFEIDPattern, a.SPIFFEID.String()) {
			return false
		}
	}

	// Check trust domain
	if f.TrustDomain != "" {
		if a.SPIFFEID.TrustDomain().String() != f.TrustDomain {
			return false
		}
	}

	// Check model constraint
	if f.ModelConstraint != "" {
		if !matchGlob(f.ModelConstraint, a.Model) {
			return false
		}
	}

	// Check version constraint
	if f.VersionConstraint != "" {
		if !matchSemver(f.VersionConstraint, a.ModelVersion) {
			return false
		}
	}

	return true
}

// MatchesAnyFunctionary checks if this agent matches any of the given functionaries.
func (a *AgentIdentity) MatchesAnyFunctionary(functionaries []Functionary) bool {
	if len(functionaries) == 0 {
		return true // No constraints means allowed
	}

	for _, f := range functionaries {
		if a.MatchesFunctionary(f) {
			return true
		}
	}
	return false
}

// ToFunctionary creates a Functionary from this agent identity for policy use.
func (a *AgentIdentity) ToFunctionary(trustDomain string) Functionary {
	a.mu.Lock()
	if a.SPIFFEID.IsZero() {
		// Derive identity if needed, then compute SPIFFE ID, all under lock.
		if a.IdentityHash == "" {
			a.deriveIdentityLocked()
		}
		modelPath := sanitizeSPIFFEPath(a.Model)
		versionPath := sanitizeSPIFFEPath(a.ModelVersion)
		hashPrefix := a.IdentityHash[:16]
		path := fmt.Sprintf("/agent/%s/%s/%s", modelPath, versionPath, hashPrefix)
		id, err := spiffeid.FromSegments(spiffeid.RequireTrustDomainFromString(trustDomain), strings.Split(path, "/")[1:]...)
		if err == nil {
			a.SPIFFEID = id
		}
	}
	spiffeIDStr := a.SPIFFEID.String()
	model := a.Model
	modelVersion := a.ModelVersion
	a.mu.Unlock()

	return Functionary{
		Type:              "spiffe",
		SPIFFEID:          spiffeIDStr,
		TrustDomain:       trustDomain,
		ModelConstraint:   model,
		VersionConstraint: fmt.Sprintf(">=%s", modelVersion),
	}
}
