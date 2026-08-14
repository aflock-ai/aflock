// Package identity provides PID-based model discovery for AI agents.
package identity

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

const osLinux = "linux"

// DiscoverModelFromPID discovers the AI model by tracing the parent process.
// It finds the Claude process, gets its working directory, and reads the active session file.
func DiscoverModelFromPID() (string, error) {
	// Get parent PID (Claude Code process that spawned aflock)
	ppid := os.Getppid()
	fmt.Fprintf(os.Stderr, "[aflock] Parent PID: %d\n", ppid)

	// Walk up the process tree to find Claude process
	pids := getProcessChain(ppid)
	fmt.Fprintf(os.Stderr, "[aflock] Process chain: %v\n", pids)

	// For each PID in the chain, check if it's the claude process
	for _, pid := range pids {
		cmd, err := getProcessCommand(pid)
		if err != nil {
			continue
		}

		// Look for the "claude" binary (not subprocesses like node)
		if !strings.Contains(cmd, "claude") || strings.Contains(cmd, "node") {
			continue
		}

		fmt.Fprintf(os.Stderr, "[aflock] Found Claude process: PID %d (%s)\n", pid, cmd)

		// Get Claude's working directory
		workDir, err := getProcessWorkingDir(pid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[aflock] Could not get working dir for PID %d: %v\n", pid, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "[aflock] Claude working directory: %s\n", workDir)

		// Find the session file from the working directory
		model, err := findModelFromWorkingDir(workDir)
		if err == nil && model != "" {
			return model, nil
		}
		fmt.Fprintf(os.Stderr, "[aflock] Could not find model from working dir: %v\n", err)
	}

	// Fallback: try to find open session files directly
	for _, pid := range pids {
		model, err := findModelFromOpenFiles(pid)
		if err == nil && model != "" {
			return model, nil
		}
	}

	return "", fmt.Errorf("could not discover model from process chain")
}

// getProcessWorkingDir gets the current working directory of a process.
func getProcessWorkingDir(pid int) (string, error) {
	if runtime.GOOS == osLinux {
		return getProcessWorkingDirLinux(pid)
	}
	return getProcessWorkingDirMacOS(pid)
}

// getProcessWorkingDirLinux reads from /proc/<pid>/cwd
func getProcessWorkingDirLinux(pid int) (string, error) {
	cwdPath := fmt.Sprintf("/proc/%d/cwd", pid)
	return os.Readlink(cwdPath)
}

// getProcessWorkingDirMacOS uses lsof to get working directory
func getProcessWorkingDirMacOS(pid int) (string, error) {
	cmd := exec.Command("lsof", "-p", strconv.Itoa(pid), "-Fn") //nolint:gosec // G204: subprocess from discovered process path, not user taint
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Look for cwd entry - it comes right after "fcwd" line
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if line == "fcwd" && i+1 < len(lines) {
			next := lines[i+1]
			if strings.HasPrefix(next, "n") {
				return next[1:], nil
			}
		}
	}

	return "", fmt.Errorf("cwd not found in lsof output")
}

// SessionIndexEntry represents an entry in Claude's sessions-index.json
type SessionIndexEntry struct {
	SessionID   string `json:"sessionId"`
	FullPath    string `json:"fullPath"`
	FileMtime   int64  `json:"fileMtime"`
	ProjectPath string `json:"projectPath"`
	Modified    string `json:"modified"`
}

// SessionIndex represents Claude's sessions-index.json
type SessionIndex struct {
	Version int                 `json:"version"`
	Entries []SessionIndexEntry `json:"entries"`
}

// findModelFromWorkingDir finds the model from Claude's working directory.
// It uses sessions-index.json to find the active session matching the working directory.
func findModelFromWorkingDir(workDir string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Convert working directory to Claude's project slug format
	// /Users/nkennedy/proj/aflock -> -Users-nkennedy-proj-aflock
	projectSlug := strings.ReplaceAll(workDir, "/", "-")

	projectDir := filepath.Join(homeDir, ".claude", "projects", projectSlug)
	indexPath := filepath.Join(projectDir, "sessions-index.json")
	fmt.Fprintf(os.Stderr, "[aflock] Reading sessions index: %s\n", indexPath)

	// Read and parse sessions-index.json
	indexData, err := os.ReadFile(indexPath) //nolint:gosec // G304: reading process info files
	if err != nil {
		// Fall back to most recent file if index doesn't exist
		return findModelFromMostRecentSession(projectDir)
	}

	var index SessionIndex
	if err := json.Unmarshal(indexData, &index); err != nil {
		return findModelFromMostRecentSession(projectDir)
	}

	// Find sessions matching the working directory
	// Match if:
	// 1. Exact match
	// 2. workDir is within the session's projectPath (workDir is subdirectory)
	// 3. session's projectPath is within workDir (session started in subdirectory)
	var matchingSessions []SessionIndexEntry
	for _, entry := range index.Entries {
		if entry.ProjectPath == workDir ||
			strings.HasPrefix(workDir, entry.ProjectPath+"/") ||
			strings.HasPrefix(entry.ProjectPath, workDir+"/") {
			matchingSessions = append(matchingSessions, entry)
		}
	}

	if len(matchingSessions) == 0 {
		fmt.Fprintf(os.Stderr, "[aflock] No sessions found matching projectPath: %s\n", workDir)
		return findModelFromMostRecentSession(projectDir)
	}

	// Find the most recently modified matching session using ACTUAL file mtime
	// (not the cached mtime in sessions-index.json which may be stale)
	var mostRecent SessionIndexEntry
	var mostRecentMtime int64
	for _, entry := range matchingSessions {
		info, err := os.Stat(entry.FullPath)
		if err != nil {
			continue
		}
		actualMtime := info.ModTime().UnixNano()
		if actualMtime > mostRecentMtime {
			mostRecentMtime = actualMtime
			mostRecent = entry
		}
	}

	if mostRecent.SessionID == "" {
		return findModelFromMostRecentSession(projectDir)
	}

	fmt.Fprintf(os.Stderr, "[aflock] Found active session: %s (projectPath: %s)\n",
		mostRecent.SessionID, mostRecent.ProjectPath)

	// Extract model from the session file
	return extractModelFromSession(mostRecent.FullPath)
}

// findModelFromMostRecentSession finds the model from the most recently modified session file.
// This is a fallback when sessions-index.json is not available.
func findModelFromMostRecentSession(projectDir string) (string, error) {
	fmt.Fprintf(os.Stderr, "[aflock] Falling back to most recent session in: %s\n", projectDir)

	entries, err := os.ReadDir(projectDir)
	if err != nil {
		return "", fmt.Errorf("read project dir: %w", err)
	}

	var mostRecent string
	var mostRecentTime int64

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().UnixNano() > mostRecentTime {
			mostRecentTime = info.ModTime().UnixNano()
			mostRecent = filepath.Join(projectDir, entry.Name())
		}
	}

	if mostRecent == "" {
		return "", fmt.Errorf("no session files found in %s", projectDir)
	}

	fmt.Fprintf(os.Stderr, "[aflock] Most recent session: %s\n", mostRecent)
	return extractModelFromSession(mostRecent)
}

// getProcessChain returns the chain of PIDs from the given pid up to init.
func getProcessChain(startPID int) []int {
	pids := []int{startPID}
	currentPID := startPID

	for currentPID > 1 {
		ppid, err := getParentPID(currentPID)
		if err != nil || ppid <= 1 {
			break
		}
		pids = append(pids, ppid)
		currentPID = ppid

		// Limit to 10 levels
		if len(pids) > 10 {
			break
		}
	}

	return pids
}

// getParentPID gets the parent PID of a process.
// Uses /proc on Linux, ps command on macOS.
func getParentPID(pid int) (int, error) {
	if runtime.GOOS == osLinux {
		return getParentPIDLinux(pid)
	}
	return getParentPIDMacOS(pid)
}

// getParentPIDLinux reads parent PID from /proc/<pid>/stat
func getParentPIDLinux(pid int) (int, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath) //nolint:gosec // G304: reading process stat file
	if err != nil {
		return 0, err
	}

	// Format: pid (comm) state ppid ...
	// The comm field can contain spaces and parentheses, so find the last ) first
	stat := string(data)
	lastParen := strings.LastIndex(stat, ")")
	if lastParen < 0 {
		return 0, fmt.Errorf("invalid stat format")
	}

	// Fields after ) are: state ppid ...
	fields := strings.Fields(stat[lastParen+1:])
	if len(fields) < 2 {
		return 0, fmt.Errorf("not enough fields in stat")
	}

	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, err
	}

	return ppid, nil
}

// getParentPIDMacOS uses ps command to get parent PID
func getParentPIDMacOS(pid int) (int, error) {
	cmd := exec.Command("ps", "-o", "ppid=", "-p", strconv.Itoa(pid)) //nolint:gosec // G204: subprocess from known tool paths
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	ppid, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		return 0, err
	}

	return ppid, nil
}

// findModelFromOpenFiles finds the Claude model from open session files.
// Uses /proc/pid/fd on Linux, lsof on macOS.
func findModelFromOpenFiles(pid int) (string, error) {
	if runtime.GOOS == osLinux {
		return findModelFromOpenFilesLinux(pid)
	}
	return findModelFromOpenFilesMacOS(pid)
}

// findModelFromOpenFilesLinux uses /proc/<pid>/fd to find open files
func findModelFromOpenFilesLinux(pid int) (string, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return "", fmt.Errorf("read fd dir: %w", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	claudeDir := filepath.Join(homeDir, ".claude", "projects")
	sessionPattern := regexp.MustCompile(`\.jsonl$`)

	for _, entry := range entries {
		// Resolve symlink to get actual file path
		fdPath := filepath.Join(fdDir, entry.Name())
		filePath, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}

		// Check if it's a Claude session file
		if !strings.HasPrefix(filePath, claudeDir) {
			continue
		}
		if !sessionPattern.MatchString(filePath) {
			continue
		}

		fmt.Fprintf(os.Stderr, "[aflock] Found session file: %s\n", filePath)

		// Try to extract model from session file
		model, err := extractModelFromSession(filePath)
		if err == nil && model != "" {
			fmt.Fprintf(os.Stderr, "[aflock] Discovered model from session: %s\n", model)
			return model, nil
		}
	}

	return "", fmt.Errorf("no model found in open files for pid %d", pid)
}

// findModelFromOpenFilesMacOS uses lsof to find open files
func findModelFromOpenFilesMacOS(pid int) (string, error) {
	// Use lsof to find open files
	cmd := exec.Command("lsof", "-p", strconv.Itoa(pid)) //nolint:gosec // G204: subprocess from known tool path
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("lsof failed: %w", err)
	}

	// Look for Claude session files (.jsonl in ~/.claude/projects/)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	claudeDir := filepath.Join(homeDir, ".claude", "projects")

	lines := strings.Split(string(output), "\n")
	sessionPattern := regexp.MustCompile(`\.jsonl$`)

	for _, line := range lines {
		// lsof output format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		filePath := fields[len(fields)-1]

		// Check if it's a Claude session file
		if !strings.HasPrefix(filePath, claudeDir) {
			continue
		}
		if !sessionPattern.MatchString(filePath) {
			continue
		}

		fmt.Fprintf(os.Stderr, "[aflock] Found session file: %s\n", filePath)

		// Try to extract model from session file
		model, err := extractModelFromSession(filePath)
		if err == nil && model != "" {
			fmt.Fprintf(os.Stderr, "[aflock] Discovered model from session: %s\n", model)
			return model, nil
		}
	}

	return "", fmt.Errorf("no model found in open files for pid %d", pid)
}

// extractModelFromSession extracts the model name from a Claude session file.
// Session files are JSONL with message objects containing a "model" field.
func extractModelFromSession(sessionPath string) (string, error) {
	file, err := os.Open(sessionPath) //nolint:gosec // G304: session file path from discovery
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	// Increase buffer for long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var lastModel string

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse JSONL line
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Check for message.model field (assistant messages)
		if message, ok := entry["message"].(map[string]interface{}); ok {
			if model, ok := message["model"].(string); ok && model != "" {
				lastModel = model
			}
		}

		// Also check top-level model field
		if model, ok := entry["model"].(string); ok && model != "" {
			lastModel = model
		}
	}

	if lastModel != "" {
		return lastModel, nil
	}

	return "", fmt.Errorf("no model found in session file")
}

// ProcessMetadata contains detailed process information for attestation.
type ProcessMetadata struct {
	AflockPID       int               `json:"aflockPid"`
	ParentPID       int               `json:"parentPid"`
	ClaudePID       int               `json:"claudePid,omitempty"`
	ProcessChain    []ProcessInfo     `json:"processChain"`
	WorkingDir      string            `json:"workingDir"`
	SessionID       string            `json:"sessionId,omitempty"`
	SessionPath     string            `json:"sessionPath,omitempty"`
	Model           string            `json:"model,omitempty"`
	DiscoveryMethod string            `json:"discoveryMethod"`
	UserID          int               `json:"userId"`
	Hostname        string            `json:"hostname"`
	Environment     map[string]string `json:"environment,omitempty"`
}

// ProcessInfo contains information about a single process in the chain.
type ProcessInfo struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid,omitempty"`
	Command    string `json:"command"`
	WorkingDir string `json:"workingDir,omitempty"`
	IsClaude   bool   `json:"isClaude,omitempty"`
}

// DiscoverFromMCPSocket discovers model and collects comprehensive process metadata.
// This is called when aflock is started as an MCP server on stdio or HTTP/SSE,
// where there is no socket peer credential to attest the connecting process.
// Identity is derived heuristically from the parent PID (os.Getppid()).
//
// For kernel-attested identity over a Unix-domain-socket transport, use
// DiscoverFromPID with the PID returned by SO_PEERCRED/LOCAL_PEERPID.
//
// No fallback to environment variables - proper attestation requires PID-based discovery.
//
//nolint:gocognit,gocyclo // MCP socket discovery requires complex process parsing
func DiscoverFromMCPSocket() (string, *ProcessMetadata, error) {
	return discoverFromPID(os.Getppid(), "pid_trace", nil)
}

// DiscoverFromPID discovers the agent model and collects process metadata
// starting from a kernel-attested peer PID (e.g. obtained via SO_PEERCRED on
// Linux or LOCAL_PEERPID on macOS for an accepted UDS connection). The
// resulting ProcessMetadata.DiscoveryMethod is set to "peercred" so callers
// and attestations can distinguish kernel-attested identity from the
// process-tree-walking heuristic used by DiscoverFromMCPSocket.
//
// Deprecated: prefer DiscoverFromPeer, which additionally records peer
// UID/GID and reads the peer's /proc/<pid>/environ rather than aflock's
// own environment.
func DiscoverFromPID(peerPID int) (string, *ProcessMetadata, error) {
	return discoverFromPID(peerPID, "peercred", nil)
}

// DiscoverFromPeer is the kernel-attested counterpart of DiscoverFromPID
// that uses peer-derived data — peer UID instead of os.Getuid(), peer's
// /proc/<pid>/environ instead of aflock's environment — to populate the
// returned ProcessMetadata. Use this when the caller has a full PeerInfo
// from SO_PEERCRED + IntrospectPeer; use DiscoverFromMCPSocket for the
// stdio/HTTP heuristic path where no peer credentials are available.
func DiscoverFromPeer(peer PeerInfo) (string, *ProcessMetadata, error) {
	return discoverFromPID(peer.PID, "peercred", &peer)
}

//nolint:gocognit,gocyclo // shared discovery logic mirrors the original DiscoverFromMCPSocket
func discoverFromPID(startPID int, method string, peer *PeerInfo) (string, *ProcessMetadata, error) {
	meta := &ProcessMetadata{
		AflockPID: os.Getpid(),
		ParentPID: startPID,
	}
	if peer != nil {
		// Kernel-attested peer UID — not aflock's UID. Differs when aflock
		// runs as a different user than the connecting agent (rare today,
		// but the trust boundary requires we never lie about it).
		meta.UserID = int(peer.UID)
	} else {
		meta.UserID = os.Getuid()
	}

	if hostname, err := os.Hostname(); err == nil {
		meta.Hostname = hostname
	}

	// Get working directory
	if cwd, err := os.Getwd(); err == nil {
		meta.WorkingDir = cwd
	}

	// Collect process chain information
	pids := getProcessChain(meta.ParentPID)
	for _, pid := range pids {
		pinfo := ProcessInfo{PID: pid}

		if cmd, err := getProcessCommand(pid); err == nil {
			pinfo.Command = cmd
			// Check if this is the Claude process
			if strings.Contains(cmd, "claude") && !strings.Contains(cmd, "/bin/zsh") {
				pinfo.IsClaude = true
				meta.ClaudePID = pid
			}
		}

		if ppid, err := getParentPID(pid); err == nil {
			pinfo.PPID = ppid
		}

		if workDir, err := getProcessWorkingDir(pid); err == nil {
			pinfo.WorkingDir = workDir
		}

		meta.ProcessChain = append(meta.ProcessChain, pinfo)
	}

	// Collect Claude-related environment variables. In peer mode, read the
	// peer's /proc/<pid>/environ so the attestation reflects the agent's
	// configuration, not aflock's. If peer.Environ is nil (macOS, where
	// reading another process's env is not supported), record an empty map
	// rather than falling back to aflock's environment — the whole point
	// of peer-cred mode is that aflock's state is untrusted for identity.
	// In heuristic mode (no peer), os.Environ() is acceptable because the
	// caller is aflock's own parent (stdio MCP transport).
	var rawEnv map[string]string
	switch {
	case peer != nil:
		rawEnv = peer.Environ // may be nil on macOS — that's fine, treat as empty
	default:
		rawEnv = make(map[string]string)
		for _, kv := range os.Environ() {
			if idx := strings.Index(kv, "="); idx > 0 {
				rawEnv[kv[:idx]] = kv[idx+1:]
			}
		}
	}

	meta.Environment = filterEnvAllowlist(rawEnv)

	// Discover model from process chain (no fallback)
	model, sessionID, sessionPath, err := discoverModelWithSessionFromPID(startPID)
	if err != nil {
		meta.DiscoveryMethod = "failed"
		return "", meta, err
	}

	meta.Model = model
	meta.SessionID = sessionID
	meta.SessionPath = sessionPath
	meta.DiscoveryMethod = method

	return model, meta, nil
}

// filterEnvAllowlist keeps only env vars relevant to attestation —
// CLAUDE_*, ANTHROPIC_*, SPIFFE_*, plus USER/HOME — and drops any whose
// key contains a sensitivity marker (KEY, TOKEN, SECRET, PASSWORD,
// CREDENTIAL) to prevent API-key leakage in attestations.
func filterEnvAllowlist(env map[string]string) map[string]string {
	out := make(map[string]string)
	sensitive := []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"}
	for key, value := range env {
		if !strings.HasPrefix(key, "CLAUDE_") &&
			!strings.HasPrefix(key, "ANTHROPIC_") &&
			!strings.HasPrefix(key, "SPIFFE_") &&
			key != "USER" && key != "HOME" {
			continue
		}
		upper := strings.ToUpper(key)
		drop := false
		for _, s := range sensitive {
			if strings.Contains(upper, s) {
				drop = true
				break
			}
		}
		if !drop {
			out[key] = value
		}
	}
	return out
}

// DiscoverModelWithSession discovers the model and returns session info,
// starting the process-chain walk from the current process's parent. Used
// by stdio/HTTP transports where there is no socket peer credential.
func DiscoverModelWithSession() (model, sessionID, sessionPath string, err error) {
	return discoverModelWithSessionFromPID(os.Getppid())
}

func discoverModelWithSessionFromPID(startPID int) (model, sessionID, sessionPath string, err error) {
	pids := getProcessChain(startPID)

	// Find Claude process and its working directory
	for _, pid := range pids {
		cmd, cmdErr := getProcessCommand(pid)
		if cmdErr != nil {
			continue
		}

		if !strings.Contains(cmd, "claude") || strings.Contains(cmd, "node") {
			continue
		}

		workDir, wdErr := getProcessWorkingDir(pid)
		if wdErr != nil {
			continue
		}

		// Find session from working directory
		model, sessionID, sessionPath, err = findModelAndSessionFromWorkingDir(workDir)
		if err == nil {
			return model, sessionID, sessionPath, nil
		}
	}

	return "", "", "", fmt.Errorf("could not discover model from process chain")
}

// FindTranscriptForWorkDir resolves the Claude session id and transcript
// JSONL path for a given working directory, without walking the process
// tree. The MCP server uses this (issue #72): it runs as a long-lived
// daemon whose parent is the shell, not claude, so the getppid-based
// DiscoverModelWithSession can't reach the claude process — but the
// workspace dir maps deterministically to ~/.claude/projects/<slug>.
func FindTranscriptForWorkDir(workDir string) (sessionID, transcriptPath string, err error) {
	_, sessionID, transcriptPath, err = findModelAndSessionFromWorkingDir(workDir)
	return sessionID, transcriptPath, err
}

// findModelAndSessionFromWorkingDir finds model and session info from working directory.
func findModelAndSessionFromWorkingDir(workDir string) (model, sessionID, sessionPath string, err error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", "", "", err
	}

	projectSlug := strings.ReplaceAll(workDir, "/", "-")
	projectDir := filepath.Join(homeDir, ".claude", "projects", projectSlug)
	indexPath := filepath.Join(projectDir, "sessions-index.json")

	indexData, err := os.ReadFile(indexPath) //nolint:gosec // G304: reading session index file
	if err != nil {
		// Fallback: scan .jsonl files directly when sessions-index.json is missing
		fmt.Fprintf(os.Stderr, "[aflock] No sessions-index.json, falling back to most recent .jsonl in: %s\n", projectDir)
		return findModelAndSessionFromDir(projectDir)
	}

	var index SessionIndex
	if err := json.Unmarshal(indexData, &index); err != nil {
		fmt.Fprintf(os.Stderr, "[aflock] Invalid sessions-index.json, falling back to most recent .jsonl\n")
		return findModelAndSessionFromDir(projectDir)
	}

	// Find matching sessions
	var mostRecentPath string
	var mostRecentID string
	var mostRecentMtime int64

	for _, entry := range index.Entries {
		if entry.ProjectPath == workDir ||
			strings.HasPrefix(workDir, entry.ProjectPath+"/") ||
			strings.HasPrefix(entry.ProjectPath, workDir+"/") {

			info, err := os.Stat(entry.FullPath)
			if err != nil {
				continue
			}
			if info.ModTime().UnixNano() > mostRecentMtime {
				mostRecentMtime = info.ModTime().UnixNano()
				mostRecentPath = entry.FullPath
				mostRecentID = entry.SessionID
			}
		}
	}

	if mostRecentPath == "" {
		// No matching sessions in index — fall back to scanning directory
		fmt.Fprintf(os.Stderr, "[aflock] No matching sessions in index, falling back to most recent .jsonl\n")
		return findModelAndSessionFromDir(projectDir)
	}

	model, err = extractModelFromSession(mostRecentPath)
	if err != nil {
		return "", "", "", err
	}

	return model, mostRecentID, mostRecentPath, nil
}

// findModelAndSessionFromDir scans a project directory for the most recent .jsonl session file.
// This is a fallback when sessions-index.json is missing or doesn't have matching entries.
func findModelAndSessionFromDir(projectDir string) (model, sessionID, sessionPath string, err error) {
	entries, err := os.ReadDir(projectDir)
	if err != nil {
		return "", "", "", fmt.Errorf("read project dir: %w", err)
	}

	var mostRecentPath string
	var mostRecentTime int64

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().UnixNano() > mostRecentTime {
			mostRecentTime = info.ModTime().UnixNano()
			mostRecentPath = filepath.Join(projectDir, entry.Name())
		}
	}

	if mostRecentPath == "" {
		return "", "", "", fmt.Errorf("no session files found in %s", projectDir)
	}

	fmt.Fprintf(os.Stderr, "[aflock] Most recent session file: %s\n", mostRecentPath)

	model, err = extractModelFromSession(mostRecentPath)
	if err != nil {
		return "", "", "", err
	}

	// Extract session ID from filename (UUID.jsonl)
	base := filepath.Base(mostRecentPath)
	sessionID = strings.TrimSuffix(base, ".jsonl")

	return model, sessionID, mostRecentPath, nil
}

// getProcessCommand gets the command line for a process.
func getProcessCommand(pid int) (string, error) {
	cmd := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pid)) //nolint:gosec // G204: subprocess from known tool path
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// TraceProcessInfo returns detailed information about a process and its ancestry.
//
//nolint:gocognit,gocyclo // process tracing requires complex system checks
func TraceProcessInfo(pid int) map[string]interface{} {
	info := make(map[string]interface{})
	info["pid"] = pid

	// Get command
	if cmd, err := getProcessCommand(pid); err == nil {
		info["command"] = cmd
	}

	// Get parent PID
	if ppid, err := getParentPID(pid); err == nil {
		info["ppid"] = ppid
	}

	// Get open files count
	if files, err := getOpenFiles(pid); err == nil { //nolint:nestif
		info["open_files_count"] = len(files)

		// Filter for interesting files
		var sessionFiles []string
		var configFiles []string
		for _, f := range files {
			if strings.Contains(f, ".claude") && strings.HasSuffix(f, ".jsonl") {
				sessionFiles = append(sessionFiles, f)
			}
			if strings.Contains(f, ".claude") && strings.HasSuffix(f, ".json") {
				configFiles = append(configFiles, f)
			}
		}
		if len(sessionFiles) > 0 {
			info["session_files"] = sessionFiles
		}
		if len(configFiles) > 0 {
			info["config_files"] = configFiles
		}
	}

	// Get environment variables (filter out sensitive keys like API keys)
	if env, err := getProcessEnvironment(pid); err == nil { //nolint:nestif
		claudeEnv := make(map[string]string)
		for k, v := range env {
			if strings.HasPrefix(k, "CLAUDE_") || strings.HasPrefix(k, "ANTHROPIC_") {
				// Skip keys that likely contain secrets
				upperK := strings.ToUpper(k)
				if strings.Contains(upperK, "KEY") ||
					strings.Contains(upperK, "TOKEN") ||
					strings.Contains(upperK, "SECRET") ||
					strings.Contains(upperK, "PASSWORD") {
					claudeEnv[k] = "[REDACTED]"
				} else {
					claudeEnv[k] = v
				}
			}
		}
		if len(claudeEnv) > 0 {
			info["claude_env"] = claudeEnv
		}
	}

	return info
}

// getOpenFiles returns a list of open file paths for a process.
func getOpenFiles(pid int) ([]string, error) {
	if runtime.GOOS == osLinux {
		return getOpenFilesLinux(pid)
	}
	return getOpenFilesMacOS(pid)
}

// getOpenFilesLinux uses /proc/<pid>/fd
func getOpenFilesLinux(pid int) ([]string, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		fdPath := filepath.Join(fdDir, entry.Name())
		if target, err := os.Readlink(fdPath); err == nil {
			files = append(files, target)
		}
	}

	return files, nil
}

// getOpenFilesMacOS uses lsof
func getOpenFilesMacOS(pid int) ([]string, error) {
	cmd := exec.Command("lsof", "-p", strconv.Itoa(pid), "-Fn") //nolint:gosec // G204: subprocess from known tool path
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var files []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "n") && !strings.HasPrefix(line, "n->") {
			files = append(files, line[1:])
		}
	}

	return files, nil
}

// getProcessEnvironment gets environment variables for a process.
func getProcessEnvironment(pid int) (map[string]string, error) {
	if runtime.GOOS == osLinux {
		return getProcessEnvironmentLinux(pid)
	}
	return getProcessEnvironmentMacOS(pid)
}

// getProcessEnvironmentLinux reads from /proc/<pid>/environ
func getProcessEnvironmentLinux(pid int) (map[string]string, error) {
	environPath := fmt.Sprintf("/proc/%d/environ", pid)
	data, err := os.ReadFile(environPath) //nolint:gosec // G304: reading process environ file
	if err != nil {
		return nil, err
	}

	env := make(map[string]string)
	// environ is null-separated key=value pairs
	for _, envVar := range strings.Split(string(data), "\x00") {
		if idx := strings.Index(envVar, "="); idx > 0 {
			key := envVar[:idx]
			value := envVar[idx+1:]
			env[key] = value
		}
	}

	return env, nil
}

// getProcessEnvironmentMacOS uses ps command (limited access)
func getProcessEnvironmentMacOS(pid int) (map[string]string, error) {
	// macOS: use ps to get environment (limited)
	cmd := exec.Command("ps", "-E", "-p", strconv.Itoa(pid), "-o", "command=") //nolint:gosec // G204: subprocess from known tool path
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	env := make(map[string]string)
	// Parse environment from the command output
	// This is limited on macOS without root access

	// Try to extract key=value pairs from command
	for _, part := range strings.Fields(string(output)) {
		if idx := strings.Index(part, "="); idx > 0 {
			key := part[:idx]
			value := part[idx+1:]
			if strings.HasPrefix(key, "CLAUDE_") || strings.HasPrefix(key, "ANTHROPIC_") {
				env[key] = value
			}
		}
	}

	return env, nil
}
