package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aflock-ai/aflock/internal/attestation"
	"github.com/aflock-ai/aflock/internal/identity"
	"github.com/aflock-ai/aflock/internal/policy"
	"github.com/aflock-ai/aflock/internal/state"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

// SimulateResult extends Result with attestation info.
type SimulateResult struct {
	Result
	AttestationFile string // path to .intoto.json if created
}

// SimulateReport extends Report with simulator-specific output.
type SimulateReport struct {
	Report
	SessionID       string
	SessionDir      string
	SimulateResults []SimulateResult
	AttestCount     int
	LimitExceeded   bool
	LimitMessage    string
	StopBlocked     bool
	StopMessage     string
}

// Simulate replays a session through the full hook lifecycle, producing
// real aflock artifacts: session state, attestations, and metrics.
func Simulate(session *Session, pol *aflock.Policy, policyPath string) (*SimulateReport, error) {
	projectRoot := filepath.Dir(policyPath)
	evaluator := policy.NewEvaluator(pol, projectRoot)
	stateManager := state.NewManager("")

	// Generate a unique session ID for this replay
	sessionID := fmt.Sprintf("replay-%d", time.Now().UnixNano())

	// ── Phase 1: SessionStart ──
	sessionState := stateManager.Initialize(sessionID, pol, policyPath)

	// Create a synthetic agent identity from the session's model
	agentIdentity := &identity.AgentIdentity{
		Model:        session.Model,
		ModelVersion: parseModelVersion(session.Model),
	}
	agentIdentity.Binary = &identity.BinaryIdentity{
		Name:    "replay-simulator",
		Version: "0.1.0",
	}
	agentIdentity.Environment = &identity.EnvironmentIdentity{
		Type: "replay",
	}
	agentIdentity.DeriveIdentity()

	if err := stateManager.Save(sessionState); err != nil {
		return nil, fmt.Errorf("save initial session state: %w", err)
	}

	report := &SimulateReport{
		Report: Report{
			Session:    session,
			PolicyName: pol.Name,
			PolicyPath: policyPath,
		},
		SessionID:  sessionID,
		SessionDir: stateManager.SessionDir(sessionID),
	}

	// Initialize attestation signer (try SPIRE, fall back gracefully)
	signer := attestation.NewSigner("")
	signerReady := false
	if err := signer.Initialize(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "[replay] Warning: attestation signing unavailable: %v\n", err)
	} else {
		signerReady = true
		defer signer.Close() //nolint:errcheck
	}

	// ── Phase 2: Replay each action (PreToolUse + PostToolUse) ──
	for _, action := range session.Actions {
		// PreToolUse — evaluate policy
		decision, reason := evaluator.EvaluatePreToolUse(action.Tool, action.RawInput)

		result := SimulateResult{
			Result: Result{
				Action:   action,
				Decision: decision,
				Reason:   reason,
			},
		}

		switch decision {
		case aflock.DecisionAllow:
			report.AllowCount++
		case aflock.DecisionDeny:
			report.DenyCount++
		case aflock.DecisionAsk:
			report.AskCount++
		}

		// Record action in session state
		stateManager.RecordAction(sessionState, aflock.ActionRecord{
			Timestamp: time.Now(),
			ToolName:  action.Tool,
			ToolUseID: action.ID,
			ToolInput: action.RawInput,
			Decision:  string(decision),
			Reason:    reason,
		})

		// PostToolUse — track file access
		if isFileOperation(action.Tool) {
			if fp, ok := action.Input["file_path"].(string); ok {
				stateManager.TrackFile(sessionState, action.Tool, fp)
			}
		}

		// PostToolUse — check fail-fast limits
		if pol.Limits != nil {
			exceeded, limitName, msg := evaluator.CheckLimits(sessionState.Metrics, "fail-fast")
			if exceeded && !report.LimitExceeded {
				report.LimitExceeded = true
				report.LimitMessage = fmt.Sprintf("%s: %s", limitName, msg)
			}
		}

		// PostToolUse — create and store attestation
		if signerReady {
			attestFile, err := createReplayAttestation(
				signer, stateManager, sessionState,
				action, string(decision), agentIdentity,
			)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[replay] Warning: attestation for action #%d failed: %v\n", action.Index, err)
			} else if attestFile != "" {
				result.AttestationFile = attestFile
				report.AttestCount++
			}
		}

		// Save state after each action
		if err := stateManager.Save(sessionState); err != nil {
			fmt.Fprintf(os.Stderr, "[replay] Warning: save state failed: %v\n", err)
		}

		report.SimulateResults = append(report.SimulateResults, result)
		report.Results = append(report.Results, result.Result)
	}

	// ── Phase 3: Stop — check requiredAttestations ──
	if len(pol.RequiredAttestations) > 0 {
		var missing []string
		for _, required := range pol.RequiredAttestations {
			if !hasAttestation(report.SimulateResults, required) {
				missing = append(missing, required)
			}
		}
		if len(missing) > 0 {
			report.StopBlocked = true
			report.StopMessage = fmt.Sprintf("missing required attestations: %v", missing)
		}
	}

	// ── Phase 4: SessionEnd — post-hoc limit check ──
	if pol.Limits != nil {
		exceeded, limitName, msg := evaluator.CheckLimits(sessionState.Metrics, "post-hoc")
		if exceeded && !report.LimitExceeded {
			report.LimitExceeded = true
			report.LimitMessage = fmt.Sprintf("post-hoc: %s: %s", limitName, msg)
		}
	}

	// Final save
	if err := stateManager.Save(sessionState); err != nil {
		fmt.Fprintf(os.Stderr, "[replay] Warning: final save failed: %v\n", err)
	}

	return report, nil
}

// createReplayAttestation creates a signed attestation for a replayed action.
func createReplayAttestation(
	signer *attestation.Signer,
	stateManager *state.Manager,
	sessionState *aflock.SessionState,
	action Action,
	decision string,
	agentIdentity *identity.AgentIdentity,
) (string, error) {
	toolUseID := action.ID
	if toolUseID == "" {
		toolUseID = fmt.Sprintf("replay-%d", action.Index)
	}

	record := aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  action.Tool,
		ToolUseID: toolUseID,
		ToolInput: action.RawInput,
		Decision:  decision,
	}

	envelope, err := signer.CreateActionAttestation(
		context.Background(),
		record,
		sessionState.SessionID,
		sessionState.Metrics,
		agentIdentity,
	)
	if err != nil {
		return "", fmt.Errorf("create attestation: %w", err)
	}

	// Store to disk
	attestDir := stateManager.AttestationsDir(sessionState.SessionID)
	if err := os.MkdirAll(attestDir, 0750); err != nil {
		return "", fmt.Errorf("create attestation dir: %w", err)
	}

	prefix := toolUseID
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	filename := fmt.Sprintf("%03d-%s-%s.intoto.json", action.Index, action.Tool, prefix)
	path := filepath.Join(attestDir, filename)

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal attestation: %w", err)
	}

	if err := os.WriteFile(path, data, 0640); err != nil {
		return "", fmt.Errorf("write attestation: %w", err)
	}

	return path, nil
}

// hasAttestation checks if a required attestation was produced.
func hasAttestation(results []SimulateResult, name string) bool {
	for _, r := range results {
		if strings.EqualFold(r.Action.Tool, name) && r.AttestationFile != "" {
			return true
		}
	}
	return false
}

func isFileOperation(toolName string) bool {
	switch toolName {
	case "Read", "Write", "Edit", "Glob", "Grep", "NotebookEdit":
		return true
	}
	return false
}

// parseModelVersion extracts version from model name.
func parseModelVersion(model string) string {
	parts := strings.Split(model, "-")
	if len(parts) >= 4 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1] + ".0"
	}
	return "0.0.0"
}

// FormatSimulateText renders the simulate report.
func (r *SimulateReport) FormatSimulateText() string {
	var b strings.Builder

	b.WriteString(r.Report.FormatText())

	b.WriteString("\n")
	b.WriteString(strings.Repeat("━", 60) + "\n")
	b.WriteString("SIMULATION OUTPUT\n\n")

	fmt.Fprintf(&b, "Session ID:   %s\n", r.SessionID)
	fmt.Fprintf(&b, "Session Dir:  %s\n", r.SessionDir)
	fmt.Fprintf(&b, "Attestations: %d signed\n", r.AttestCount)

	if r.LimitExceeded {
		fmt.Fprintf(&b, "Limits:       EXCEEDED — %s\n", r.LimitMessage)
	} else {
		b.WriteString("Limits:       within bounds\n")
	}

	if r.StopBlocked {
		fmt.Fprintf(&b, "Stop check:   BLOCKED — %s\n", r.StopMessage)
	} else {
		b.WriteString("Stop check:   passed\n")
	}

	if r.AttestCount > 0 {
		b.WriteString("\nAttestation files:\n")
		for _, res := range r.SimulateResults {
			if res.AttestationFile != "" {
				fmt.Fprintf(&b, "  %s\n", filepath.Base(res.AttestationFile))
			}
		}
	}

	fmt.Fprintf(&b, "\nInspect:  ls %s/\n", r.SessionDir)
	fmt.Fprintf(&b, "Verify:   aflock verify --session %s\n", r.SessionID)

	return b.String()
}
