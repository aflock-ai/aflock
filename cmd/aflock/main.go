// Package main implements the aflock CLI for Claude Code plugin integration.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/aflock-ai/aflock/internal/hooks"
	"github.com/aflock-ai/aflock/internal/mcp"
	"github.com/aflock-ai/aflock/internal/plan"
	"github.com/aflock-ai/aflock/internal/policy"
	"github.com/aflock-ai/aflock/internal/replay"
	"github.com/aflock-ai/aflock/internal/sandbox"
	"github.com/aflock-ai/aflock/internal/verify"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

var (
	version = "0.1.0"
)

var rootCmd = &cobra.Command{
	Use:   "aflock",
	Short: "Cryptographically signed policy enforcement for AI agents",
	Long: `aflock enforces .aflock policies on AI agents like Claude Code.

It integrates via Claude Code's hooks system to:
- Evaluate policy before tool execution (PreToolUse)
- Record attestations after tool execution (PostToolUse)
- Track cumulative metrics (turns, spend, tokens)
- Verify constraints at session end`,
	Version: version,
}

var hookCmd = &cobra.Command{
	Use:   "hook <event>",
	Short: "Handle a Claude Code hook event",
	Long: `Handle a Claude Code hook event by reading JSON from stdin and writing JSON to stdout.

Supported events:
  SessionStart      - Initialize session with policy
  PreToolUse        - Evaluate tool call against policy
  PostToolUse       - Record attestation
  PermissionRequest - Auto-approve/deny
  UserPromptSubmit  - Validate prompt
  Stop              - Check completion
  SubagentStop      - Check sublayout
  SessionEnd        - Finalize and verify`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		handler := hooks.NewHandler()
		if err := handler.Handle(args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "Hook error: %v\n", err)
			os.Exit(1)
		}
	},
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a new .aflock policy template",
	Run: func(cmd *cobra.Command, args []string) {
		template := `{
  "version": "1.0",
  "name": "my-policy",

  "limits": {
    "maxSpendUSD": { "value": 10.00, "enforcement": "fail-fast" },
    "maxTurns": { "value": 50, "enforcement": "post-hoc" }
  },

  "tools": {
    "allow": ["Read", "Edit", "Write", "Glob", "Grep", "Bash", "LSP"],
    "deny": ["Task"],
    "requireApproval": ["Bash:rm *", "Bash:git push"]
  },

  "files": {
    "allow": ["src/**", "tests/**"],
    "deny": ["**/.env", "**/secrets/**"],
    "readOnly": ["package.json", "go.mod"]
  }
}
`
		if err := os.WriteFile(".aflock", []byte(template), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create .aflock: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Created .aflock policy template")
	},
}

var verifyPolicyPath string
var verifyAttestDir string
var verifyTreeHash string
var verifySessionID string
var verifySkipAI bool

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify step attestations against policy",
	Long: `Verify attestations against a policy.

Supports two verification modes:
  - Step-based: Verify step attestations for a git tree hash (default)
  - Session-based: Verify a session's compliance with policy constraints

Examples:
  aflock verify --policy .aflock                     # Verify steps for current git HEAD
  aflock verify --policy .aflock --tree-hash abc123  # Verify specific tree hash
  aflock verify --session <session-id>               # Verify a session (Phase 2-4)
  aflock verify -p policy.json -a ./attestations     # Custom attestation directory`,
	Run: func(cmd *cobra.Command, args []string) { //nolint:gocyclo // verify command handles two modes
		// Session-based verification mode
		if verifySessionID != "" {
			verifier := verify.NewVerifier()
			verifier.SkipAI = verifySkipAI
			result, err := verifier.VerifySession(verifySessionID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Session verification failed: %v\n", err)
				os.Exit(1)
			}
			output, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(output))
			if !result.Success {
				os.Exit(1)
			}
			return
		}

		// Step-based verification mode (default)
		if verifyPolicyPath == "" {
			// Try to find policy in current directory
			cwd, _ := os.Getwd()
			pol, path, err := policy.Load(cwd)
			if err != nil {
				fmt.Fprintf(os.Stderr, "No policy specified and none found in current directory.\n")
				fmt.Fprintf(os.Stderr, "Use --policy to specify a policy file.\n")
				os.Exit(1)
			}
			verifyPolicyPath = path
			_ = pol // Will reload below
		}

		pol, _, err := policy.Load(verifyPolicyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
			os.Exit(1)
		}

		// Default attestation directory
		if verifyAttestDir == "" {
			homeDir, _ := os.UserHomeDir()
			verifyAttestDir = filepath.Join(homeDir, ".aflock", "attestations")
		}

		verifier := verify.NewVerifier()
		var result *verify.StepsResult

		if verifyTreeHash != "" {
			result, err = verifier.VerifySteps(pol, verifyAttestDir, verifyTreeHash)
		} else {
			result, err = verifier.VerifyTreeHash(pol, verifyAttestDir)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
			os.Exit(1)
		}

		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))

		if !result.Success {
			os.Exit(1)
		}
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current session status",
	Run: func(cmd *cobra.Command, args []string) {
		verifier := verify.NewVerifier()
		sessions, err := verifier.ListSessions()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list sessions: %v\n", err)
			os.Exit(1)
		}

		if len(sessions) == 0 {
			fmt.Println("No active sessions found")
			return
		}

		fmt.Printf("Found %d session(s):\n\n", len(sessions))
		for _, s := range sessions {
			fmt.Printf("  Session: %s\n", s.SessionID)
			fmt.Printf("  Policy:  %s\n", s.PolicyName)
			fmt.Printf("  Started: %s\n", s.StartedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Turns:   %d\n", s.Turns)
			fmt.Printf("  Tools:   %d\n", s.ToolCalls)
			fmt.Println()
		}
	},
}

var (
	signOutputPath string
	signKeyPath    string
)

var signCmd = &cobra.Command{
	Use:   "sign <policy.aflock>",
	Short: "Sign a policy file (Sigstore keyless by default; --key for raw PEM)",
	Long: `Sign a policy file as a DSSE envelope.

Two signer paths, picked by flags / env:

  Sigstore keyless (default):
    Fulcio issues an ephemeral cert bound to the caller's OIDC identity, then
    aflock bundles an RFC 3161 timestamp so the signature survives the
    ~10-min cert validity window. Requires network at sign time.
    OIDC sources: GITHUB_ACTIONS=true | $FULCIO_TOKEN | $FULCIO_TOKEN_PATH |
                  $FULCIO_OIDC_ISSUER (interactive browser)

  Raw key (--key <pem> or $AFLOCK_SIGNING_KEY):
    PEM-encoded ECDSA, RSA, or Ed25519 private key. Operator manages the key.
    No TSA needed (raw keys don't expire), no network needed.

The verifier picks which path to take by reading aflock-trust.json — see
docs/concepts/policies.md#signing-and-trust.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		policyPath := args[0]

		policyData, err := os.ReadFile(policyPath) //nolint:gosec // G304: policy file path from CLI arg
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read policy: %v\n", err)
			os.Exit(1)
		}

		var policyJSON json.RawMessage
		if err := json.Unmarshal(policyData, &policyJSON); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid policy JSON: %v\n", err)
			os.Exit(1)
		}

		keyPath := signKeyPath
		if keyPath == "" {
			keyPath = os.Getenv("AFLOCK_SIGNING_KEY")
		}

		var envelopeJSON []byte
		if keyPath != "" {
			envelopeJSON, err = policy.SignWithKey(cmd.Context(), keyPath, policyData)
		} else {
			envelopeJSON, err = policy.SignWithFulcio(cmd.Context(), policyData)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Sign failed: %v\n", err)
			os.Exit(1)
		}

		outputPath := signOutputPath
		if outputPath == "" {
			outputPath = policyPath + ".signed"
		}

		if outputPath == "-" {
			fmt.Println(string(envelopeJSON))
		} else {
			if err := os.WriteFile(outputPath, envelopeJSON, 0600); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write signed policy: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Signed policy written to %s\n", outputPath)
		}
	},
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Inspect, sign, and verify .aflock policies",
}

var policyVerifyCmd = &cobra.Command{
	Use:   "verify <policy.aflock.signed>",
	Short: "Verify a signed policy against the configured trust root",
	Long: `Verify a DSSE-signed .aflock policy.

Loads the trust config from $AFLOCK_TRUST_CONFIG, <policy_dir>/aflock-trust.json,
or ~/.aflock/trust.json (first hit wins) and checks the embedded Fulcio cert
against the declared issuer + subjectPattern.

Exits 0 if verification passed, 1 otherwise. Prints the verified identity to
stdout on success.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pol, _, err := policy.Load(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
			os.Exit(1)
		}
		if pol.SignatureInfo == nil {
			fmt.Fprintf(os.Stderr, "Policy loaded but no signature info — not a signed envelope?\n")
			os.Exit(1)
		}
		out, err := json.MarshalIndent(pol.SignatureInfo, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Marshal signature info: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(out))
	},
}

// exec command flags
var (
	execPolicyPath string
	execStrict     bool
)

var execCmd = &cobra.Command{
	Use:   "exec [flags] -- <command> [args...]",
	Short: "Run an agent under a kernel-enforced sandbox derived from the policy",
	Long: `Launch an agent (e.g. claude) inside a kernel sandbox derived from the
.aflock policy. Kernel sandboxes are inherited by EVERY descendant process
and cannot be dropped or widened by children — a subagent five levels deep
is exactly as constrained as the agent itself (issue #100).

What is enforced:
  - the policy file, its signed variant, aflock-trust.json, and pinned
    AgentCards are write-protected for the whole process tree;
  - on macOS (Seatbelt), files.deny globs are also unreadable at any depth;
  - on Linux (Landlock, kernel 5.13+), write access is granted only to the
    files.allow prefixes plus runtime dirs (state, transcripts, tmp).

This complements hook enforcement — hooks still see, decide, and attest
every tool call; the kernel guarantees what the hooks never saw also could
not touch the protected surface.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		searchPath := execPolicyPath
		if searchPath == "" {
			cwd, err := os.Getwd()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Getwd: %v\n", err)
				os.Exit(1)
			}
			searchPath = cwd
		}
		pol, policyPath, err := policy.Load(searchPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Load policy: %v\n", err)
			os.Exit(1)
		}
		plan, err := sandbox.BuildPlan(pol, policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Build sandbox plan: %v\n", err)
			os.Exit(1)
		}
		plan.Strict = execStrict
		if !sandbox.Available() {
			if execStrict {
				fmt.Fprintf(os.Stderr, "[aflock] Kernel sandbox unavailable and --strict set — refusing to launch\n")
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "[aflock] Warning: kernel sandbox unavailable on this platform — launching without it\n")
		}
		fmt.Fprintf(os.Stderr, "[aflock] Kernel sandbox: %d protected file(s), %d deny glob(s)\n",
			len(plan.ProtectedFiles), len(plan.DenyReadGlobs))
		for _, note := range sandbox.GapNotes(plan) {
			fmt.Fprintf(os.Stderr, "[aflock] Sandbox gap: %s\n", note)
		}
		if err := sandbox.Exec(plan, args); err != nil {
			fmt.Fprintf(os.Stderr, "Exec under sandbox: %v\n", err)
			os.Exit(1)
		}
	},
}

// plan-to-policy command flags
var (
	planPath       string
	planOutput     string
	planMerge      bool
	planInferFiles bool
	planLimits     bool
	planModel      string
	planList       bool
)

var planToPolicyCmd = &cobra.Command{
	Use:   "plan-to-policy",
	Short: "Convert a Claude plan into an .aflock policy",
	Long: `Convert a Claude plan markdown file into an .aflock policy with steps and AI evaluators.

This implements spec-driven development: define acceptance criteria BEFORE implementation,
then verify the AI agent's work against those criteria using attestations.

The plan file is parsed for:
  - Deterministic steps (lint, test, build) with commands
  - UAT steps with AI evaluator prompts (PASS/FAIL criteria)
  - File paths (used to infer files.allow rules)
  - Acceptance criteria (auto-converted to UAT steps if no explicit UAT steps found)

Examples:
  # List available plans
  aflock plan-to-policy --list

  # Convert a plan to policy
  aflock plan-to-policy --plan ~/.claude/plans/my-plan.md

  # Output to specific file with limits
  aflock plan-to-policy --plan plan.md -o policies/feature.aflock --limits

  # Merge into existing policy
  aflock plan-to-policy --plan plan.md --merge

  # Infer file rules from plan
  aflock plan-to-policy --plan plan.md --infer-files`,
	Run: func(cmd *cobra.Command, args []string) {
		if planList {
			sources, err := plan.ListPlans()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to list plans: %v\n", err)
				os.Exit(1)
			}
			if len(sources) == 0 {
				fmt.Println("No plans found.")
				fmt.Println("  Checked: .claude/plans/ (project) and ~/.claude/plans/ (global)")
				return
			}
			total := 0
			for _, s := range sources {
				total += len(s.Plans)
			}
			fmt.Printf("Available plans (%d):\n", total)
			for _, s := range sources {
				fmt.Printf("\n  [%s] %s\n", s.Label, s.Dir)
				for _, p := range s.Plans {
					fmt.Printf("    %s\n", filepath.Base(p))
				}
			}
			return
		}

		if planPath == "" {
			fmt.Fprintln(os.Stderr, "Error: --plan is required (path to Claude plan markdown file)")
			fmt.Fprintln(os.Stderr, "Use --list to see available plans")
			os.Exit(1)
		}

		// Parse the plan
		parsed, err := plan.ParseFile(planPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse plan: %v\n", err)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "Parsed plan: %s\n", parsed.Name)
		fmt.Fprintf(os.Stderr, "  Deterministic steps: %d\n", len(parsed.DeterministicSteps))
		fmt.Fprintf(os.Stderr, "  UAT steps:           %d\n", len(parsed.UATSteps))
		fmt.Fprintf(os.Stderr, "  Files referenced:    %d\n", len(parsed.FilesModified))

		// Build options
		opts := plan.GenerateOptions{
			OutputPath:     planOutput,
			DefaultModel:   planModel,
			InferFileRules: planInferFiles,
			DefaultLimits:  planLimits,
		}

		// Merge with existing policy if requested
		if planMerge {
			// Try loading from the output path first, then fall back to CWD
			var mergePolicy *aflock.Policy
			if _, err := os.Stat(planOutput); err == nil {
				data, err := os.ReadFile(planOutput)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: --merge: could not read %s: %v\n", planOutput, err)
				} else {
					var pol aflock.Policy
					if err := json.Unmarshal(data, &pol); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: --merge: could not parse %s: %v\n", planOutput, err)
					} else {
						mergePolicy = &pol
					}
				}
			}
			if mergePolicy == nil {
				cwd, _ := os.Getwd()
				p, _, err := policy.Load(cwd)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: --merge specified but no existing policy found: %v\n", err)
				} else {
					mergePolicy = p
				}
			}
			if mergePolicy != nil {
				opts.MergeWith = mergePolicy
				fmt.Fprintln(os.Stderr, "  Merging with existing policy")
			}
		}

		// Generate and write
		outputPath, err := plan.WritePolicy(parsed, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate policy: %v\n", err)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "\nPolicy written to: %s\n", outputPath)
		fmt.Fprintln(os.Stderr, "\nNext steps:")
		fmt.Fprintf(os.Stderr, "  1. Review the policy:  cat %s\n", outputPath)
		fmt.Fprintf(os.Stderr, "  2. Sign the policy:    aflock sign %s\n", outputPath)
		fmt.Fprintln(os.Stderr, "  3. Implement the feature with Claude")
		fmt.Fprintf(os.Stderr, "  4. Verify attestations: aflock verify --policy %s\n", outputPath)
	},
}

var replaySessionPath string
var replayPolicyPath string
var replayFormat string
var replaySimulate bool

var replayCmd = &cobra.Command{
	Use:   "replay",
	Short: "Replay a Claude session against an aflock policy",
	Long: `Replay a recorded Claude Code session (.jsonl) against an aflock policy.

Parses every tool call from the session and evaluates it against the policy
deterministically. Shows which actions would be allowed, denied, or require
approval.

Examples:
  aflock replay --session ~/.claude/projects/.../session.jsonl --policy .aflock
  aflock replay --session session.jsonl --policy strict.aflock --format json
  aflock replay --session session.jsonl --policy .aflock --simulate`,
	Run: func(cmd *cobra.Command, args []string) {
		if replaySessionPath == "" {
			fmt.Fprintln(os.Stderr, "Error: --session is required")
			fmt.Fprintln(os.Stderr, "Usage: aflock replay --session <session.jsonl> --policy <policy.aflock>")
			os.Exit(1)
		}

		// Parse session
		session, err := replay.ParseSession(replaySessionPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing session: %v\n", err)
			os.Exit(1)
		}

		if len(session.Actions) == 0 {
			fmt.Fprintln(os.Stderr, "No tool calls found in session file.")
			os.Exit(0)
		}

		// Load policy
		polPath := replayPolicyPath
		if polPath == "" {
			cwd, _ := os.Getwd()
			polPath = cwd
		}

		pol, resolvedPath, err := policy.Load(polPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading policy: %v\n", err)
			os.Exit(1)
		}

		// Simulate mode: full hook lifecycle with attestations
		if replaySimulate {
			simReport, err := replay.Simulate(session, pol, resolvedPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error running simulation: %v\n", err)
				os.Exit(1)
			}

			switch replayFormat {
			case "json":
				output, err := simReport.FormatJSON()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
					os.Exit(1)
				}
				fmt.Println(output)
			default:
				fmt.Print(simReport.FormatSimulateText())
			}

			if simReport.DenyCount > 0 {
				os.Exit(1)
			}
			return
		}

		// Validator mode: report only
		report := replay.Run(session, pol, resolvedPath)

		switch replayFormat {
		case "json":
			output, err := report.FormatJSON()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(output)
		default:
			fmt.Print(report.FormatText())
		}

		if report.DenyCount > 0 {
			os.Exit(1)
		}
	},
}

var servePolicyPath string
var serveHTTPPort int
var serveUnixSocket string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the aflock MCP server",
	Long: `Start the aflock MCP server on stdio, HTTP, or Unix-domain socket.

The MCP server provides tools for AI agents with policy enforcement:
- get_identity: Get the agent's derived identity
- get_policy: Get the loaded .aflock policy
- check_tool: Check if a tool call would be allowed
- bash: Execute commands with policy enforcement
- read_file: Read files with policy enforcement
- write_file: Write files with policy enforcement
- get_session: Get current session metrics

For stdio (Claude Code):
{
  "mcpServers": {
    "aflock": {
      "command": "aflock",
      "args": ["serve"]
    }
  }
}

For HTTP (OpenClaw via mcporter):
  aflock serve --http 8787 --policy .aflock
  mcporter config add aflock http://localhost:8787/sse

For Unix-domain socket (kernel-attested peer-cred identity, issue #63):
  aflock serve --unix /tmp/aflock.sock --policy .aflock`,
	Run: func(cmd *cobra.Command, args []string) {
		server := mcp.NewServer()
		var err error
		switch {
		case serveUnixSocket != "":
			err = server.ServeUnix(servePolicyPath, serveUnixSocket)
		case serveHTTPPort > 0:
			err = server.ServeHTTP(servePolicyPath, serveHTTPPort)
		default:
			err = server.Serve(servePolicyPath)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
			os.Exit(1)
		}
	},
}

var hookFlag string

func init() {
	rootCmd.AddCommand(hookCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policyVerifyCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(planToPolicyCmd)
	rootCmd.AddCommand(replayCmd)
	rootCmd.AddCommand(execCmd)

	// Add --hook flag as alternative to hook subcommand for backwards compatibility
	rootCmd.Flags().StringVar(&hookFlag, "hook", "", "Hook event to handle (alternative to 'hook' subcommand)")

	// Exec command flags
	execCmd.Flags().StringVarP(&execPolicyPath, "policy", "p", "", "Path to .aflock policy (default: discover from cwd)")
	execCmd.Flags().BoolVar(&execStrict, "strict", false, "Fail instead of degrading when the kernel sandbox is unavailable")

	// Verify command flags
	verifyCmd.Flags().StringVarP(&verifyPolicyPath, "policy", "p", "", "Path to .aflock policy file (enables step-based verification)")
	verifyCmd.Flags().StringVarP(&verifyAttestDir, "attestations", "a", "", "Attestations directory (default: ~/.aflock/attestations)")
	verifyCmd.Flags().StringVar(&verifyTreeHash, "tree-hash", "", "Git tree hash to verify (default: current HEAD)")
	verifyCmd.Flags().StringVar(&verifySessionID, "session", "", "Session ID to verify (session-based verification mode)")
	verifyCmd.Flags().BoolVar(&verifySkipAI, "skip-ai", false, "Skip Phase 5 (AI Evaluation) — saves cost, no network needed")

	// Sign command flags
	signCmd.Flags().StringVarP(&signOutputPath, "output", "o", "", "Output path for signed envelope (default: <input>.signed, use - for stdout)")
	signCmd.Flags().StringVarP(&signKeyPath, "key", "k", "", "Path to PEM-encoded private key (ECDSA / RSA / Ed25519). Falls back to $AFLOCK_SIGNING_KEY. When unset, signs via Sigstore Fulcio.")

	// Plan-to-policy command flags
	planToPolicyCmd.Flags().StringVar(&planPath, "plan", "", "Path to Claude plan markdown file (required)")
	planToPolicyCmd.Flags().StringVarP(&planOutput, "output", "o", ".aflock", "Output path for generated policy")
	planToPolicyCmd.Flags().BoolVar(&planMerge, "merge", false, "Merge steps into existing .aflock policy")
	planToPolicyCmd.Flags().BoolVar(&planInferFiles, "infer-files", false, "Infer files.allow rules from plan")
	planToPolicyCmd.Flags().BoolVar(&planLimits, "limits", false, "Add default spend/turn limits")
	planToPolicyCmd.Flags().StringVar(&planModel, "model", "", "AI evaluator model (default: claude-opus-4-5-20251101)")
	planToPolicyCmd.Flags().BoolVar(&planList, "list", false, "List available plans from .claude/plans/ (project) and ~/.claude/plans/ (global)")

	// Replay command flags
	replayCmd.Flags().StringVar(&replaySessionPath, "session", "", "Path to Claude session .jsonl file (required)")
	replayCmd.Flags().StringVar(&replayPolicyPath, "policy", "", "Path to .aflock policy file (default: .aflock in current directory)")
	replayCmd.Flags().StringVar(&replayFormat, "format", "text", "Output format: text or json")
	replayCmd.Flags().BoolVar(&replaySimulate, "simulate", false, "Run full simulation: produce session state + signed attestations")

	// Serve command flags
	serveCmd.Flags().StringVarP(&servePolicyPath, "policy", "p", "", "Path to .aflock policy file")
	serveCmd.Flags().IntVar(&serveHTTPPort, "http", 0, "HTTP port for SSE transport (default: stdio)")
	serveCmd.Flags().StringVar(&serveUnixSocket, "unix", "", "Unix-domain socket path for kernel-attested peer-cred identity (mutually exclusive with --http)")
	serveCmd.MarkFlagsMutuallyExclusive("http", "unix")
}

func main() {
	// Handle --hook flag directly before cobra parsing
	for i, arg := range os.Args {
		if arg == "--hook" && i+1 < len(os.Args) {
			hookName := os.Args[i+1]
			handler := hooks.NewHandler()
			if err := handler.Handle(hookName); err != nil {
				fmt.Fprintf(os.Stderr, "Hook error: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
