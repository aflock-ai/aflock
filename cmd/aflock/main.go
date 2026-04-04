// Package main implements the aflock CLI for Claude Code plugin integration.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/aflock-ai/aflock/internal/hooks"
	"github.com/aflock-ai/aflock/internal/mcp"
	"github.com/aflock-ai/aflock/internal/plan"
	"github.com/aflock-ai/aflock/internal/policy"
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

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify step attestations against policy",
	Long: `Verify step attestations for a git tree hash against a policy.

Uses the current git tree hash if --tree-hash is not specified.

The policy defines required steps (e.g., lint, test, build) and the
verify command checks that attestations exist and are valid for each step.

Examples:
  aflock verify --policy .aflock                     # Verify steps for current git HEAD
  aflock verify --policy .aflock --tree-hash abc123  # Verify specific tree hash
  aflock verify -p policy.json -a ./attestations     # Custom attestation directory`,
	Run: func(cmd *cobra.Command, args []string) {
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

var signKeyPath string
var signOutputPath string

var signCmd = &cobra.Command{
	Use:   "sign <policy.aflock>",
	Short: "Sign a policy file",
	Long: `Sign a policy file with an ECDSA key.

If no key is provided via --key or AFLOCK_SIGNING_KEY, a new ephemeral
key is generated and the public key is printed to stderr.

This creates a DSSE-signed policy envelope that cannot be modified by the agent.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		policyPath := args[0]

		// Read the policy file
		policyData, err := os.ReadFile(policyPath) //nolint:gosec // G304: policy file path from CLI arg
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read policy: %v\n", err)
			os.Exit(1)
		}

		// Validate it's valid JSON
		var policyJSON json.RawMessage
		if err := json.Unmarshal(policyData, &policyJSON); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid policy JSON: %v\n", err)
			os.Exit(1)
		}

		// Load or generate signing key
		keyPath := signKeyPath
		if keyPath == "" {
			keyPath = os.Getenv("AFLOCK_SIGNING_KEY")
		}

		var privKey *ecdsa.PrivateKey
		if keyPath != "" {
			keyData, err := os.ReadFile(keyPath) //nolint:gosec // G304: key file path from CLI arg
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to read key: %v\n", err)
				os.Exit(1)
			}
			privKey, err = parseECDSAPrivateKey(keyData)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to parse key: %v\n", err)
				os.Exit(1)
			}
		} else {
			// Generate ephemeral key
			privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to generate key: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Generated ephemeral signing key (no --key provided)\n")
		}

		// Compute keyid as SHA256 fingerprint of the DER-encoded public key
		pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal public key: %v\n", err)
			os.Exit(1)
		}
		keyFingerprint := sha256.Sum256(pubDER)
		keyID := fmt.Sprintf("SHA256:%x", keyFingerprint)

		// For ephemeral keys, output the public key PEM so the user can verify later
		if keyPath == "" {
			pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
			fmt.Fprintf(os.Stderr, "Public key (save this to verify signatures):\n%s", pubPEM)
		}

		// Create DSSE envelope
		payloadType := "application/vnd.aflock.policy+json"
		payload := base64.StdEncoding.EncodeToString(policyData)

		// Create PAE (Pre-Authentication Encoding)
		paeData := createSignPAE(payloadType, policyData)
		hash := sha256.Sum256(paeData)

		// Sign
		sigBytes, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to sign: %v\n", err)
			os.Exit(1)
		}

		envelope := struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
			Signatures  []struct {
				KeyID string `json:"keyid"`
				Sig   string `json:"sig"`
			} `json:"signatures"`
		}{
			PayloadType: payloadType,
			Payload:     payload,
			Signatures: []struct {
				KeyID string `json:"keyid"`
				Sig   string `json:"sig"`
			}{
				{
					KeyID: keyID,
					Sig:   base64.StdEncoding.EncodeToString(sigBytes),
				},
			},
		}

		envelopeJSON, err := json.MarshalIndent(envelope, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal envelope: %v\n", err)
			os.Exit(1)
		}

		// Write output
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

// createSignPAE creates a DSSE Pre-Authentication Encoding.
func createSignPAE(payloadType string, payload []byte) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	buf.Write(payload)
	return buf.Bytes()
}

// parseECDSAPrivateKey parses a PEM-encoded ECDSA private key.
func parseECDSAPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key file")
	}

	// Try EC private key format (SEC1) first
	key, ecErr := x509.ParseECPrivateKey(block.Bytes)
	if ecErr == nil {
		return key, nil
	}

	// Try PKCS8
	pkcs8Key, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if pkcs8Err != nil {
		return nil, fmt.Errorf("failed to parse private key (SEC1: %v; PKCS8: %w)", ecErr, pkcs8Err)
	}

	ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an ECDSA private key (got %T)", pkcs8Key)
	}
	return ecKey, nil
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

var servePolicyPath string
var serveHTTPPort int

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the aflock MCP server",
	Long: `Start the aflock MCP server on stdio or HTTP.

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
  mcporter config add aflock http://localhost:8787/sse`,
	Run: func(cmd *cobra.Command, args []string) {
		server := mcp.NewServer()
		var err error
		if serveHTTPPort > 0 {
			err = server.ServeHTTP(servePolicyPath, serveHTTPPort)
		} else {
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
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(planToPolicyCmd)

	// Add --hook flag as alternative to hook subcommand for backwards compatibility
	rootCmd.Flags().StringVar(&hookFlag, "hook", "", "Hook event to handle (alternative to 'hook' subcommand)")

	// Verify command flags
	verifyCmd.Flags().StringVarP(&verifyPolicyPath, "policy", "p", "", "Path to .aflock policy file (enables step-based verification)")
	verifyCmd.Flags().StringVarP(&verifyAttestDir, "attestations", "a", "", "Attestations directory (default: ~/.aflock/attestations)")
	verifyCmd.Flags().StringVar(&verifyTreeHash, "tree-hash", "", "Git tree hash to verify (default: current HEAD)")

	// Sign command flags
	signCmd.Flags().StringVarP(&signKeyPath, "key", "k", "", "Path to ECDSA private key PEM file (or set AFLOCK_SIGNING_KEY)")
	signCmd.Flags().StringVarP(&signOutputPath, "output", "o", "", "Output path for signed envelope (default: <input>.signed, use - for stdout)")

	// Plan-to-policy command flags
	planToPolicyCmd.Flags().StringVar(&planPath, "plan", "", "Path to Claude plan markdown file (required)")
	planToPolicyCmd.Flags().StringVarP(&planOutput, "output", "o", ".aflock", "Output path for generated policy")
	planToPolicyCmd.Flags().BoolVar(&planMerge, "merge", false, "Merge steps into existing .aflock policy")
	planToPolicyCmd.Flags().BoolVar(&planInferFiles, "infer-files", false, "Infer files.allow rules from plan")
	planToPolicyCmd.Flags().BoolVar(&planLimits, "limits", false, "Add default spend/turn limits")
	planToPolicyCmd.Flags().StringVar(&planModel, "model", "", "AI evaluator model (default: claude-opus-4-5-20251101)")
	planToPolicyCmd.Flags().BoolVar(&planList, "list", false, "List available plans from .claude/plans/ (project) and ~/.claude/plans/ (global)")

	// Serve command flags
	serveCmd.Flags().StringVarP(&servePolicyPath, "policy", "p", "", "Path to .aflock policy file")
	serveCmd.Flags().IntVar(&serveHTTPPort, "http", 0, "HTTP port for SSE transport (default: stdio)")
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
