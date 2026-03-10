// Package main generates CLI reference documentation and JSON schemas for aflock.
//
// Usage:
//
//	go run ./docgen [--dir docs]
//
// This generates:
//   - docs/commands.md         — CLI reference from cobra commands
//   - docs/schemas/policy.json — JSON Schema for .aflock policy files
//   - docs/schemas/hooks.json  — JSON Schema for hook input/output
//
// Modeled after the witness project's docgen pattern.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/invopop/jsonschema"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

var directory string

func init() {
	flag.StringVar(&directory, "dir", "docs", "Directory to store the generated docs")
	flag.Parse()
}

// newRootCmd re-creates the aflock cobra command tree for documentation purposes.
// We re-create rather than import because cmd/aflock is package main.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "aflock",
		Short: "Cryptographically signed policy enforcement for AI agents",
		Long: `aflock enforces .aflock policies on AI agents like Claude Code.

It integrates via Claude Code's hooks system to:
- Evaluate policy before tool execution (PreToolUse)
- Record attestations after tool execution (PostToolUse)
- Track cumulative metrics (turns, spend, tokens)
- Verify constraints at session end`,
	}

	hookCmd := &cobra.Command{
		Use:   "hook <event>",
		Short: "Handle a Claude Code hook event",
		Long: `Handle a Claude Code hook event by reading JSON from stdin and writing JSON to stdout.

Supported events:
  SessionStart      - Initialize session, load policy, inject context
  PreToolUse        - Evaluate tool authorization before execution
  PostToolUse       - Record attestation after tool execution
  PermissionRequest - Handle permission prompts
  UserPromptSubmit  - Track turn count
  Stop              - Check completion constraints
  SubagentStop      - Handle subagent lifecycle
  SessionEnd        - Final verification
  Notification      - Handle agent notifications
  PreCompact        - Handle session compaction

The hook reads JSON from stdin (Claude Code's hook protocol) and writes
a JSON response to stdout.

Example:
  echo '{"session_id":"s1","cwd":"/project","tool_name":"Read","tool_input":{"file_path":"src/app.go"}}' | aflock hook PreToolUse`,
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create a new .aflock policy template",
		Long: `Create a new .aflock policy template in the current directory.

The template includes sensible defaults for:
  - Tool restrictions (allow common tools, deny dangerous ones)
  - File access patterns (deny secrets, .env files)
  - Spend and token limits
  - Identity constraints`,
	}

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify step attestations against policy",
		Long: `Verify that attestations in the attestation directory satisfy the policy constraints.

This performs:
  1. Signature verification (ECDSA, Ed25519, RSA)
  2. Policy limit compliance (spend, tokens, turns)
  3. Required attestation presence
  4. Data flow violation detection

Example:
  aflock verify --policy .aflock --attestations ./attestations
  aflock verify --policy .aflock --attestations ./attestations --tree-hash abc123`,
	}
	verifyCmd.Flags().StringP("policy", "p", "", "Path to .aflock policy file")
	verifyCmd.Flags().StringP("attestations", "a", "", "Attestations directory (default: ~/.aflock/attestations)")
	verifyCmd.Flags().String("tree-hash", "", "Git tree hash to verify (default: current HEAD)")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show current session status",
		Long: `Display all active aflock sessions with their policy, metrics, and tool usage.

Sessions are stored in ~/.aflock/sessions/ and persist across Claude Code restarts.`,
	}

	signCmd := &cobra.Command{
		Use:   "sign <policy.aflock>",
		Short: "Sign a policy file",
		Long: `Sign a policy file with an ECDSA P256 key and output a DSSE envelope.

If no --key is provided, an ephemeral signing key is generated and the
public key is printed to stderr. Save the public key to verify signatures later.

The signed output is a DSSE (Dead Simple Signing Envelope) with:
  - payloadType: "application/vnd.aflock.policy+json"
  - payload: base64-encoded policy content
  - signatures: ECDSA P256 signature with key ID

Example:
  aflock sign .aflock                          # ephemeral key
  aflock sign .aflock --key private.pem        # existing key
  aflock sign .aflock --output signed.json     # custom output path
  aflock sign .aflock --output -               # write to stdout`,
	}
	signCmd.Flags().StringP("key", "k", "", "Path to ECDSA private key PEM file (or set AFLOCK_SIGNING_KEY)")
	signCmd.Flags().StringP("output", "o", "", "Output path for signed envelope (default: <input>.signed)")

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the aflock MCP server",
		Long: `Start the aflock MCP (Model Context Protocol) server.

The MCP server exposes policy-enforced tools that AI agents can use:
  - get_identity     Get the derived agent identity
  - get_policy       Get the loaded policy
  - check_tool       Pre-check if a tool call would be allowed
  - bash             Execute commands with policy enforcement and optional attestation
  - read_file        Read files with access control
  - write_file       Write files with access control
  - get_session      Get session metrics
  - sign_attestation Sign an attestation with the agent's SPIRE identity

By default, the server communicates over stdio (for Claude Code integration).
Use --http to start an HTTP server with SSE transport instead.

Example:
  aflock serve --policy .aflock            # stdio mode (Claude Code)
  aflock serve --policy .aflock --http 8080  # HTTP SSE mode`,
	}
	serveCmd.Flags().StringP("policy", "p", "", "Path to .aflock policy file")
	serveCmd.Flags().Int("http", 0, "HTTP port for SSE transport (default: stdio)")

	planToPolicyCmd := &cobra.Command{
		Use:   "plan-to-policy",
		Short: "Convert a Claude plan into an .aflock policy",
		Long: `Convert a Claude Code plan (markdown) into an .aflock policy file.

The plan parser extracts:
  - Deterministic steps (build commands, test commands)
  - UAT/acceptance criteria (converted to AI evaluators)
  - Referenced files (used for files.allow rules)

Example:
  aflock plan-to-policy --plan .claude/plans/feature.md --output .aflock
  aflock plan-to-policy --plan plan.md --limits --infer-files
  aflock plan-to-policy --list    # list available plans`,
	}
	planToPolicyCmd.Flags().String("plan", "", "Path to Claude plan markdown file (required)")
	planToPolicyCmd.Flags().StringP("output", "o", ".aflock", "Output path for generated policy")
	planToPolicyCmd.Flags().Bool("merge", false, "Merge steps into existing .aflock policy")
	planToPolicyCmd.Flags().Bool("infer-files", false, "Infer files.allow rules from plan")
	planToPolicyCmd.Flags().Bool("limits", false, "Add default spend/turn limits")
	planToPolicyCmd.Flags().String("model", "", "AI evaluator model (default: claude-opus-4-5-20251101)")
	planToPolicyCmd.Flags().Bool("list", false, "List available plans")

	root.AddCommand(hookCmd, initCmd, verifyCmd, statusCmd, signCmd, serveCmd, planToPolicyCmd)
	return root
}

func main() {
	log.Println("Generating aflock documentation")

	// --- 1. CLI Reference ---
	log.Println("Generating CLI reference...")
	mdContent := "# aflock CLI Reference\n\n"
	mdContent += "This is the reference for the aflock command line tool, auto-generated from [Cobra](https://cobra.dev/) command definitions.\n\n"
	mdContent += "> Run `aflock <command> --help` for the most up-to-date usage information.\n\n"

	root := newRootCmd()

	// Generate doc for root command itself
	buf := new(bytes.Buffer)
	if err := doc.GenMarkdown(root, buf); err != nil {
		log.Fatalf("Error generating root doc: %v", err)
	}
	mdContent += buf.String()

	// Generate doc for each subcommand
	for _, command := range root.Commands() {
		if command.Use == "completion [bash|zsh|fish|powershell]" || command.Use == "help [command]" {
			continue
		}

		buf := new(bytes.Buffer)
		if err := doc.GenMarkdown(command, buf); err != nil {
			log.Printf("Error generating doc for %s: %v", command.Use, err)
			continue
		}
		mdContent += buf.String()
	}

	// Replace actual $HOME paths with $HOME for portability
	if home := os.Getenv("HOME"); home != "" {
		mdContent = strings.ReplaceAll(mdContent, home, "$HOME")
	}

	if err := os.MkdirAll(fmt.Sprintf("%s/reference", directory), 0755); err != nil {
		log.Fatalf("Error creating reference dir: %v", err)
	}

	if err := os.WriteFile(fmt.Sprintf("%s/reference/commands.md", directory), []byte(mdContent), 0644); err != nil {
		log.Fatalf("Error writing commands.md: %v", err)
	}
	log.Println("  -> docs/reference/commands.md")

	// --- 2. JSON Schemas ---
	log.Println("Generating JSON schemas...")
	if err := os.MkdirAll(fmt.Sprintf("%s/schemas", directory), 0755); err != nil {
		log.Fatalf("Error creating schemas dir: %v", err)
	}

	schemas := map[string]interface{}{
		"policy":      aflock.Policy{},
		"hook-input":  aflock.HookInput{},
		"hook-output": aflock.HookOutput{},
		"session":     aflock.SessionState{},
	}

	for name, typ := range schemas {
		schema := jsonschema.Reflect(typ)
		schema.Title = name
		schemaJSON, err := schema.MarshalJSON()
		if err != nil {
			log.Fatalf("Error generating %s schema: %v", name, err)
		}

		var indented bytes.Buffer
		if err := json.Indent(&indented, schemaJSON, "", "  "); err != nil {
			log.Fatalf("Error indenting %s schema: %v", name, err)
		}

		path := fmt.Sprintf("%s/schemas/%s.json", directory, name)
		if err := os.WriteFile(path, append(indented.Bytes(), '\n'), 0644); err != nil {
			log.Fatalf("Error writing %s: %v", path, err)
		}
		log.Printf("  -> docs/schemas/%s.json", name)
	}

	// --- 3. Append schema to policy-schema.md if it exists ---
	policySchemaPath := fmt.Sprintf("%s/reference/policy-schema.md", directory)
	if f, err := os.ReadFile(policySchemaPath); err == nil {
		schema := jsonschema.Reflect(aflock.Policy{})
		schemaJSON, _ := schema.MarshalJSON()
		var indented bytes.Buffer
		json.Indent(&indented, schemaJSON, "", "  ")

		schemaContent := "\n## Schema\n```json\n" + indented.String() + "\n```\n"

		content := string(f)
		if idx := strings.Index(content, "## Schema"); idx != -1 {
			content = content[:idx]
		}
		content += schemaContent

		if err := os.WriteFile(policySchemaPath, []byte(content), 0644); err != nil {
			log.Fatalf("Error writing policy-schema.md: %v", err)
		}
		log.Println("  -> Updated docs/reference/policy-schema.md with schema")
	}

	log.Println("Documentation generation complete!")
}
