# Plan-to-Policy: Spec-Driven Development for AI Agents

:::info PR Status
Plan-to-policy is implemented on the `spire-attestation-fixes` branch ([PR #11](https://github.com/aflock-ai/aflock/pull/11)) along with SPIRE and MCP fixes. This PR is open and not yet merged to `main`.
:::

## What It Does

`plan-to-policy` converts Claude plan files (markdown with acceptance criteria) into `.aflock` policy files with verification steps and AI evaluators. This enables **spec-driven development**: define what the AI must prove it did *before* implementation begins.

## Why It Matters

Without plan-to-policy, policies are written manually. With it, the workflow becomes:

1. Claude creates a plan (in `.claude/plans/` or `~/.claude/plans/`)
2. `aflock plan-to-policy` converts it to a `.aflock` policy
3. Human signs the policy (cryptographic commitment)
4. AI implements the feature, constrained by the policy
5. `aflock verify` confirms all attestations satisfy the policy

The plan becomes a **verifiable contract** — not just documentation.

## Architecture

```
                    ┌──────────────────────────────────────────────────┐
                    │              plan-to-policy pipeline             │
                    └──────────────────────────────────────────────────┘

  ┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐
  │                 │        │                 │        │                 │
  │  Claude Plan    │──────▶ │     Parser      │──────▶ │   Generator     │
  │  (.md file)     │        │                 │        │                 │
  │                 │        │  Extracts steps, │        │  Creates policy │
  └─────────────────┘        │  criteria, files │        │  with evaluators│
                             └─────────────────┘        └────────┬────────┘
  ~/.claude/plans/           internal/plan/                      │
  plan.md                    parser.go                           │
                                      │                          ▼
                                      │               ┌─────────────────┐
                                      │               │                 │
                                      └──────────────▶│  .aflock Policy │
                                        ParsedPlan    │  (JSON file)    │
                                                      │                 │
                                                      └─────────────────┘
                                                      cmd/aflock/main.go
```

*[View interactive diagram on Excalidraw](https://excalidraw.com/#json=8JiDzCXJjIX_MhlU5KSf7,Kq7Xag5CZVcW-N-HVBXwZQ)*

**Workflow:** Plan → Convert → Sign → Implement → Verify

### Components

| Component | File | Purpose |
|-----------|------|---------|
| Parser | `internal/plan/parser.go` | Parses Claude plan markdown into `ParsedPlan` struct |
| Generator | `internal/plan/generator.go` | Converts `ParsedPlan` into `aflock.Policy` |
| CLI Command | `cmd/aflock/main.go` | `aflock plan-to-policy` subcommand |
| Claude Skill | `plugin/skills/plan-to-policy.md` | `/plan-to-policy` skill for Claude Code |

### Parser Formats

The parser handles three markdown formats that Claude plans commonly use:

**Table format** (recommended):
```markdown
## Steps
| Step | Command | AI Evaluator Prompt |
|------|---------|---------------------|
| lint | npm run lint | |
| test | npm test | |
| uat-search | | "PASS if search shows results" |
```

**List format**:
```markdown
## Deterministic Steps
- lint: npm run lint
- test: npm test

## Acceptance Criteria
- Search input is visible on the main page
- Typing a query filters results
```

**Section format** (UAT steps):
```markdown
### uat-inbox
**AI Policy Prompt**: PASS if frames show email inbox with list of emails
```

### Generator Output

The generator creates a complete `.aflock` policy with:
- **Steps**: Each plan step becomes a policy step with attestation requirements
- **AI Evaluators**: UAT steps get AI evaluators with PASS/FAIL prompts
- **File Rules**: Optionally inferred from files mentioned in the plan
- **Limits**: Optional default spend/turn limits
- **Tool Rules**: Default set of allowed tools (Read, Edit, Write, Glob, Grep, Bash, LSP)

## CLI Usage

```bash
# List available plans
aflock plan-to-policy --list

# Convert a plan to policy
aflock plan-to-policy \
  --plan ~/.claude/plans/my-plan.md \
  --output .aflock \
  --infer-files \
  --limits

# Merge new steps into existing policy
aflock plan-to-policy \
  --plan ~/.claude/plans/feature.md \
  --merge

# Use a different AI model for evaluators
aflock plan-to-policy \
  --plan plan.md \
  --model claude-sonnet-4-6
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--plan` | Path to Claude plan markdown file | (required unless --list) |
| `--output` | Output path for policy | `.aflock` |
| `--merge` | Merge into existing policy at output path | `false` |
| `--infer-files` | Generate `files.allow` from plan's referenced files | `false` |
| `--limits` | Add default spend ($10) and turn (50) limits | `false` |
| `--model` | AI evaluator model | `claude-opus-4-5-20251101` |
| `--list` | List available plans in `~/.claude/plans/` | `false` |

## Generated Policy Example

Given this plan:
```markdown
# Add Search Feature
## Deterministic Steps
- lint: npm run lint
- test: npm test
## Acceptance Criteria
- Search input is visible on main page
- Typing a query filters results
```

Generates this `.aflock` policy:
```json
{
  "version": "1.0",
  "name": "add-search-feature",
  "steps": {
    "lint": {
      "name": "lint",
      "attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}]
    },
    "test": {
      "name": "test",
      "attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}]
    },
    "uat-1": {
      "name": "uat-1",
      "attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}]
    },
    "uat-2": {
      "name": "uat-2",
      "attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}]
    }
  },
  "requiredAttestations": ["lint", "test", "uat-1", "uat-2"],
  "evaluators": {
    "ai": [
      {
        "name": "uat-1",
        "prompt": "PASS if the following acceptance criterion is met: Search input is visible on main page. FAIL otherwise.",
        "model": "claude-opus-4-5-20251101"
      },
      {
        "name": "uat-2",
        "prompt": "PASS if the following acceptance criterion is met: Typing a query filters results. FAIL otherwise.",
        "model": "claude-opus-4-5-20251101"
      }
    ]
  },
  "tools": {
    "allow": ["Read", "Edit", "Write", "Glob", "Grep", "Bash", "LSP"]
  },
  "files": {
    "deny": ["**/.env", "**/secrets/**"]
  }
}
```

## Tests

```bash
cd /Users/rahulxf/work-dir/aflock
go test ./internal/plan/...
```

Tests cover:
- Table, list, and section format parsing
- File path extraction from plan markdown
- Mixed tables (deterministic + UAT in one table)
- Empty content handling
- Real-world plan parsing
- Policy generation (basic, with limits, file inference, merge mode)
- End-to-end (parse markdown → generate policy → verify JSON roundtrip)
