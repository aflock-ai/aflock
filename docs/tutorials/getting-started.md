---
sidebar_position: 0
---

# Getting Started

:::caution Alpha Software
aflock is under active development. Policy creation, signing, hooks integration, and resource limit enforcement are working. The 6-phase verification pipeline is partially implemented (Phase 1 only). See the [open issues](https://github.com/aflock-ai/aflock/issues) for current status.
:::

This tutorial walks you through creating your first `.aflock` policy, integrating it with Claude Code, and verifying agent compliance.

## Prerequisites

- Go 1.25+ installed
- Claude Code CLI installed
- A project directory to work in

## Install aflock

Clone and build from source:

```bash
git clone https://github.com/aflock-ai/aflock.git
cd aflock
make build
```

The binary is at `./bin/aflock`. Move it to your PATH:

```bash
cp ./bin/aflock /usr/local/bin/aflock
```

## Create Your First Policy

Navigate to your project and initialize a policy:

```bash
cd /path/to/your/project
aflock init
```

This creates a `.aflock` file with sensible defaults:

```json
{
  "version": "1.0",
  "name": "my-project-policy",
  "limits": {
    "maxSpendUSD": { "value": 5.00, "enforcement": "fail-fast" },
    "maxTurns": { "value": 30, "enforcement": "post-hoc" }
  },
  "tools": {
    "allow": ["Read", "Edit", "Write", "Glob", "Grep", "Bash"],
    "deny": ["Task"]
  },
  "files": {
    "allow": ["src/**", "tests/**"],
    "deny": ["**/.env", "**/secrets/**"]
  }
}
```

## Understanding the Policy

| Section | What It Controls |
|---------|-----------------|
| `limits` | Cost, token, turn, and time budgets |
| `tools` | Which Claude Code tools the agent can use |
| `files` | Which files the agent can read/write |
| `identity` | Which AI models are authorized |
| `evaluators` | Post-hoc quality and constraint checks |

### Enforcement Modes

- **`fail-fast`**: Abort immediately when the limit is breached. Use for cost and security constraints.
- **`post-hoc`**: Verify at session end. Use for quality metrics and turn counts.

## Integrate with Claude Code

### Via Hooks

aflock registers as a Claude Code plugin. Configure it in your Claude Code settings:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "aflock hook PreToolUse",
        "timeout": 5
      }]
    }],
    "PostToolUse": [{
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "aflock hook PostToolUse",
        "timeout": 5
      }]
    }]
  }
}
```

### Via MCP Server

Start the aflock MCP server:

```bash
aflock serve --policy .aflock
```

This exposes MCP tools that Claude Code can use directly: `get_identity`, `get_policy`, `check_tool`, and more.

## Verify Compliance

After a session completes, verify the attestations:

```bash
aflock verify --policy .aflock
```

This runs the verification algorithm. Currently Phase 1 (Signature Verification) is implemented. The full 6-phase pipeline is in active development ([#16](https://github.com/aflock-ai/aflock/issues/16)):

1. **Signature Verification** — Check cryptographic signatures (**implemented**)
2. **Identity Verification** — Agent matches policy constraints (*WIP*)
3. **Materials Binding** — Merkle tree and git hash verification (*WIP*)
4. **Constraint Evaluation** — Rego policies against all attestations (*WIP*)
5. **AI Evaluation** — Qualitative assessments (*WIP*)
6. **Sublayout Recursion** — Verify sub-agent attestations (*WIP*)

Exit code `0` means the session was compliant. Non-zero means violations were found.

## Check Session Status

While a session is active:

```bash
aflock status
```

This shows active sessions with metrics: turns completed, tool calls, spend, and policy name.

## Next Steps

- Learn about [Policies](/docs/docs/concepts/policies) in depth
- Understand [Agent Identity](/docs/docs/concepts/identity)
- Explore [Example Policies](/docs/docs/examples/feature-development)
- Read the [Comparison](/docs/docs/reference/comparison) with other systems
