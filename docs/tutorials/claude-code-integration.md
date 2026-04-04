---
sidebar_position: 1
---

# Claude Code Integration

:::info What's Working
Hook-based constraint enforcement (tool allowlists, file access, limits), **attestation generation**, and **JWT-based agent authorization** ([#19](https://github.com/aflock-ai/aflock/issues/19)) are implemented. Every allowed tool call produces a signed in-toto v1 attestation stored in `~/.aflock/sessions/<id>/attestations/`. The MCP server issues ES256 JWTs at session start, scoped to policy grants and validated per-request. Note that HTTP mode currently has no authentication ([#27](https://github.com/aflock-ai/aflock/issues/27)) — use stdio mode for now.
:::

:::caution Active Development
Policy expiration is not yet enforced at runtime ([#18](https://github.com/aflock-ai/aflock/issues/18)).
:::

aflock integrates with Claude Code through two mechanisms: **hooks** and **MCP server**. This tutorial covers both approaches.

## Hook Integration

Claude Code fires lifecycle events at every stage of a session. aflock registers handlers for each event to enforce policy in real-time.

### Hook Event Flow

```
SessionStart       Initialize session, load policy
     |
UserPromptSubmit   Track conversation turns
     |
PreToolUse         Check: tool allowed? file access OK? limits OK?
     |              If denied: { "decision": "block", "message": "..." }
     |
[Tool Executes]
     |
PostToolUse        Sign & store in-toto attestation for the action
     |
PermissionRequest  Auto-approve/deny based on policy
     |
Stop               Check completion constraints
     |
SessionEnd         Final verification, run evaluators
```

### Hook Configuration

Add to your Claude Code `settings.json`:

```json
{
  "hooks": {
    "SessionStart": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "aflock hook SessionStart",
        "timeout": 10
      }]
    }],
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
    }],
    "Stop": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "aflock hook Stop",
        "timeout": 10
      }]
    }]
  }
}
```

### How PreToolUse Enforcement Works

When Claude Code wants to use a tool (e.g., `Bash`), aflock evaluates:

1. **Tool allowlist**: Is `Bash` in `tools.allow`?
2. **File access**: Does the command target files in `files.allow`?
3. **Domain access**: Does the request hit an allowed domain?
4. **Spend limits**: Is `maxSpendUSD` still within budget?
5. **Pattern matching**: Does the command match `requireApproval` patterns?

If any check fails, aflock returns a block decision and the tool call is denied.

## MCP Server Integration

The MCP server provides a richer integration where aflock acts as a proxy between the agent and system resources.

### Start the Server

```bash
aflock serve --policy .aflock
```

### Available MCP Tools

| Tool | Purpose |
|------|---------|
| `get_identity` | Return the derived agent identity hash |
| `get_policy` | Return the loaded policy document |
| `get_token` | Get a JWT authorization token for this session |
| `check_tool` | Pre-check whether a tool call would be allowed |
| `bash` | Execute commands with policy enforcement |
| `read_file` | Read files with access control |
| `write_file` | Write files with access control |
| `get_session` | Return current session metrics |
| `sign_attestation` | Sign an attestation using SPIRE identity |

### JWT Authorization in MCP Mode

The MCP server initializes a JWT token issuer on startup. Call `get_token` to receive a session-scoped JWT, then include it as `_token` in all subsequent tool calls. See the [JWT Authorization tutorial](/docs/docs/tutorials/jwt-authorization) for a hands-on walkthrough.

### MCP vs Hooks

| Aspect | Hooks | MCP Server |
|--------|-------|------------|
| Integration | Claude Code settings | MCP configuration |
| Latency | Per-hook process spawn | Persistent connection |
| Capabilities | Observe and block | Full proxy with identity |
| Identity | Limited | Full PID introspection |
| Best for | Quick setup | Production deployments |

## Plugin Installation

aflock ships as a Claude Code plugin:

```json
// .claude-plugin/plugin.json
{
  "name": "aflock",
  "version": "0.1.0",
  "description": "Cryptographically signed policy enforcement for AI agents",
  "hooks": "./hooks/hooks.json"
}
```

Place this in your project's `.claude-plugin/` directory and Claude Code will discover it automatically.
