---
sidebar_position: 0
---

# CLI Reference

The `aflock` command-line tool provides policy management, verification, and integration capabilities.

## Commands

### `aflock init`

Create a template `.aflock` policy in the current directory.

```bash
aflock init
```

Creates `.aflock` with sensible defaults for tool access, file restrictions, and spend limits.

### `aflock hook <event>`

Handle Claude Code hook events. Reads JSON from stdin, outputs JSON to stdout.

```bash
aflock hook <event>
```

**Events:**

| Event | When It Fires | What aflock Does |
|-------|---------------|------------------|
| `SessionStart` | Session begins | Load policy, initialize state |
| `PreToolUse` | Before tool execution | Check allowlists, limits |
| `PostToolUse` | After tool execution | Record attestation |
| `PermissionRequest` | Permission prompt | Auto-approve/deny |
| `UserPromptSubmit` | User sends message | Track turn count |
| `Stop` | Agent stops | Check completion constraints |
| `SubagentStop` | Sub-agent stops | Check sublayout constraints |
| `SessionEnd` | Session ends | Final verification |

### `aflock verify`

Verify attestations against a policy.

```bash
aflock verify [flags]
```

**Flags:**

| Flag | Description |
|------|-------------|
| `-p, --policy` | Path to `.aflock` policy file (default: `.aflock` in cwd) |
| `-a, --attestations` | Path to attestation directory |
| `--tree-hash` | Expected git tree hash |

**Examples:**

```bash
# Verify with policy in current directory
aflock verify

# Verify with explicit policy and git hash
aflock verify --policy .aflock --tree-hash abc123

# Verify with custom attestation directory
aflock verify -p policy.json -a ./attestations
```

**Exit codes:** `0` = compliant, non-zero = violations found.

### `aflock status`

Show active agent sessions with metrics.

```bash
aflock status
```

Displays: session ID, policy name, start time, turns completed, tool calls, spend.

### `aflock sign`

Sign a policy file with ECDSA P256, producing a DSSE envelope.

```bash
aflock sign <policy.aflock>
```

### `aflock serve`

Start the MCP server for Claude Code integration.

```bash
aflock serve [flags]
```

**Flags:**

| Flag | Description |
|------|-------------|
| `-p, --policy` | Path to `.aflock` policy (default: auto-discover in cwd) |

**MCP Tools Exposed:**

| Tool | Description |
|------|-------------|
| `get_identity` | Return derived agent identity |
| `get_policy` | Return loaded policy |
| `get_token` | Get a JWT authorization token for this session |
| `check_tool` | Pre-check tool authorization |
| `bash` | Execute commands with enforcement |
| `read_file` | Read files with access control |
| `write_file` | Write files with access control |
| `get_session` | Return session metrics |
| `sign_attestation` | Sign an attestation using SPIRE identity |

#### JWT Authorization

When the MCP server starts, it initializes a JWT token issuer with an ephemeral ECDSA P-256 key. Clients can call `get_token` to receive a session-scoped JWT, then pass it as `_token` in subsequent tool calls:

```json
{
  "method": "tools/call",
  "params": {
    "name": "bash",
    "arguments": {
      "command": "echo hello",
      "_token": "<jwt-from-get_token>"
    }
  }
}
```

Once a token has been issued for a session, **all tool calls must include `_token`**. Calls without a token are rejected with an authorization error. Before `get_token` is called, tools work without authentication (graceful adoption).

The JWT encodes: agent identity, session binding, allowed/denied tools, policy limits, and policy digest. See the [JWT Authorization tutorial](/docs/docs/tutorials/jwt-authorization) for a hands-on walkthrough.
