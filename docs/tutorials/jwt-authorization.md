---
sidebar_position: 2
---

# JWT Authorization

This tutorial walks through testing JWT-based agent authorization with a real Claude Code session. You'll see how aflock issues tokens, how they're validated, and how tool-level scoping works.

## Overview

aflock issues short-lived ES256 JWTs scoped to:
- **Session** — token is bound to the session ID (audience claim)
- **Agent identity** — SPIFFE ID and identity hash baked into claims
- **Policy** — allowed/denied tools and limits from the `.aflock` policy
- **Policy version** — SHA-256 digest prevents use with a different policy

## Prerequisites

- aflock built from the `feat/19-jwt-agent-authorization` branch
- A project with an `.aflock` policy file
- Claude Code installed

## Testing with MCP Server Mode

### 1. Create a test policy

```bash
mkdir -p /tmp/jwt-test && cd /tmp/jwt-test
```

Create `.aflock`:

```json
{
  "version": "1.0",
  "name": "jwt-test-policy",
  "tools": {
    "allow": ["Read", "Bash", "Glob", "Grep"],
    "deny": ["Write", "Edit"]
  },
  "limits": {
    "maxTurns": { "value": 20, "enforcement": "fail-fast" }
  },
  "files": {
    "allow": ["**"],
    "deny": ["**/.env", "**/secrets/**"]
  }
}
```

### 2. Start the MCP server

```bash
aflock serve --policy .aflock
```

You should see in stderr:

```
[aflock] JWT authorization enabled
[aflock] MCP server started with policy: jwt-test-policy
```

### 3. Get a token

From Claude Code (or any MCP client), call `get_token`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_token",
    "arguments": {}
  }
}
```

Response:

```json
{
  "token": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImVwaGVtZXJhbC1lY2RzYS1wMjU2IiwidHlwIjoiSldUIn0...",
  "expiresIn": "1h0m0s",
  "sessionId": "mcp-abc123..."
}
```

### 4. Use the token in tool calls

Pass the JWT as `_token` in every subsequent tool call:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "bash",
    "arguments": {
      "command": "echo hello world",
      "_token": "eyJhbGciOiJFUzI1NiIs..."
    }
  }
}
```

### 5. Test tool-level scoping

Try calling a denied tool with the token:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "write_file",
    "arguments": {
      "path": "/tmp/test.txt",
      "content": "hello",
      "_token": "eyJhbGciOiJFUzI1NiIs..."
    }
  }
}
```

Expected response:

```
Authorization denied: tool 'Write' not permitted by token scope
```

### 6. Test without a token (after issuance)

Once `get_token` has been called for a session, all subsequent calls **must** include `_token`:

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "bash",
    "arguments": {
      "command": "echo no token"
    }
  }
}
```

Expected response:

```
Authorization denied: missing auth token (_token parameter)
```

## Testing with Hooks Mode (Claude Code)

In hooks mode, the JWT is issued automatically during `SessionStart` and stored in the session state file.

### 1. Set up hooks

Add to your Claude Code `settings.json` (or use the aflock plugin):

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
    }]
  }
}
```

### 2. Start a Claude Code session

```bash
cd /tmp/jwt-test
claude
```

In stderr output you should see:

```
[aflock] JWT issued for session <session-id> (ttl=1h0m0s)
```

### 3. Verify the token in session state

The JWT is saved in the session state file. You can inspect it:

```bash
# Find the session state
ls ~/.aflock/sessions/

# Read the state file (the auth_token field contains the JWT)
cat ~/.aflock/sessions/<session-id>/state.json | jq '.auth_token'
```

### 4. Decode and inspect the JWT

You can decode the token to see the claims (the signature won't verify without the ephemeral key, but the payload is readable):

```bash
# Extract and decode the JWT payload (second segment)
TOKEN=$(cat ~/.aflock/sessions/<session-id>/state.json | jq -r '.auth_token')
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Expected output:

```json
{
  "iss": "aflock",
  "sub": "spiffe://aflock.ai/agent/claude-opus/...",
  "aud": ["<session-id>"],
  "exp": 1737244800,
  "iat": 1737241200,
  "jti": "<session-id>",
  "agent_id": "spiffe://aflock.ai/agent/claude-opus/...",
  "identity_hash": "sha256:abc123...",
  "allowed_tools": ["Read", "Bash", "Glob", "Grep"],
  "denied_tools": ["Write", "Edit"],
  "limits": { "maxTurns": { "value": 20, "enforcement": "fail-fast" } },
  "policy_digest": "sha256:..."
}
```

## What the JWT Encodes

| Claim | Source | Purpose |
|-------|--------|---------|
| `iss` | Always `"aflock"` | Issuer validation — rejects tokens from other systems |
| `sub` | Agent's SPIFFE ID | Identity binding |
| `aud` | Session ID | Prevents cross-session replay |
| `exp` | Policy `maxWallTimeSeconds` or 1 hour | Auto-expiry |
| `agent_id` | SPIFFE ID from identity discovery | Agent identification |
| `identity_hash` | SHA-256 of agent properties | Tamper detection |
| `allowed_tools` | Policy `tools.allow` | Tool-level allowlist |
| `denied_tools` | Policy `tools.deny` | Tool-level denylist |
| `limits` | Policy `limits` | Resource constraints |
| `policy_digest` | SHA-256 of serialized policy | Policy version binding |

## Security Model

### What's Protected

1. **Unauthenticated access**: After `get_token` is called, all MCP tool calls require a valid JWT
2. **Tool scope escalation**: Token carries allow/deny lists; denied tools are rejected even with a valid token
3. **Session hijacking**: Token is bound to a session ID via the `aud` claim
4. **Algorithm confusion**: Only ES256 (ECDSA P-256) is accepted; HMAC/RSA tokens are rejected
5. **Token replay**: Tokens expire and are session-bound

### What's Not Yet Protected

1. **Signing key separation**: The agent still holds an ephemeral key for attestation signing in some paths. Full separation (server-only signing) is tracked in [#19](https://github.com/aflock-ai/aflock/issues/19) Phase 3.
2. **Token revocation**: No mid-session revocation mechanism yet. Tokens expire naturally.
3. **JWKS endpoint**: No external key discovery. Keys are ephemeral and in-process.

## Troubleshooting

### "JWT auth unavailable" on server start

The ephemeral key generation failed. Check that your Go installation includes `crypto/ecdsa` support (standard in all Go builds).

### "missing auth token" on tool calls

A token was previously issued for this session. All subsequent calls must include `_token`. Call `get_token` to get a new token.

### "token not valid for session"

The JWT was issued for a different session. Each token is bound to one session via the `aud` claim. Get a new token from `get_token`.

### Token in hooks mode but not in MCP mode

In hooks mode, the JWT is issued during `SessionStart` and stored in session state. In MCP mode, call `get_token` explicitly. The two modes use separate token issuers (different ephemeral keys).
