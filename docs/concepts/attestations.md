---
sidebar_position: 2
---

# Attestations

:::info What's Working
- **Attestation signing** using DSSE envelopes is implemented in both **MCP server mode** and **hooks mode** ([#17](https://github.com/aflock-ai/aflock/issues/17)). Every `PostToolUse` hook generates a signed in-toto v1 attestation with the `action/v0.1` predicate type. Signing uses SPIRE X509-SVIDs when available, or an ephemeral ECDSA key as fallback.
- **JWT-based agent authorization** ([#19](https://github.com/aflock-ai/aflock/issues/19)) — ES256 tokens issued at session start, scoped to policy grants, validated per-request
:::

:::caution Active Development
**JWT + Signing Key full separation** (server-only signing key, agent holds JWT only) is partially implemented — the agent still holds an ephemeral signing key for attestation in some paths. Session Merkle trees are designed but not yet implemented.
:::

Every agent action produces a **cryptographically signed attestation** — an unforgeable record of what happened. aflock uses the [in-toto](https://in-toto.io/) attestation format wrapped in DSSE envelopes.

## JWT-based Agent Authorization

> **Status: Implemented** — See [#19](https://github.com/aflock-ai/aflock/issues/19). JWT tokens are issued at session start and validated on each MCP tool call.

A critical security property is the separation between **authorization** (what the agent is allowed to do) and **attestation** (proof of what the agent did):

| Component | Held By | Purpose |
|-----------|---------|---------|
| **JWT** | Agent | Short-lived authorization token |
| **Signing Key** | Server | Signs all attestations |

The agent presents its JWT when requesting actions, but all attestations are signed by a key the agent never sees. This ensures that **even a compromised agent cannot forge attestations** claiming compliant behavior.

### JWT Claims Structure

Tokens use **ES256** (ECDSA P-256) exclusively — HMAC and RSA are rejected to prevent algorithm confusion attacks.

```json
{
  "iss": "aflock",
  "sub": "spiffe://aflock.ai/agent/claude-opus/4.5/abc123",
  "aud": ["session-uuid-here"],
  "exp": 1737244800,
  "iat": 1737241200,
  "jti": "session-uuid-here",
  "agent_id": "spiffe://aflock.ai/agent/claude-opus/4.5/abc123",
  "identity_hash": "sha256:abc123...",
  "allowed_tools": ["Read", "Edit", "Bash"],
  "denied_tools": ["Task"],
  "limits": {
    "maxSpendUSD": { "value": 5.00, "enforcement": "fail-fast" },
    "maxTurns": { "value": 30, "enforcement": "post-hoc" }
  },
  "policy_digest": "sha256:def456..."
}
```

### Security Properties

| Property | How It Works |
|----------|-------------|
| **Algorithm confusion prevention** | Only ES256 accepted; `token.Method` checked before key use |
| **Session binding** | `aud` claim = session ID; cross-session replay rejected |
| **Policy binding** | `policy_digest` = SHA-256 of serialized policy; token invalidated if policy changes |
| **Tool-level scoping** | `allowed_tools`/`denied_tools` enforced per-request |
| **Ephemeral keys** | ECDSA P-256 key per process, never persisted to disk |
| **Graceful adoption** | Enforcement only activates after `get_token` is called |

### How It Works

1. **SessionStart** (hooks mode) or **server init** (MCP mode): An ephemeral ECDSA P-256 keypair is generated. A JWT is issued with the agent's verified identity, session ID, and policy-derived scopes.
2. **Tool calls**: Each tool handler validates the `_token` parameter — checks signature, expiry, issuer, session binding, and tool-level authorization.
3. **Token refresh**: Call the `get_token` MCP tool to get a new token (e.g., after policy changes).

## Attestation Format

Attestations follow the in-toto Statement specification:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "session-turn-5",
      "digest": { "sha256": "abc123..." }
    }
  ],
  "predicateType": "https://aflock.ai/attestations/action/v0.1",
  "predicate": {
    "agent": {
      "identity": "sha256:a1b2c3...",
      "model": "claude-opus-4-5-20251101"
    },
    "action": {
      "tool": "Bash",
      "input": "go test ./...",
      "decision": "allow"
    },
    "metrics": {
      "costUSD": 0.15,
      "tokensIn": 2500,
      "tokensOut": 800,
      "turnNumber": 5
    },
    "sessionRoot": "sha256:merkle-root..."
  }
}
```

## DSSE Envelope

Attestations are wrapped in a Dead Simple Signing Envelope:

```json
{
  "payload": "base64-encoded-attestation",
  "payloadType": "application/vnd.in-toto+json",
  "signatures": [
    {
      "keyid": "sha256:server-key-fingerprint",
      "sig": "base64-encoded-signature"
    }
  ]
}
```

## Session Merkle Trees

> **Status: Not yet implemented** — Merkle tree construction is designed but no code exists yet. See [#16](https://github.com/aflock-ai/aflock/issues/16).

By constructing a merkle tree over the session JSONL, aflock can cryptographically prove:

- **Order**: Turn *n* came after turns 0 through *n-1*
- **Completeness**: No turns were omitted
- **Distance**: Turns are contiguous (no gaps)

```
materialsFrom:
  session:
    path: "${CLAUDE_SESSION_PATH}"
    algorithm: sha256
    merkleTree: true
```

The merkle root is included in each attestation's `sessionRoot` field, enabling verification that the execution history hasn't been tampered with.

## Cross-Step Access

Using Rego evaluators, aflock can access attestations across all execution steps:

```rego
package aflock
import rego.v1

turns := [t | some t in input.attestations]
sum_spend := sum([t.predicate.metrics.costUSD | some t in turns])

deny contains msg if {
    sum_spend > input.policy.limits.maxSpendUSD.value
    msg := sprintf("Spend $%.2f exceeds $%.2f",
        [sum_spend, input.policy.limits.maxSpendUSD.value])
}
```

This enables cumulative constraint checking — verifying that the total spend across all turns doesn't exceed the limit, not just individual turns.
