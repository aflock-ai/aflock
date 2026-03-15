---
sidebar_position: 2
---

# Attestations

:::info Implementation Status
Attestation signing using DSSE envelopes is implemented in both **MCP server mode** and **hooks mode** ([#17](https://github.com/aflock-ai/aflock/issues/17)). Every `PostToolUse` hook generates a signed in-toto v1 attestation with the `action/v0.1` predicate type. Signing uses SPIRE X509-SVIDs when available, or an ephemeral ECDSA key as fallback. **JWT-based agent authorization** ([#19](https://github.com/aflock-ai/aflock/issues/19)) and the **JWT + Signing Key Separation** model described below are not yet implemented. Session Merkle trees are designed but not yet implemented. **We're looking for contributors in these areas.**
:::

Every agent action produces a **cryptographically signed attestation** — an unforgeable record of what happened. aflock uses the [in-toto](https://in-toto.io/) attestation format wrapped in DSSE envelopes.

## JWT and Signing Key Separation

> **Status: Not yet implemented** — Currently the agent directly holds the signing key. See [#19](https://github.com/aflock-ai/aflock/issues/19).

A critical security property is the separation between **authorization** (what the agent is allowed to do) and **attestation** (proof of what the agent did):

| Component | Held By | Purpose |
|-----------|---------|---------|
| **JWT** | Agent | Short-lived authorization token |
| **Signing Key** | Server | Signs all attestations |

The agent presents its JWT when requesting actions, but all attestations are signed by a key the agent never sees. This ensures that **even a compromised agent cannot forge attestations** claiming compliant behavior.

### JWT Structure

```json
{
  "sub": "sha256:a1b2c3...",
  "iat": 1737200000,
  "exp": 1737203600,
  "grants": {
    "tools": ["Read", "Edit", "Bash"],
    "files": { "allow": ["src/**"], "deny": ["**/.env"] },
    "limits": { "maxSpendUSD": 10.00 }
  }
}
```

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
