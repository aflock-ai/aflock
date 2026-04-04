---
sidebar_position: 0
---

# Policies

:::info What's Working
Policy loading, signing (`aflock sign`), tool allowlists, file access rules, domain controls, and resource limit enforcement (spend, tokens, turns, time) are all fully implemented. Features marked below as WIP have types/schemas defined but the runtime enforcement code is not yet complete.
:::

An `.aflock` file is a **cryptographically signed policy** that constrains AI agent behavior. Like `package-lock.json` locks dependencies, `.aflock` locks what an agent can do.

## Why Policies?

AI agents are increasingly autonomous. They run commands, access APIs, modify files, and spawn sub-agents. Without constraints, an agent could:

- Exceed cost budgets through unbounded API usage
- Access sensitive files (credentials, environment variables)
- Execute dangerous commands (force pushes, destructive operations)
- Exfiltrate data through unrestricted network access
- Delegate unconstrained authority to sub-agents

An `.aflock` policy defines the bounds. The agent generates attestations proving it operated within those bounds. Verification ensures constraints weren't violated.

## Policy Structure

A policy is a JSON document with these sections:

```json
{
  "version": "1.0",
  "name": "policy-name",
  "expires": "2026-12-01T00:00:00Z",

  "identity": { ... },
  "limits": { ... },
  "tools": { ... },
  "files": { ... },
  "domains": { ... },
  "grants": { ... },
  "dataFlow": { ... },
  "evaluators": { ... },
  "sublayouts": [ ... ],
  "functionaries": [ ... ],
  "materialsFrom": { ... }
}
```

## Identity Constraints

Specify which agent configurations are authorized:

```json
{
  "identity": {
    "allowedModels": ["claude-opus-4-5-20251101", "claude-sonnet-4-*"],
    "allowedEnvironments": ["container:ghcr.io/org/*", "user:deploy-*"],
    "requiredTools": ["Read", "Edit"]
  }
}
```

Glob patterns enable flexible matching. An agent running a model not in `allowedModels` will be rejected.

## Resource Limits

Each limit has a value and an enforcement mode:

```json
{
  "limits": {
    "maxSpendUSD": { "value": 10.00, "enforcement": "fail-fast" },
    "maxTokensIn": { "value": 500000, "enforcement": "fail-fast" },
    "maxTurns": { "value": 50, "enforcement": "post-hoc" },
    "maxWallTimeSeconds": { "value": 3600, "enforcement": "fail-fast" },
    "maxToolCalls": { "value": 200, "enforcement": "post-hoc" }
  }
}
```

| Mode | Behavior | Use Case |
|------|----------|----------|
| `fail-fast` | Abort immediately when breached | Cost, security, time limits |
| `post-hoc` | Verify at session completion | Quality, turn counts |

## Tool Allowlists

Follow the principle of least privilege — all access denied unless explicitly granted:

```json
{
  "tools": {
    "allow": ["Read", "Edit", "Bash", "Glob", "Grep"],
    "deny": ["Task"],
    "requireApproval": ["Bash:rm -rf *", "Bash:git push --force"]
  }
}
```

- `allow`: Tools the agent can use freely
- `deny`: Tools that are always blocked
- `requireApproval`: Patterns that require human confirmation

## File Access

```json
{
  "files": {
    "allow": ["src/**", "tests/**"],
    "deny": ["**/.env", "**/secrets/**"],
    "readOnly": ["package.json", "go.mod"]
  }
}
```

## Domain Access

```json
{
  "domains": {
    "allow": ["github.com", "*.anthropic.com"],
    "deny": ["*"]
  }
}
```

## Grants

> **Status: Schema defined, runtime enforcement not yet implemented** — The `grants` policy is parsed but never evaluated at runtime. See [#22](https://github.com/aflock-ai/aflock/issues/22). **We're looking for contributors.**

Explicit authorization for resource access:

```json
{
  "grants": {
    "secrets": {
      "allow": ["vault:secret/data/readonly/*"],
      "deny": ["vault:secret/production/*"]
    },
    "apis": {
      "allow": ["https://api.anthropic.com/*"]
    },
    "storage": {
      "allow": ["s3://attestations/${RUN_ID}/*"]
    }
  }
}
```

## Signing and Immutability

Policies are signed using a DSSE (Dead Simple Signing Envelope):

```bash
aflock sign policy.aflock
```

Once signed, the agent cannot modify the policy. The signature is verified during every attestation check.

## Functionaries

Define who can sign the policy:

```json
{
  "functionaries": [
    {
      "type": "keyless",
      "issuer": "https://accounts.google.com",
      "subject": "admin@example.com"
    },
    {
      "type": "spiffe",
      "trustDomain": "aflock.ai",
      "spiffeIdPattern": "spiffe://aflock.ai/agent/claude-*"
    }
  ]
}
```

Supported types: `publickey`, `keyless` (Sigstore/OIDC), `x509`, `spiffe`.

> **Note:** `publickey` and `x509` functionaries are implemented. `keyless` (Sigstore) signing is not yet implemented ([#20](https://github.com/aflock-ai/aflock/issues/20)). `spiffe` functionaries work for X509-SVIDs; JWT-SVID support is not yet available.
