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

## Signing and trust

aflock signs `.aflock` policies as DSSE envelopes using a Sigstore Fulcio-issued
short-lived certificate bound to the signer's OIDC identity. There's no
long-lived signing key to lose. Verification at `policy.Load` time chains the
embedded cert to the Sigstore root and matches it against an operator-controlled
`aflock-trust.json`.

### Sign

```bash
# In GitHub Actions (or any OIDC-aware CI), with id-token: write:
GITHUB_ACTIONS=true aflock sign .aflock      # writes .aflock.signed

# Locally, providing a token out-of-band:
FULCIO_TOKEN=<oidc-jwt> aflock sign .aflock
```

The produced `.aflock.signed` is a DSSE envelope
(`payloadType: application/vnd.aflock.policy+json`) containing the policy bytes,
the Fulcio leaf cert, and the signature.

### Trust config

Trust roots live in `aflock-trust.json`, resolved in this order (first hit wins):

1. `$AFLOCK_TRUST_CONFIG` (explicit operator override)
2. `<policy_dir>/aflock-trust.json` (per-policy, version-controlled)
3. `~/.aflock/trust.json` (per-user default)

```json
{
  "version": "1",
  "verifiers": [
    {
      "type": "sigstore",
      "issuer": "https://token.actions.githubusercontent.com",
      "subjectPattern": "https://github.com/org/repo/.github/workflows/sign-policy.yml@refs/heads/main"
    }
  ]
}
```

`subjectPattern` supports glob via `github.com/gobwas/glob`. `FulcioRootPath` can
override the embedded Sigstore production root for self-hosted Sigstore
deployments.

The trust config is **not** part of the policy — an attacker who can write the
policy must not be able to declare their own trust root. Keep it in
operator-controlled locations.

### Verify

```bash
aflock policy verify .aflock.signed
# exits 0 + prints SignatureInfo on success, 1 on failure
```

### Enforcement modes

By default, `policy.Load` warns when loading an unsigned policy but still
proceeds (so existing unsigned deployments keep working through migration).
Set `AFLOCK_REQUIRE_SIGNED_POLICY=1` to refuse unsigned policies.

Any DSSE-envelope-shaped file is treated as "must verify or hard-fail." This
closes the silent-degrade bug where passing an envelope to a pre-signing
`policy.Load` returned an empty allow-most policy.

### TSA timestamping

Every signed envelope bundles an RFC 3161 timestamp from the Sigstore
Public Good TSA (`https://timestamp.sigstore.dev/api/v1/timestamp`). Verifiers
use the TSA-attested time when checking the Fulcio leaf cert's validity, so
signatures stay verifiable past the cert's ~10-minute window. Sign once,
verify forever.

`$AFLOCK_TSA_URL` overrides the endpoint for self-hosted Sigstore.
`$AFLOCK_TSA_DISABLE=1` skips timestamping at sign time (the resulting
envelope only verifies inside the Fulcio cert window — only useful for
air-gapped tests).

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

> **Note:** `publickey`, `x509`, and `keyless` (Sigstore/Fulcio) functionaries are implemented. `spiffe` functionaries work for X509-SVIDs; JWT-SVID support is not yet available.
