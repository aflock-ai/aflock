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
    "deny": ["Task", "Agent"],
    "requireApproval": ["Bash:rm -rf *", "Bash:git push --force"]
  }
}
```

- `allow`: tools the agent can use freely. A non-empty `allow` list is itself a restriction — any tool not listed is denied.
- `deny`: tools that are always blocked.
- `requireApproval`: patterns that require human confirmation.

**Precedence:** `deny` > `requireApproval` > `allow`. A tool in both `allow` and `deny` is denied.

**Matching:** entries are glob-matched. A wildcard-free literal (e.g. `Task`) matches only that exact tool name — so `deny: ["Task"]` does **not** cover `Agent`. Use `Tool:pattern` to scope by command/argument (e.g. `Bash:rm -rf *`).

### Subagent trust boundary (issue #100)

`Task` and `Agent` are **subagent-spawning** tools, and they are two distinct names — deny **both**. This boundary matters because a spawned subagent runs Claude Code's **native** `Bash`/`Write`/`Edit`, which route through Claude Code's harness, **not** through aflock:

- **MCP mode** (`aflock serve`): a native subagent tool call never reaches aflock at all, so aflock cannot see or block it. `tools.deny` is moot for a native spawn here — deny `Task`/`Agent` in `.claude/settings.local.json` (`permissions.deny`) so Claude Code itself refuses the spawn.
- **Hook mode** (`aflock hook`): aflock's `PreToolUse` can **deny the spawn** outright, or — if the policy declares [sublayouts](sublayouts.md) — require the spawn to match a declared, attenuated sublayout, and it accounts for the child after the fact at `SubagentStop`. It does **not** intercept the subagent's individual native tool calls in real time: Claude Code does not fire parent hooks inside subagents ([claude-code#27661](https://github.com/anthropics/claude-code/issues/27661), [#34692](https://github.com/anthropics/claude-code/issues/34692)).

**Safe patterns:**

- **Forbid delegation (airtight):** deny `Task` and `Agent` in the policy and, for MCP mode, in `.claude/settings.local.json`. No spawn means no bypass.
- **Constrained delegation:** allow the spawn but declare `sublayouts` (hook mode) so the child is attenuated and bound to a named slot. The child's native calls are still not enforced in real time — only delegate to subagents you trust, and audit them via the child's own attestations.

aflock surfaces this trap two ways: it logs a startup **WARNING** (`AFLOCK_STRICT=1` refuses to start) when a policy permits `Task`/`Agent` without declaring sublayouts, and it tags `Task`/`Agent` attestations with `trustBoundaryCrossing` so `aflock verify` flags a session that delegated work out of the enforcement plane. The tag's *absence* does not prove no delegation occurred.

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

Two signer paths; pick by flag/env:

**Sigstore keyless (default).** Fulcio issues an ephemeral cert bound to the
caller's OIDC identity; aflock bundles an RFC 3161 timestamp from the
Sigstore TSA so the signature outlives the cert's 10-minute window.

```bash
GITHUB_ACTIONS=true aflock sign .aflock         # in CI with id-token: write
FULCIO_OIDC_ISSUER=https://oauth2.sigstore.dev/auth aflock sign .aflock  # local browser flow
FULCIO_TOKEN=<jwt> aflock sign .aflock          # OIDC token provided out-of-band
```

**Raw key (`--key` / `$AFLOCK_SIGNING_KEY`).** Operator-managed PEM private
key (ECDSA, RSA, or Ed25519). No network at sign time, no TSA needed (raw
keys don't have a Fulcio-style validity window).

```bash
aflock sign .aflock --key ./team-signing.priv.pem
```

The produced `.aflock.signed` is a DSSE envelope
(`payloadType: application/vnd.aflock.policy+json`). For Sigstore: contains
the Fulcio leaf cert + TSA timestamp. For raw-key: just the signature + keyid.

### Trust config

Trust roots live in `aflock-trust.json`, resolved in this order (first hit wins):

1. `$AFLOCK_TRUST_CONFIG` (explicit operator override)
2. `~/.aflock/trust.json` (per-user default)

There is intentionally NO `<policy_dir>/aflock-trust.json` fallback. If trust
lived next to the policy, anyone with write access to the policy could also
rewrite its trust root — which collapses the "signed by authorized
principals" guarantee into ordinary repo-write access. Operators must point
`$AFLOCK_TRUST_CONFIG` at a path the policy author can't reach, or rely on
the per-user `~/.aflock/trust.json`.

```json
{
  "version": "1",
  "verifiers": [
    {
      "type": "sigstore",
      "issuer": "https://token.actions.githubusercontent.com",
      "subjectPattern": "https://github.com/org/repo/.github/workflows/sign-policy.yml@refs/heads/main"
    },
    {
      "type": "pubkey",
      "keyPath": "/etc/aflock/team-signing.pub.pem"
    }
  ]
}
```

`sigstore` verifiers match Fulcio-issued certs against `{Issuer,
SubjectPattern}`. `subjectPattern` is **exact-match** against the cert's
SAN email (for human OIDC identities like Google/GitHub login) or SAN URI
(for CI workflow identities) — rookery's underlying `CertConstraint` does
not glob-match SAN fields. Wildcards like `*@gmail.com` will NOT match;
pin the exact identity instead. `FulcioRootPath` overrides the embedded
production root for self-hosted Sigstore.

`pubkey` verifiers load a PEM-encoded public key from `KeyPath`. ECDSA, RSA,
and Ed25519 are accepted. Optional `keyid` enforces an exact SHA-256
fingerprint match — leave unset to accept any signature that verifies against
the loaded key.

Multiple verifiers can coexist; a signature passing any one of them is
accepted.

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

Self-hosted TSA must also pin TSA roots at verify time. Set
`tsaRootPath` on the trust-config verifier (or `$AFLOCK_TSA_ROOTS`) to a
PEM chain that matches the signing TSA; otherwise verification falls back
to the embedded Sigstore production chain and timestamp validation fails.

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
