---
sidebar_position: 1
---

# Policy Schema

:::info Implementation Status
The schema below represents the full target format. Fields that are parsed but **not yet enforced at runtime**: `expires` ([#18](https://github.com/aflock-ai/aflock/issues/18)), `grants` ([#22](https://github.com/aflock-ai/aflock/issues/22)), `evaluators.grpc` ([#21](https://github.com/aflock-ai/aflock/issues/21)), `evaluators.rego` and `evaluators.ai` at verification time ([#16](https://github.com/aflock-ai/aflock/issues/16)), `materialsFrom.session.merkleTree`, and `sublayouts.inherit`/`sublayouts.attestationPrefix` ([#26](https://github.com/aflock-ai/aflock/issues/26)).
:::

Complete reference for the `.aflock` policy file format.

## Full Schema

```json
{
  "version": "1.0",
  "name": "string (required)",
  "expires": "ISO-8601 datetime (optional)",

  "identity": {
    "allowedModels": ["glob-pattern", ...],
    "allowedEnvironments": ["glob-pattern", ...],
    "requiredTools": ["tool-name", ...]
  },

  "limits": {
    "maxSpendUSD": { "value": 0.00, "enforcement": "fail-fast|post-hoc" },
    "maxTokensIn": { "value": 0, "enforcement": "fail-fast|post-hoc" },
    "maxTokensOut": { "value": 0, "enforcement": "fail-fast|post-hoc" },
    "maxTurns": { "value": 0, "enforcement": "fail-fast|post-hoc" },
    "maxWallTimeSeconds": { "value": 0, "enforcement": "fail-fast|post-hoc" },
    "maxToolCalls": { "value": 0, "enforcement": "fail-fast|post-hoc" }
  },

  "tools": {
    "allow": ["tool-name|glob", ...],
    "deny": ["tool-name|glob", ...],
    "requireApproval": ["tool:pattern", ...]
  },

  "files": {
    "allow": ["glob-pattern", ...],
    "deny": ["glob-pattern", ...],
    "readOnly": ["glob-pattern", ...]
  },

  "domains": {
    "allow": ["domain|glob", ...],
    "deny": ["domain|glob", ...]
  },

  "grants": {
    "secrets": { "allow": ["pattern", ...], "deny": ["pattern", ...] },
    "apis": { "allow": ["url-pattern", ...] },
    "storage": { "allow": ["uri-pattern", ...] }
  },

  "dataFlow": {
    "classify": {
      "label": ["source-pattern", ...]
    },
    "flowRules": [
      { "deny": "source->destination", "message": "string" }
    ]
  },

  "materialsFrom": {
    "session": {
      "path": "string",
      "algorithm": "sha256",
      "merkleTree": true
    },
    "git": {
      "treeHash": "string",
      "branch": "string"
    }
  },

  "requiredAttestations": ["attestation-name", ...],

  "evaluators": {
    "rego": [
      { "name": "string", "policy": "rego-source" }
    ],
    "ai": [
      { "name": "string", "prompt": "string", "model": "string" }
    ],
    "grpc": [
      { "name": "string", "endpoint": "host:port" }
    ]
  },

  "sublayouts": [
    {
      "name": "string",
      "policy": "path-to-policy",
      "limits": { ... },
      "inherit": ["section-name", ...],
      "attestationPrefix": "string"
    }
  ],

  "functionaries": [
    {
      "type": "publickey|keyless|x509|spiffe",
      "...type-specific-fields": "..."
    }
  ]
}
```

## Field Reference

### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Schema version. Currently `"1.0"` |
| `name` | string | Yes | Human-readable policy name |
| `expires` | string | No | ISO-8601 expiration datetime |

### Limits

| Field | Type | Description |
|-------|------|-------------|
| `maxSpendUSD` | Limit | Maximum USD spend |
| `maxTokensIn` | Limit | Maximum input tokens |
| `maxTokensOut` | Limit | Maximum output tokens |
| `maxTurns` | Limit | Maximum conversation turns |
| `maxWallTimeSeconds` | Limit | Maximum wall clock time |
| `maxToolCalls` | Limit | Maximum tool invocations |

Each limit is an object: `{ "value": number, "enforcement": "fail-fast" | "post-hoc" }`

### Enforcement Modes

| Mode | Behavior | Check Timing |
|------|----------|-------------|
| `fail-fast` | Abort immediately | Every action |
| `post-hoc` | Verify at end | Final verification |

### Functionary Types

**Public Key:**
```json
{ "type": "publickey", "publickeyid": "SHA256_OF_KEY" }
```

**Keyless (Sigstore):**
```json
{
  "type": "keyless",
  "issuer": "https://accounts.google.com",
  "subject": "user@example.com"
}
```

**SPIFFE:**
```json
{
  "type": "spiffe",
  "trustDomain": "aflock.ai",
  "spiffeIdPattern": "spiffe://aflock.ai/agent/claude-*"
}
```

**X.509:**
```json
{
  "type": "x509",
  "commonName": "*.example.com",
  "organizations": ["Example Corp"]
}
```
