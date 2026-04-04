---
sidebar_position: 2
---

# Example: Data Flow Protection

:::info Implementation Status
This example demonstrates the target policy format. **What works now:** data flow classification and flow rules for direct file operations, tool allowlists, file access rules, resource limits. **Known limitation:** Bash file-reading commands beyond the built-in set (cat, head, tail, etc.) are not analyzed for data flow — commands like `grep`, `sed`, `awk`, `cp` can bypass flow rules ([#25](https://github.com/aflock-ai/aflock/issues/25)). **SPIFFE functionaries** work for X509-SVIDs but the SPIFFE ID format in the implementation differs from the documented format.
:::

A policy preventing data exfiltration with sensitivity classification.

## Policy

```json
{
  "version": "1.0",
  "name": "data-flow-protection",
  "identity": {
    "allowedModels": ["claude-opus-*", "claude-sonnet-*"]
  },
  "limits": {
    "maxSpendUSD": { "value": 10.00, "enforcement": "fail-fast" }
  },
  "tools": {
    "allow": ["Read", "Write", "Edit", "Glob", "Grep", "Bash", "mcp__*"],
    "deny": ["Task"]
  },
  "dataFlow": {
    "classify": {
      "internal": ["mcp__internal-db__*", "Read:**/internal/**"],
      "pii": ["mcp__user-data__*", "Read:**/users/**"],
      "secrets": ["mcp__vault__*", "Read:**/.env"],
      "public": ["mcp__external-api__*", "Write:**/public/**"]
    },
    "flowRules": [
      {
        "deny": "internal->public",
        "message": "Cannot write internal data to public destinations"
      },
      {
        "deny": "pii->public",
        "message": "Cannot write PII to public destinations (GDPR/CCPA)"
      },
      {
        "deny": "secrets->public",
        "message": "Cannot expose secrets to public destinations"
      }
    ]
  },
  "files": {
    "allow": ["**/*"],
    "deny": ["**/.env", "**/secrets/**"]
  },
  "functionaries": [
    {
      "type": "spiffe",
      "trustDomain": "aflock.ai",
      "spiffeIdPattern": "spiffe://aflock.ai/agent/claude-*"
    }
  ]
}
```

## Key Features

- **Data classification**: Four sensitivity levels (internal, pii, secrets, public)
- **Flow rules**: Blocks sensitive data from reaching public destinations
- **GDPR/CCPA**: PII-to-public flow is blocked with compliance message
- **SPIFFE identity**: Agent identity verified via SPIFFE workload identity
- **MCP tools**: Allows all MCP-prefixed tools (database, vault, API access)
