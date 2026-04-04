---
sidebar_position: 1
---

# Example: Compliance Evaluation

:::info Implementation Status
This example demonstrates the target policy format. **What works now:** tool allowlists, file access rules, resource limits, and identity constraints (model matching). **Not yet implemented:** `grants` enforcement ([#22](https://github.com/aflock-ai/aflock/issues/22)), Rego/AI evaluator execution ([#16](https://github.com/aflock-ai/aflock/issues/16)), and sublayout recursive verification ([#26](https://github.com/aflock-ai/aflock/issues/26)). Sublayout limit attenuation and accumulation work.
:::

A policy for automated OSCAL control assessment with sub-agent delegation.

## Policy

```json
{
  "version": "1.0",
  "name": "oscal-control-evaluation",
  "expires": "2026-06-01T00:00:00Z",
  "identity": {
    "allowedModels": ["claude-opus-4-5-*"],
    "allowedEnvironments": ["container:ghcr.io/testifysec/*"],
    "requiredTools": ["Read", "Glob"]
  },
  "grants": {
    "secrets": {
      "allow": ["vault:secret/data/compliance/*"],
      "deny": ["vault:secret/data/production/*"]
    },
    "apis": {
      "allow": ["https://api.anthropic.com/*", "https://csrc.nist.gov/*"]
    }
  },
  "limits": {
    "maxSpendUSD": { "value": 25.00, "enforcement": "fail-fast" },
    "maxTokensIn": { "value": 1000000, "enforcement": "post-hoc" },
    "maxTurns": { "value": 100, "enforcement": "post-hoc" },
    "maxWallTimeSeconds": { "value": 7200, "enforcement": "fail-fast" }
  },
  "tools": {
    "allow": ["Read", "Glob", "Grep", "WebFetch", "Task"],
    "deny": ["Edit", "Write"],
    "requireApproval": ["Bash:curl *"]
  },
  "evaluators": {
    "rego": [
      {
        "name": "all-controls-assessed",
        "policy": "deny contains msg if { count(missing_controls) > 0 }"
      }
    ],
    "ai": [
      {
        "name": "assessment-quality",
        "prompt": "PASS if each control assessment includes evidence references and remediation guidance. FAIL otherwise.",
        "model": "claude-opus-4-5-20251101"
      }
    ]
  },
  "sublayouts": [
    {
      "name": "evidence-collector",
      "policy": "./policies/evidence.aflock",
      "limits": { "maxSpendUSD": { "value": 5.00 } }
    }
  ]
}
```

## Key Features

- **Read-only**: Agent can read but not modify files (assessment only)
- **Containerized**: Must run in a specific container image
- **Sub-agent delegation**: Evidence collector with a $5 sub-budget
- **Rego verification**: Ensures all controls were assessed
- **AI quality check**: Evaluates assessment depth and evidence references
- **API access**: Restricted to Anthropic API and NIST resources
