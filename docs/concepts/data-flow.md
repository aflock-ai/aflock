---
sidebar_position: 5
---

# Data Flow Tracking

:::info Implementation Status
Data flow classification and flow rule enforcement are implemented in the hooks handler for direct file reads/writes. Note that Bash command analysis currently has a limited set of recognized file-reading commands — some commands (e.g., `grep`, `sed`, `awk`) may not trigger data flow checks. See [#25](https://github.com/aflock-ai/aflock/issues/25).
:::

aflock can classify data by sensitivity level and enforce rules preventing data from flowing between classifications.

## Why Data Flow Tracking?

An agent might read sensitive data (PII, secrets, internal documents) and inadvertently write it to a public destination. Data flow rules prevent this at the policy level.

## Classification

Define sensitivity levels and map data sources to them:

```json
{
  "dataFlow": {
    "classify": {
      "internal": ["mcp__internal-db__*", "Read:**/internal/**"],
      "pii": ["mcp__user-data__*", "Read:**/users/**"],
      "secrets": ["mcp__vault__*", "Read:**/.env"],
      "public": ["mcp__external-api__*", "Write:**/public/**"]
    }
  }
}
```

Each classification uses glob patterns to match tool calls and file paths.

## Flow Rules

Define which data flows are prohibited:

```json
{
  "dataFlow": {
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
  }
}
```

## How It Works

1. Agent reads from a source (e.g., `Read:src/internal/config.go`)
2. aflock classifies this as `internal` data
3. Agent attempts to write to a destination (e.g., `Write:public/output.md`)
4. aflock classifies this as a `public` destination
5. Flow rule `internal->public` is triggered
6. Action is **blocked** with the configured message

## Use Cases

| Rule | Compliance |
|------|-----------|
| `pii->public` | GDPR, CCPA |
| `secrets->public` | Security best practices |
| `internal->public` | Data governance |
| `secrets->*` | Zero-trust secret handling |
