---
sidebar_position: 0
---

# Example: Feature Development

:::info Implementation Status
This example demonstrates the target policy format. **What works now:** tool allowlists, file access rules, resource limits (spend, tokens, turns, time), and `requireApproval` patterns. **Not yet implemented:** `requiredAttestations` enforcement, Rego evaluator execution, and AI evaluator execution. These are tracked in [#16](https://github.com/aflock-ai/aflock/issues/16) and [#17](https://github.com/aflock-ai/aflock/issues/17).
:::

A policy for constraining an AI agent implementing features in a todo app.

## Policy

```json
{
  "version": "1.0",
  "name": "todo-app-feature-verification",
  "expires": "2026-03-01T00:00:00Z",
  "limits": {
    "maxSpendUSD": { "value": 10.00, "enforcement": "fail-fast" },
    "maxTokensIn": { "value": 300000, "enforcement": "fail-fast" },
    "maxTokensOut": { "value": 75000, "enforcement": "post-hoc" },
    "maxTurns": { "value": 30, "enforcement": "post-hoc" },
    "maxWallTimeSeconds": { "value": 1800, "enforcement": "fail-fast" },
    "maxToolCalls": { "value": 150, "enforcement": "post-hoc" }
  },
  "tools": {
    "allow": ["Read", "Edit", "Write", "Glob", "Grep", "Bash", "Task"],
    "requireApproval": ["Bash:rm -rf *", "Write:*.env*"]
  },
  "files": {
    "allow": ["src/**", "tests/**", "e2e/**", "playwright/**"],
    "deny": ["**/.env", "**/secrets/**", "**/node_modules/**"],
    "readOnly": ["package-lock.json", "yarn.lock"]
  },
  "requiredAttestations": [
    "unit-tests",
    "integration-tests",
    "e2e-tests",
    "uat-screenshots"
  ],
  "evaluators": {
    "rego": [
      {
        "name": "all-tests-passed",
        "policy": "package aflock\nimport rego.v1\n\nfailed := [t | some t in input.attestations; t.name == \"test-result\"; t.predicate.exitCode != 0]\ndeny contains msg if {\n  count(failed) > 0\n  msg := sprintf(\"%d tests failed\", [count(failed)])\n}"
      }
    ],
    "ai": [
      {
        "name": "test-coverage-quality",
        "prompt": "PASS if unit, integration, and E2E tests cover all CRUD operations with meaningful assertions. FAIL if only happy paths are tested.",
        "model": "claude-opus-4-5-20251101"
      },
      {
        "name": "code-quality",
        "prompt": "PASS if functions are under 50 lines, no security issues (XSS, injection), and state management is predictable. FAIL otherwise.",
        "model": "claude-opus-4-5-20251101"
      }
    ]
  }
}
```

## What This Policy Does

- **Spend cap**: $10 max, abort immediately if exceeded
- **Time limit**: 30 minutes wall time
- **File access**: Only `src/`, `tests/`, `e2e/`, `playwright/`
- **Protected files**: `.env`, secrets, `node_modules` blocked; lock files read-only
- **Required testing**: Agent must produce unit, integration, E2E tests and UAT screenshots
- **Quality checks**: AI evaluates test coverage and code quality post-hoc
