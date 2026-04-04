---
sidebar_position: 4
---

# Sublayouts

:::caution Active Development
The sublayout security model is partially implemented. **Numeric limit attenuation** (invariant 1) and **metric accumulation** (invariant 2) work. **Attestation namespacing** (invariant 3), **recursive verification** (invariant 4), the `inherit` field, and constraint enforcement during sub-agent execution are not yet implemented. See [#26](https://github.com/aflock-ai/aflock/issues/26). **We're looking for contributors in this area.**
:::

Inspired by [in-toto sublayouts](https://github.com/in-toto/specification), aflock supports **hierarchical sub-agent delegation** with mandatory constraint attenuation.

## The Problem

When an agent spawns sub-agents (e.g., a research agent, a testing agent), how do you ensure the sub-agent operates within bounds? Without sublayouts, a sub-agent could inherit the parent's full authority.

## How Sublayouts Work

```json
{
  "sublayouts": [
    {
      "name": "research-agent",
      "policy": "./policies/research.aflock",
      "limits": { "maxSpendUSD": { "value": 2.00 } },
      "inherit": ["domains", "functionaries"],
      "attestationPrefix": "research-"
    },
    {
      "name": "testing-agent",
      "policy": "./policies/testing.aflock",
      "limits": { "maxSpendUSD": { "value": 3.00 } },
      "inherit": ["files", "domains"],
      "attestationPrefix": "testing-"
    }
  ]
}
```

## Enforced Invariants

### 1. Attenuation
Sub-agent limits must be **stricter** than (or equal to) parent limits. A parent with `maxSpendUSD: 10.00` cannot create a sub-agent with `maxSpendUSD: 15.00`.

### 2. Accumulation
Sub-agent spend counts toward the parent's totals. If the research agent spends $1.50, that reduces the parent's remaining budget by $1.50.

### 3. Namespacing
Sub-agent attestations are prefixed with the sublayout name:
- `research-turn-1.json`
- `research-turn-2.json`
- `testing-turn-1.json`

### 4. Recursion
Verification recurses into sublayouts. The parent session isn't compliant unless all sub-agent sessions are also compliant.

## Inheritance

The `inherit` field specifies which policy sections the sub-agent inherits from the parent:

| Inheritable | What It Means |
|-------------|---------------|
| `domains` | Sub-agent uses parent's domain allowlist |
| `functionaries` | Sub-agent uses parent's signing authorities |
| `files` | Sub-agent uses parent's file access rules |

Sections not inherited must be defined in the sub-agent's own policy.

## Verification Flow

```
Parent Policy Verification
  |
  +-- Phase 1-5 (parent attestations)
  |
  +-- Phase 6: Sublayout Recursion
       |
       +-- research-agent
       |    |
       |    +-- Load ./policies/research.aflock
       |    +-- Filter attestations with prefix "research-"
       |    +-- VERIFY(research.aflock, research-attestations, M)
       |
       +-- testing-agent
            |
            +-- Load ./policies/testing.aflock
            +-- Filter attestations with prefix "testing-"
            +-- VERIFY(testing.aflock, testing-attestations, M)
```

All sublayouts must pass for the parent verification to succeed.
