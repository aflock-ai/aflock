---
sidebar_position: 3
---

# Verification

:::caution Active Development
The 6-phase verification pipeline is partially implemented. **Phase 1 (Signature Verification)** works in the `VerifySteps` path. **Phases 2–6** (Identity, Materials Binding, Rego Evaluation, AI Evaluation, Sublayout Recursion) are designed but not yet implemented in code. See [GitHub issue #16](https://github.com/aflock-ai/aflock/issues/16) for progress. **We're looking for contributors in this area.**
:::

aflock's verification algorithm checks that an agent session complied with its policy. Verification proceeds in **six phases** — all must pass for the session to be considered compliant.

## The 6-Phase Algorithm

```
VERIFY(Policy P, Attestations A, Materials M):

  Phase 1: Signature Verification
    for each attestation a_i in A:
      if not VerifySignature(a_i, P.functionaries):
        return FAIL: "Invalid signature on attestation i"

  Phase 2: Identity Verification
    for each attestation a_i in A:
      if not MatchesIdentity(a_i.agent, P.identity):
        return FAIL: "Identity mismatch on attestation i"

  Phase 3: Materials Binding
    if P.materialsFrom.session.merkleTree:
      root = ComputeMerkleRoot(M.session)
      if root != A[n].predicate.sessionRoot:
        return FAIL: "Session merkle root mismatch"

  Phase 4: Constraint Evaluation
    for each Rego evaluator e in P.evaluators.rego:
      result = EvaluateRego(e.policy, {P, A, M})
      if result.deny is not empty:
        return FAIL: result.deny

  Phase 5: AI Evaluation
    for each AI evaluator e in P.evaluators.ai:
      result = EvaluateAI(e.prompt, e.model, M)
      if result == FAIL:
        return FAIL: "AI evaluator 'e.name' failed"

  Phase 6: Sublayout Recursion
    for each sublayout s in P.sublayouts:
      A_s = {a in A : a.prefix == s.name}
      result = VERIFY(s.policy, A_s, M)
      if result == FAIL:
        return FAIL: "Sublayout 's.name' failed"

  return PASS
```

## Phase Details

### Phase 1: Signature Verification

Every attestation must be signed by a key authorized in the policy's `functionaries` section. This ensures attestations haven't been forged or tampered with.

### Phase 2: Identity Verification

> **Status: Not yet implemented** — [#16](https://github.com/aflock-ai/aflock/issues/16)

The agent identity recorded in each attestation must match the policy's `identity` constraints (allowed models, environments, required tools).

### Phase 3: Materials Binding

> **Status: Not yet implemented** — no Merkle tree code exists yet. [#16](https://github.com/aflock-ai/aflock/issues/16)

If the policy specifies `materialsFrom.session.merkleTree`, the verifier recomputes the merkle root over the session JSONL and compares it to the root recorded in the final attestation. This proves execution ordering and completeness.

### Phase 4: Constraint Evaluation

> **Status: Not yet implemented** — no OPA/Rego integration exists yet. [#16](https://github.com/aflock-ai/aflock/issues/16)

Rego evaluators receive the full set of attestations and can compute cumulative metrics. This is where spend limits, token limits, and custom constraints are checked across all turns.

### Phase 5: AI Evaluation

> **Status: Not yet implemented** — [#16](https://github.com/aflock-ai/aflock/issues/16)

AI evaluators assess qualitative properties (code quality, test coverage, task completion) that are difficult to express in formal logic. These are probabilistic — critical constraints should use Rego.

### Phase 6: Sublayout Recursion

> **Status: Not yet implemented** — [#16](https://github.com/aflock-ai/aflock/issues/16), [#26](https://github.com/aflock-ai/aflock/issues/26)

For each sublayout (sub-agent delegation), verification recurses with the sub-agent's policy and its namespaced attestations.

## Running Verification

```bash
# Verify against policy in current directory
aflock verify --policy .aflock

# Verify with specific git tree hash
aflock verify --policy .aflock --tree-hash abc123

# Verify with custom attestation directory
aflock verify -p policy.json -a ./attestations
```

Exit code `0` = compliant. Non-zero = violations found with detailed error messages.

## Evaluators

### Rego Evaluators

> **Status: Schema defined, runtime not yet implemented** — [#16](https://github.com/aflock-ai/aflock/issues/16)

Deterministic, cross-step constraint verification:

```json
{
  "evaluators": {
    "rego": [{
      "name": "cumulative-spend-check",
      "policy": "package aflock\nimport rego.v1\n\nturns := [t | some t in input.attestations]\nsum_spend := sum([t.predicate.metrics.costUSD | some t in turns])\n\ndeny contains msg if {\n  sum_spend > input.policy.limits.maxSpendUSD.value\n  msg := sprintf(\"Spend $%.2f exceeds $%.2f\", [sum_spend, input.policy.limits.maxSpendUSD.value])\n}"
    }]
  }
}
```

### AI Evaluators

> **Status: Schema defined, runtime not yet implemented** — [#16](https://github.com/aflock-ai/aflock/issues/16)

Qualitative assessment:

```json
{
  "evaluators": {
    "ai": [{
      "name": "code-quality",
      "prompt": "PASS if code is production-ready. FAIL otherwise.",
      "model": "claude-opus-4-5-20251101"
    }]
  }
}
```

### gRPC Evaluators

> **Status: Not yet implemented** — [#21](https://github.com/aflock-ai/aflock/issues/21)

Custom evaluation logic:

```json
{
  "evaluators": {
    "grpc": [{
      "name": "custom-validator",
      "endpoint": "localhost:50051"
    }]
  }
}
```
