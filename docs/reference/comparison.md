---
sidebar_position: 2
---

# Comparison with Related Work

How aflock compares to other AI agent constraint systems.

## Feature Comparison

| Capability | Omega | VeriGuard | ARIA | ShieldAgent | **aflock** |
|-----------|-------|-----------|------|-------------|--------|
| Signed policy file | ? | No | No | No | **Yes** |
| Identity derivation | TEE | No | DID | No | **PID+MCP** |
| Cryptographic attestations | Yes | No | VC | No | **in-toto** |
| Cross-step verification | ? | No | No | No | **Rego** |
| Spend/token limits | No | No | No | No | **Yes** |
| Sub-agent delegation | ? | No | Yes | No | **sublayouts** |
| Session ordering proofs | No | No | No | No | **Merkle** |
| Software-only (no TEE) | No | Yes | Yes | Yes | **Yes** |

## Detailed Comparison

### Omega — Trusted Execution

Omega provides strong isolation through confidential VMs and GPUs (AMD SEV-SNP, NVIDIA H100). While offering hardware-backed security, this approach requires specialized infrastructure unavailable in many deployment contexts. aflock provides a **software-only** alternative with cryptographic (rather than hardware) guarantees.

### VeriGuard — Formal Verification

VeriGuard applies formal verification to agent policies using Hoare triples, proving safety properties before execution. This approach **complements** aflock: VeriGuard could verify policy correctness while aflock provides runtime attestation that the policy was followed.

### ARIA — Identity Framework

ARIA proposes a graph-native identity model with DIDs and verifiable credentials. While powerful for complex delegation, ARIA's graph-based approach adds complexity that may be unnecessary for simpler deployments. aflock uses a simpler derived-identity model inspired by SPIFFE/SPIRE.

### ShieldAgent — Runtime Guardrails

ShieldAgent and AgentGuardian provide runtime policy enforcement but **lack cryptographic attestation**. These systems cannot prove compliance after the fact — a critical requirement for regulated industries.

### Macaroons / Biscuit — Token Delegation

Google's Macaroons and Biscuit tokens provide elegant primitives for offline attenuation and delegation. aflock could adopt these as transport mechanisms while providing the higher-level policy semantics and attestation framework.

## Key Differentiators

aflock is unique in combining:

1. **Software-only**: No TEE or HSM required
2. **Signed policies**: Immutable constraint files
3. **Derived identity**: Server-verified, not self-declared
4. **in-toto attestations**: Industry-standard format
5. **Cross-step Rego**: Cumulative constraint checking
6. **Sublayouts**: Hierarchical sub-agent delegation
7. **Merkle proofs**: Session ordering and completeness

:::caution
Some features in the comparison table above reflect the target design. In the current alpha, Rego evaluators, Merkle proofs, full sublayout recursion, and identity verification are not yet implemented at runtime. See the [implementation status](https://github.com/aflock-ai/aflock/issues) for details.
:::
