---
sidebar_position: 1
---

# Agent Identity

:::caution Active Development
The identity derivation model described here is the target design. The current implementation uses **process-tree heuristics** (`os.Getppid()` and `ps`) rather than kernel-level socket credentials (`SO_PEERCRED`/`LOCAL_PEERCRED`). The MCP server currently uses stdio transport, not Unix domain sockets. See [#24](https://github.com/aflock-ai/aflock/issues/24). The SPIFFE ID format in the implementation also differs from what's documented here. **We're looking for contributors in this area.**
:::

A core insight of aflock is that agent identity should be **derived from introspectable properties** rather than assigned. The agent cannot lie about its identity because the server independently verifies all components.

## Identity Derivation

When an agent connects to the aflock server via MCP over a Unix domain socket, the server obtains the connecting process's PID through `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` (macOS).

> **Current implementation note:** The server currently uses process-tree walking (`os.Getppid()`) over stdio transport rather than socket credentials. See [#24](https://github.com/aflock-ai/aflock/issues/24).

From the PID, the server introspects:

| Component | Source | Example |
|-----------|--------|---------|
| **Binary path** | `/proc/PID/cmdline` | `/usr/bin/claude-code` |
| **User/Group ID** | Socket credentials | `uid:501` |
| **Container ID** | `/proc/PID/cgroup` | `container:abc123` |
| **Environment** | `/proc/PID/environ` | `CLAUDE_SESSION_ID=xyz` |
| **Model** | MCP handshake | `claude-opus-4-5-20251101` |
| **Tools** | MCP capabilities | `[Read, Edit, Bash]` |
| **Policy** | `.aflock` in agent's cwd | `sha256:def456...` |

Combined, the server computes:

```
AgentIdentity = SHA256(model || env || tools || policyDigest || parent)
```

## Why Derived Identity?

This approach mirrors [SPIRE's workload attestation](https://spiffe.io/), where identity emerges from verifiable properties rather than self-declaration.

| Approach | Problem |
|----------|---------|
| Self-declared identity | Agent can lie |
| Token-based identity | Tokens can be stolen |
| **Derived identity** | Server verifies independently |

The agent connects, the server inspects the process, and identity is computed. No trust in the agent required.

## SPIRE as Reference Architecture

aflock's identity model is directly inspired by SPIRE (SPIFFE Runtime Environment):

| SPIRE Concept | aflock Equivalent |
|---------------|-------------------|
| Workload | AI Agent (Claude Code) |
| SPIRE Agent | aflock MCP Server |
| Workload API | MCP Protocol |
| Workload Attestor | Agent Identity Discovery |
| SVID | Agent Signing Key |
| Registration Entry | `.aflock` Policy |

SPIRE's attestors that aflock reuses conceptually:

- **unix**: PID, UID, GID, binary path
- **docker**: Container ID, image digest
- **k8s**: Pod, namespace, service account

## Identity Hash

The identity hash is deterministic:

1. Changes if any component changes (different model = different identity)
2. Can be verified by re-computing from components
3. Is unique per agent configuration

```
Agent A: claude-opus + container:abc + [Read,Edit,Bash] + policy:sha256:xxx
  -> Identity: sha256:a1b2c3...

Agent B: claude-sonnet + container:abc + [Read,Edit,Bash] + policy:sha256:xxx
  -> Identity: sha256:d4e5f6...  (different model = different identity)
```

## Sub-Agent Identity

When an agent spawns a sub-agent, the parent's identity is included in the child's identity computation:

```
SubAgentIdentity = SHA256(model || env || tools || policyDigest || parentIdentity)
```

This creates a chain of identity that can be verified during sublayout recursion.

## SPIFFE ID Format

Agent identities can be expressed as SPIFFE IDs:

```
spiffe://aflock.ai/agent/sha256:a1b2c3.../session/xyz
```

This enables integration with existing SPIFFE/SPIRE infrastructure for workload identity federation.
