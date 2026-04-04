---
sidebar_position: 3
title: Specification
---

# AgentFlow Lock (`.aflock`) Specification

**Version:** 1.0
**Status:** Draft
**Last Updated:** 2026-01-18

## Overview

An `.aflock` file is a **cryptographically signed policy** that constrains AI agent behavior. Like `package-lock.json` locks dependencies, `.aflock` locks agent execution parameters. The agent must generate attestations proving it operated within bounds, and verification ensures constraints weren't violated.

**Key insight**: Combine Judge's execution tracking with ai-notary's attestation model and go-witness cross-step access for cumulative constraint checking.

## Architecture

![Architecture Overview](/img/diagrams/architecture-overview.svg)

## Design Principles

### 1. Attestation Generation is Agent-Driven

The policy specifies **which attestations are required**, not **when** to generate them. The agent is responsible for satisfying policy requirements. This is more flexible than fixed checkpoints (per-turn, per-tool-call) because the agent can batch or stream attestations as needed.

### 2. Configurable Enforcement Modes

Each limit can specify its enforcement mode:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `fail-fast` | Abort immediately when breached | Cost limits, security constraints |
| `post-hoc` | Verify at completion | Quality metrics, turn counts |

### 3. Cross-Step Verification

Using go-witness `feat/cross-step-attestation-access`, Rego policies can access all turn attestations to compute cumulative metrics.

### 4. Agent Identity

An agent's cryptographic identity is derived from its configuration, not assigned statically. This identity determines:
- What the agent can **sign** (attestations)
- What resources the agent can **access** (files, APIs, secrets)

#### Identity Components

| Component | Description | Example |
|-----------|-------------|---------|
| **Model** | The AI model powering the agent | `claude-opus-4-5-20251101` |
| **Environment** | Execution context (container, host, user) | `container:abc123`, `user:ci-bot` |
| **Tools** | Set of tools the agent has access to | `[Read, Edit, Bash, WebFetch]` |
| **Policy** | The .aflock policy constraining the agent | `sha256:def456...` |
| **Parent** | If spawned as sub-agent, parent's identity | `agent:parent-xyz` |

#### Identity Derivation

The agent identity is computed as a hash of its configuration:

```
AgentIdentity = SHA256(
    model ||
    environment ||
    sorted(tools) ||
    policyDigest ||
    parentIdentity
)
```

This produces a deterministic identity that:
1. Changes if any component changes
2. Can be verified by re-computing from components
3. Is unique per agent configuration

#### Cryptographic Key Assignment

Each unique agent identity maps to a cryptographic key:

![Identity Derivation](/img/diagrams/identity-derivation.svg)

#### SPIRE Agent as Reference Architecture

The [SPIRE Agent](https://github.com/spiffe/spire) provides a production-ready model for ai-notary. SPIRE solves the same fundamental problem: attesting workloads and issuing identity credentials based on introspection.

**SPIRE Agent Architecture:**

![SPIRE Architecture Mapping](/img/diagrams/spire-architecture.svg)

**Mapping SPIRE → ai-notary:**

| SPIRE Concept | ai-notary Equivalent |
|---------------|---------------------|
| Workload | AI Agent (Claude Code) |
| SPIRE Agent | ai-notary MCP Server |
| Workload API | MCP Protocol |
| Workload Attestor | Agent Identity Discovery (PID → model, tools, policy) |
| SVID | Agent Signing Key |
| Registration Entry | `.aflock` Policy |
| SPIRE Server | (optional) Central policy/key server |

**SPIRE Attestors to Reuse:**

| Attestor | What it Provides | ai-notary Use |
|----------|------------------|---------------|
| `unix` | PID, UID, GID, binary path | Base identity |
| `docker` | Container ID, image digest | Container environment |
| `k8s` | Pod, namespace, service account | K8s environment |

**Implementation Starting Point:**

```go
// SPIRE's workload attestor interface (simplified)
type Attestor interface {
    Attest(ctx context.Context, pid int32) ([]*Selector, error)
}

// ai-notary equivalent
type AgentAttestor interface {
    Attest(ctx context.Context, pid int32) (*AgentIdentity, error)
}

// AgentIdentity extends SPIRE's selectors with AI-specific fields
type AgentIdentity struct {
    // From SPIRE-style attestors
    PID         int32
    UID         int32
    BinaryPath  string
    ContainerID string  // if in container

    // AI-specific
    Model       string  // claude-opus-4, etc.
    Tools       []string
    PolicyDigest string
    SessionID   string
    ParentAgent *AgentIdentity  // if sub-agent
}
```

**Key SPIRE Code to Reference:**

| Component | SPIRE Location | Purpose |
|-----------|----------------|---------|
| Unix attestor | `pkg/agent/attestor/workload/unix.go` | PID introspection |
| Docker attestor | `pkg/agent/attestor/workload/docker.go` | Container identity |
| Workload API | `pkg/agent/endpoints/workload/` | Client connection handling |
| SVID rotation | `pkg/agent/svid/` | Key lifecycle |

**Why Start with SPIRE:**

1. **Battle-tested**: SPIRE is CNCF graduated, production-ready
2. **Attestor framework**: Pluggable attestors for different environments
3. **Key rotation**: Built-in SVID rotation and caching
4. **Security model**: Well-documented trust boundaries
5. **Go codebase**: Same language as ai-notary

**aflock Extensions Beyond SPIRE:**

| Feature | SPIRE | aflock |
|---------|-------|--------|
| Protocol | gRPC | MCP (JSON-RPC) |
| Identity | SPIFFE ID (URI) | Agent Identity Hash |
| Policy | Registration entries | `.aflock` files |
| Attestation | SVIDs only | in-toto attestations |
| Model awareness | ❌ | ✓ Model in identity |
| Tool awareness | ❌ | ✓ Tools in identity |
| Sublayouts | ❌ | ✓ Sub-agent delegation |

#### Agent Credential Model: JWT + Signing Key Separation

Agents receive a **JWT** for authentication, but attestations are signed by a **key they cannot access**. This separation is critical for security.

![Credential Model](/img/diagrams/credential-model.svg)

**JWT Structure (Implemented):**

```json
{
  "header": {
    "alg": "ES256",
    "typ": "JWT",
    "kid": "ephemeral-ecdsa-p256"
  },
  "payload": {
    "iss": "aflock",
    "sub": "spiffe://aflock.ai/agent/claude-opus/4.5/abc123",
    "aud": ["session-uuid"],
    "exp": 1737244800,
    "iat": 1737241200,
    "jti": "session-uuid",

    "agent_id": "spiffe://aflock.ai/agent/claude-opus/4.5/abc123",
    "identity_hash": "sha256:abc123...",

    "allowed_tools": ["Read", "Edit", "Bash"],
    "denied_tools": ["Task"],
    "limits": {
      "maxSpendUSD": { "value": 5.00, "enforcement": "fail-fast" }
    },
    "policy_digest": "sha256:def456..."
  }
}
```

> **Note:** The `grants` (secrets/APIs/storage) and `scopes` fields from the original design are not yet in the JWT claims. Grant enforcement is handled by the policy evaluator at the server level ([#22](https://github.com/aflock-ai/aflock/issues/22)). Future iterations may embed grant scopes in the JWT for per-request enforcement.

**Flow:**

![MCP Flow](/img/diagrams/mcp-flow.svg)

**Why This Separation:**

| Property | JWT | Signing Key |
|----------|-----|-------------|
| Who holds it | Agent | Server only |
| Purpose | Authz/access control | Attestation signing |
| Lifetime | Short (minutes/hours) | Long (rotated by server) |
| If compromised | Limited damage (expires) | Full attestation forgery |
| Revocation | Server stops accepting | Re-key required |

**Security Properties:**

1. **Agent cannot forge attestations**: No access to signing key
2. **JWT limits blast radius**: Short-lived, scoped to specific grants
3. **Server controls signing**: All signatures go through server
4. **Identity binding**: JWT is bound to verified identity hash
5. **Revocation**: Server can reject JWT before expiration

**JWT Issuance (Implemented — `internal/auth/jwt.go`):**

```go
// TokenIssuer generates and validates session JWTs using ECDSA P-256.
issuer, _ := auth.NewTokenIssuer() // Ephemeral key, never persisted

tokenStr, _ := issuer.IssueToken(
    sessionID,                          // Bound to session (aud claim)
    agentIdentity.ToSPIFFEID("aflock.ai"), // SPIFFE ID (sub claim)
    agentIdentity.IdentityHash,         // Identity hash for verification
    policy,                             // Scoped tools/limits from policy
    1*time.Hour,                        // TTL (or policy maxWallTimeSeconds)
)
```

**JWT Validation (per-request):**

```go
// Validate token signature, expiry, issuer, and session binding
claims, err := issuer.ValidateTokenForSession(tokenStr, sessionID)
if err != nil {
    return fmt.Errorf("auth failed: %w", err)
}

// Check tool-level authorization from token scope
if !auth.IsToolAllowed(toolName, claims.AllowedTools, claims.DeniedTools) {
    return fmt.Errorf("tool %q not permitted by token scope", toolName)
}
```

**Signing Attestation (Server-Side):**

```go
// Agent requests signing, server performs it
func (s *Server) signAttestation(jwt string, attestation *intoto.Statement) (*dsse.Envelope, error) {
    // Verify JWT
    claims, err := s.tokenIssuer.ValidateTokenForSession(jwt, s.sessionID)
    if err != nil {
        return nil, fmt.Errorf("invalid JWT: %w", err)
    }

    // Sign with server-held key (agent never sees this key)
    return s.signer.Sign(ctx, attestation)
}
```

#### Identity Discovery via MCP (Claude Code)

The agent communicates with ai-notary via **MCP (Model Context Protocol)**. This is how identity discovery works - the MCP connection over localhost allows the signer to introspect the connecting process:

![MCP Identity Discovery](/img/diagrams/mcp-identity-discovery.svg)

**MCP Tool Flow:**

*See the [MCP Flow diagram](#flow) above for the detailed sequence.*

**Why MCP Matters:**

1. **Trust Boundary**: The agent cannot forge its identity. The signer independently discovers identity by inspecting the connecting process.

2. **Key Isolation**: The agent never sees the signing key. It asks ai-notary to sign, and ai-notary signs with the key bound to the agent's verified identity.

3. **Policy Enforcement**: Before executing commands, ai-notary can check the `.aflock` policy and reject disallowed operations.

4. **Attestation Binding**: Every attestation includes the verified agent identity, creating an unforgeable chain from process → identity → attestation.

**Implementation Notes:**

1. **PID from Socket**:
   - Unix socket: `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS)
   - TCP localhost: Parse `/proc/net/tcp` to find PID by port

2. **Process Inspection** (with PID):
   - `/proc/{pid}/cmdline` (Linux) or `ps -p {pid}` (macOS)
   - `/proc/{pid}/cwd` → agent's working directory
   - `/proc/{pid}/environ` → environment variables

3. **Identity Binding**:
   - **Model**: From `--model` flag or `CLAUDE_MODEL` env
   - **Environment**: UID, hostname, container ID if present
   - **Tools**: MCP capabilities declared by agent
   - **Policy**: `.aflock` loaded from agent's cwd

4. **Security Boundary**: Only localhost connections. Remote agents must use SPIFFE/Sigstore.

#### Resource Access

The agent's identity grants access to resources:

```json
{
  "agentIdentity": {
    "model": "claude-opus-4-5-20251101",
    "environment": {
      "type": "container",
      "image": "ghcr.io/testifysec/agent-runner:v1",
      "imageDigest": "sha256:abc123..."
    },
    "tools": ["Read", "Edit", "Bash", "Glob", "Grep"],
    "policyDigest": "sha256:def456...",
    "parentIdentity": null
  },

  "grants": {
    "secrets": ["vault:secret/data/api-keys/*"],
    "files": ["s3://bucket/attestations/*"],
    "apis": ["https://api.anthropic.com/*"]
  }
}
```

Policy can restrict grants:

```json
{
  "identity": {
    "allowedModels": ["claude-opus-4-5-20251101", "claude-sonnet-4-20250514"],
    "allowedEnvironments": ["container:ghcr.io/testifysec/*"],
    "requiredTools": ["Read", "Glob"],
    "deniedTools": ["Bash:rm -rf *"]
  },

  "grants": {
    "secrets": {
      "allow": ["vault:secret/data/readonly/*"],
      "deny": ["vault:secret/data/production/*"]
    }
  }
}
```

#### Identity in Attestations

Each attestation includes the agent's identity:

```json
{
  "predicate": {
    "agent": {
      "identity": "sha256:abc123def456...",
      "model": "claude-opus-4-5-20251101",
      "environment": {
        "type": "container",
        "imageDigest": "sha256:..."
      },
      "tools": ["Read", "Edit", "Bash"],
      "policyDigest": "sha256:def456..."
    }
  }
}
```

Verification checks:
1. Identity hash matches computed hash from components
2. Identity is authorized by policy's functionaries
3. Resources accessed are within identity's grants

#### Sub-Agent Identity Chaining

When a parent spawns a sub-agent, identity chains:

![Sub-Agent Identity Chain](/img/diagrams/sub-agent-identity.svg)

This creates an identity chain that can be verified:
- Sub-agent's parent field matches parent's identity
- Sub-agent's tools are subset of parent's tools
- Sub-agent's policy is referenced in parent's sublayouts

---

## `.aflock` Schema

### Full Schema Definition

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["version", "name"],
  "properties": {
    "version": {
      "type": "string",
      "description": "Schema version (e.g., '1.0')"
    },
    "name": {
      "type": "string",
      "description": "Human-readable name for this policy"
    },
    "expires": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 expiration timestamp"
    },
    "identity": {
      "type": "object",
      "description": "Agent identity constraints",
      "properties": {
        "allowedModels": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Models permitted to execute this policy"
        },
        "allowedEnvironments": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Environment patterns (e.g., 'container:ghcr.io/org/*')"
        },
        "requiredTools": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Tools that must be available"
        }
      }
    },
    "grants": {
      "type": "object",
      "description": "Resources this identity can access",
      "properties": {
        "secrets": {
          "type": "object",
          "properties": {
            "allow": { "type": "array", "items": { "type": "string" } },
            "deny": { "type": "array", "items": { "type": "string" } }
          }
        },
        "apis": {
          "type": "object",
          "properties": {
            "allow": { "type": "array", "items": { "type": "string" } },
            "deny": { "type": "array", "items": { "type": "string" } }
          }
        },
        "storage": {
          "type": "object",
          "properties": {
            "allow": { "type": "array", "items": { "type": "string" } },
            "deny": { "type": "array", "items": { "type": "string" } }
          }
        }
      }
    },
    "limits": {
      "type": "object",
      "description": "Resource consumption limits",
      "properties": {
        "maxSpendUSD": { "$ref": "#/$defs/limit" },
        "maxTokensIn": { "$ref": "#/$defs/limit" },
        "maxTokensOut": { "$ref": "#/$defs/limit" },
        "maxTurns": { "$ref": "#/$defs/limit" },
        "maxWallTimeSeconds": { "$ref": "#/$defs/limit" },
        "maxToolCalls": { "$ref": "#/$defs/limit" }
      }
    },
    "tools": {
      "type": "object",
      "description": "Tool access controls",
      "properties": {
        "allow": { "type": "array", "items": { "type": "string" } },
        "deny": { "type": "array", "items": { "type": "string" } },
        "requireApproval": { "type": "array", "items": { "type": "string" } }
      }
    },
    "files": {
      "type": "object",
      "description": "File access controls using glob patterns",
      "properties": {
        "allow": { "type": "array", "items": { "type": "string" } },
        "deny": { "type": "array", "items": { "type": "string" } },
        "readOnly": { "type": "array", "items": { "type": "string" } }
      }
    },
    "domains": {
      "type": "object",
      "description": "Network access controls",
      "properties": {
        "allow": { "type": "array", "items": { "type": "string" } },
        "deny": { "type": "array", "items": { "type": "string" } }
      }
    },
    "requiredAttestations": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Step names that must have attestations"
    },
    "attestationDir": {
      "type": "string",
      "description": "Directory to store attestations"
    },
    "attestationsFrom": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Glob patterns for attestations to load for cross-step access"
    },
    "materialsFrom": {
      "type": "object",
      "description": "Materials binding for ordering and provenance",
      "properties": {
        "session": {
          "type": "object",
          "description": "Session JSONL merkle tree binding",
          "properties": {
            "path": { "type": "string", "description": "Path to session JSONL file" },
            "merkleRoot": { "type": "string", "description": "Expected merkle root of session" },
            "algorithm": { "type": "string", "enum": ["sha256", "sha512"], "default": "sha256" }
          }
        },
        "git": {
          "type": "object",
          "description": "Git tree binding",
          "properties": {
            "treeHash": { "type": "string", "description": "Git tree hash to bind attestations to" },
            "branch": { "type": "string", "description": "Expected branch name" }
          }
        },
        "artifacts": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "name": { "type": "string" },
              "digest": { "type": "object" },
              "uri": { "type": "string" }
            }
          },
          "description": "Additional artifact bindings"
        }
      }
    },
    "evaluators": {
      "type": "object",
      "description": "Verification evaluators",
      "properties": {
        "rego": {
          "type": "array",
          "items": { "$ref": "#/$defs/regoEvaluator" }
        },
        "ai": {
          "type": "array",
          "items": { "$ref": "#/$defs/aiEvaluator" }
        },
        "grpc": {
          "type": "array",
          "items": { "$ref": "#/$defs/grpcEvaluator" }
        }
      }
    },
    "functionaries": {
      "type": "array",
      "items": { "$ref": "#/$defs/functionary" },
      "description": "Authorized signers for this policy"
    },
    "sublayouts": {
      "type": "array",
      "items": { "$ref": "#/$defs/sublayout" },
      "description": "Sub-agent policy delegations"
    }
  },
  "$defs": {
    "limit": {
      "oneOf": [
        { "type": "number" },
        {
          "type": "object",
          "required": ["value"],
          "properties": {
            "value": { "type": "number" },
            "enforcement": {
              "type": "string",
              "enum": ["fail-fast", "post-hoc"],
              "default": "fail-fast"
            }
          }
        }
      ]
    },
    "regoEvaluator": {
      "type": "object",
      "required": ["name", "policy"],
      "properties": {
        "name": { "type": "string" },
        "policy": { "type": "string", "description": "Inline Rego policy or path to .rego file" }
      }
    },
    "aiEvaluator": {
      "type": "object",
      "required": ["name", "prompt"],
      "properties": {
        "name": { "type": "string" },
        "prompt": { "type": "string", "description": "AI evaluation prompt (PASS/FAIL)" },
        "model": { "type": "string", "default": "claude-sonnet-4-20250514" }
      }
    },
    "grpcEvaluator": {
      "type": "object",
      "required": ["name", "endpoint"],
      "properties": {
        "name": { "type": "string" },
        "endpoint": { "type": "string", "description": "gRPC endpoint for custom evaluator" }
      }
    },
    "functionary": {
      "type": "object",
      "required": ["type"],
      "properties": {
        "type": { "type": "string", "enum": ["keyless", "publickey", "x509"] },
        "issuer": { "type": "string" },
        "subject": { "type": "string" },
        "publickeyid": { "type": "string" }
      }
    },
    "sublayout": {
      "type": "object",
      "required": ["name", "policy"],
      "properties": {
        "name": { "type": "string", "description": "Sublayout identifier (matches sub-agent task name)" },
        "policy": { "type": "string", "description": "Path to sub-agent .aflock policy file or inline policy" },
        "policyDigest": { "type": "object", "description": "Expected digest of the sublayout policy" },
        "functionaries": {
          "type": "array",
          "items": { "$ref": "#/$defs/functionary" },
          "description": "Authorized signers for this sublayout (overrides parent if specified)"
        },
        "limits": {
          "type": "object",
          "description": "Limit overrides for sub-agent (must be stricter than parent)",
          "properties": {
            "maxSpendUSD": { "$ref": "#/$defs/limit" },
            "maxTokensIn": { "$ref": "#/$defs/limit" },
            "maxTurns": { "$ref": "#/$defs/limit" }
          }
        },
        "inherit": {
          "type": "array",
          "items": { "type": "string", "enum": ["limits", "tools", "files", "domains", "functionaries"] },
          "description": "Which fields to inherit from parent policy"
        },
        "attestationPrefix": {
          "type": "string",
          "description": "Prefix for sub-agent attestations (e.g., 'research-agent-')"
        }
      }
    }
  }
}
```

### Example `.aflock` File

```json
{
  "version": "1.0",
  "name": "feature-search-implementation",
  "expires": "2026-02-01T00:00:00Z",

  "limits": {
    "maxSpendUSD": { "value": 5.00, "enforcement": "fail-fast" },
    "maxTokensIn": { "value": 500000, "enforcement": "fail-fast" },
    "maxTokensOut": { "value": 100000, "enforcement": "post-hoc" },
    "maxTurns": { "value": 50, "enforcement": "post-hoc" },
    "maxWallTimeSeconds": { "value": 3600, "enforcement": "fail-fast" },
    "maxToolCalls": { "value": 200, "enforcement": "post-hoc" }
  },

  "tools": {
    "allow": ["Read", "Edit", "Write", "Glob", "Grep", "Bash", "LSP"],
    "deny": ["Task"],
    "requireApproval": ["Bash:rm *", "Bash:git push", "Write:*.env"]
  },

  "files": {
    "allow": ["src/**", "tests/**", "docs/**"],
    "deny": ["**/.env", "**/secrets/**", "**/credentials.*"],
    "readOnly": ["package.json", "go.mod"]
  },

  "domains": {
    "allow": ["github.com", "*.anthropic.com", "docs.*"],
    "deny": ["*"]
  },

  "requiredAttestations": [
    "task-complete",
    "quality-check"
  ],

  "attestationDir": "./attestations/agent-runs",

  "evaluators": {
    "rego": [
      {
        "name": "cumulative-spend-check",
        "policy": "package agentflow\nimport rego.v1\nsum_spend := sum([t.predicate.metrics.costUSD | some t in input.attestationsFrom[\"turn-*\"]])\ndeny contains msg if { sum_spend > input.limits.maxSpendUSD.value; msg := sprintf(\"Spend $%.2f exceeds limit $%.2f\", [sum_spend, input.limits.maxSpendUSD.value]) }"
      }
    ],
    "ai": [
      {
        "name": "output-quality",
        "prompt": "PASS if the agent completed the task successfully and the code is production-ready. FAIL if incomplete, buggy, or poor quality.",
        "model": "claude-opus-4-5-20251101"
      }
    ]
  },

  "attestationsFrom": ["turn-*"],

  "functionaries": [
    {
      "type": "keyless",
      "issuer": "https://accounts.google.com",
      "subject": "user@example.com"
    }
  ]
}
```

---

## Schema Field Reference

### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Schema version (currently "1.0") |
| `name` | string | Yes | Human-readable policy name |
| `expires` | string | No | ISO 8601 expiration timestamp |
| `identity` | object | No | Agent identity constraints (models, environments, tools) |
| `grants` | object | No | Resources this identity can access (secrets, APIs, storage) |
| `limits` | object | No | Resource consumption limits |
| `tools` | object | No | Tool access controls |
| `files` | object | No | File access controls |
| `domains` | object | No | Network access controls |
| `requiredAttestations` | array | No | Step names requiring attestations |
| `attestationDir` | string | No | Output directory for attestations |
| `attestationsFrom` | array | No | Patterns for cross-step attestation loading |
| `materialsFrom` | object | No | Materials binding for ordering and provenance |
| `evaluators` | object | No | Verification evaluators |
| `functionaries` | array | No | Authorized policy signers |
| `sublayouts` | array | No | Sub-agent policy delegations |

### Limits Object

Limits control resource consumption. Each limit can be a simple number or an object with enforcement mode.

| Field | Type | Enforcement | Description |
|-------|------|-------------|-------------|
| `maxSpendUSD` | number | fail-fast | Maximum cost in USD |
| `maxTokensIn` | number | fail-fast | Maximum input tokens |
| `maxTokensOut` | number | post-hoc | Maximum output tokens |
| `maxTurns` | number | post-hoc | Maximum conversation turns |
| `maxWallTimeSeconds` | number | fail-fast | Maximum wall-clock time |
| `maxToolCalls` | number | post-hoc | Maximum tool invocations |

**Simple format:**
```json
"maxSpendUSD": 5.00
```

**Extended format with enforcement:**
```json
"maxSpendUSD": { "value": 5.00, "enforcement": "fail-fast" }
```

### Tools Object

Controls which tools the agent can use.

| Field | Type | Description |
|-------|------|-------------|
| `allow` | array | Tools the agent may use (allowlist) |
| `deny` | array | Tools the agent must not use (denylist) |
| `requireApproval` | array | Tools that require human approval (format: `Tool:pattern`) |

**Pattern format for `requireApproval`:**
- `Bash:rm *` - Bash commands matching `rm *`
- `Write:*.env` - Write operations to files matching `*.env`
- `Edit:src/config/*` - Edit operations on config files

### Files Object

Controls file system access using glob patterns.

| Field | Type | Description |
|-------|------|-------------|
| `allow` | array | Patterns for files the agent may access |
| `deny` | array | Patterns for files the agent must not access |
| `readOnly` | array | Patterns for files the agent may read but not modify |

**Glob pattern examples:**
- `src/**` - All files under src/
- `**/*.ts` - All TypeScript files
- `!**/node_modules/**` - Exclude node_modules

### Domains Object

Controls network access for web fetching.

| Field | Type | Description |
|-------|------|-------------|
| `allow` | array | Domains the agent may access |
| `deny` | array | Domains the agent must not access |

**Wildcard support:**
- `*.anthropic.com` - All subdomains of anthropic.com
- `docs.*` - Any domain starting with `docs.`
- `*` - All domains (use in deny to create allowlist)

### Evaluators Object

Defines verification rules run during or after execution.

#### Rego Evaluators

```json
{
  "name": "cumulative-spend-check",
  "policy": "package agentflow\ndeny[msg] { ... }"
}
```

The `policy` field can be:
- Inline Rego code (as shown)
- Path to a `.rego` file: `"policy": "./policies/spend.rego"`

#### AI Evaluators

```json
{
  "name": "output-quality",
  "prompt": "PASS if the agent completed the task successfully. FAIL otherwise.",
  "model": "claude-opus-4-5-20251101"
}
```

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `name` | string | Yes | - |
| `prompt` | string | Yes | - |
| `model` | string | No | `claude-sonnet-4-20250514` |

#### gRPC Evaluators

```json
{
  "name": "custom-validator",
  "endpoint": "localhost:50051"
}
```

For custom evaluation logic via gRPC service.

### Functionaries

Defines who can sign this policy.

```json
{
  "type": "keyless",
  "issuer": "https://accounts.google.com",
  "subject": "user@example.com"
}
```

| Type | Required Fields | Description |
|------|-----------------|-------------|
| `keyless` | `issuer`, `subject` | Sigstore keyless signing (OIDC) |
| `publickey` | `publickeyid` | Traditional public key |
| `x509` | `issuer`, `subject` | X.509 certificate |

---

## Turn Attestation Schema

Each turn generates an attestation with metrics. The attestation follows the in-toto Statement specification.

### Full Schema

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    { "name": "agentflow:run:abc123", "digest": { "sha256": "..." } },
    { "name": "git:treehash", "digest": { "sha1": "fbc8f78..." } }
  ],
  "predicateType": "https://agentflow.dev/attestation/turn/v0.1",
  "predicate": {
    "turn": 3,
    "runId": "abc123",
    "timestamp": "2026-01-18T10:30:00Z",

    "metrics": {
      "tokensIn": 12500,
      "tokensOut": 3200,
      "cacheRead": 8000,
      "cacheWrite": 2000,
      "costUSD": 0.08,
      "durationMs": 4500
    },

    "cumulative": {
      "tokensIn": 45000,
      "tokensOut": 12000,
      "costUSD": 0.32,
      "turns": 3,
      "toolCalls": 28
    },

    "model": "claude-sonnet-4-20250514",

    "tools": [
      { "name": "Read", "path": "src/search.ts", "allowed": true },
      { "name": "Edit", "path": "src/search.ts", "allowed": true },
      { "name": "Bash", "command": "npm test", "allowed": true }
    ],

    "files": {
      "read": ["src/search.ts", "src/types.ts"],
      "written": ["src/search.ts"],
      "created": []
    },

    "domains": {
      "fetched": ["github.com/anthropics/claude-code"]
    },

    "approvals": [],

    "agent": {
      "provider": "anthropic",
      "model": "claude-sonnet-4-20250514",
      "sessionId": "sess_abc123"
    }
  }
}
```

### Predicate Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `turn` | number | Turn number (1-indexed) |
| `runId` | string | Unique identifier for this agent run |
| `timestamp` | string | ISO 8601 timestamp |
| `metrics` | object | Metrics for this turn only |
| `cumulative` | object | Cumulative metrics across all turns so far |
| `model` | string | Model used for this turn |
| `tools` | array | Tools invoked during this turn |
| `files` | object | Files accessed during this turn |
| `domains` | object | Domains accessed during this turn |
| `approvals` | array | Human approvals received during this turn |
| `agent` | object | Agent metadata |

### Subject Binding

Attestations are bound to:

1. **Run ID**: Unique identifier for the agent execution
2. **Git tree hash**: The state of the codebase at attestation time

This ensures attestations cannot be replayed for different runs or code states.

### Materials Binding and Session Merkle Tree

The `materialsFrom` directive enables cryptographic binding of attestations to source materials, with the session JSONL merkle tree providing ordering and distance proofs.

#### Session JSONL Structure

Claude Code sessions are stored as JSONL files:
```
~/.claude/projects/<project-path>/<session-id>.jsonl
```

Each line represents a conversation turn with:
- User messages
- Assistant responses
- Tool calls and results
- Token metrics

#### Merkle Tree Construction

The session JSONL is converted to a merkle tree:

```
                    [Root Hash]
                   /          \
          [Hash 0-1]          [Hash 2-3]
          /       \           /       \
    [Turn 0]  [Turn 1]   [Turn 2]  [Turn 3]
```

Each turn's hash includes:
- Previous turn hash (chain linking)
- Turn content hash
- Timestamp
- Token metrics

#### Ordering Proof

Turn attestations include a merkle proof linking them to specific positions:

```json
{
  "predicate": {
    "turn": 3,
    "sessionBinding": {
      "merkleRoot": "abc123...",
      "turnIndex": 3,
      "merkleProof": ["hash0", "hash1", "..."],
      "previousTurnHash": "def456..."
    }
  }
}
```

This proves:
1. **Order**: Turn 3 definitively came after turns 0-2
2. **Completeness**: No turns were skipped or hidden
3. **Integrity**: Turn content wasn't modified after the fact

#### Distance Calculation

The merkle tree enables distance-based constraints:

```json
{
  "materialsFrom": {
    "session": {
      "constraints": {
        "maxTurnDistance": 5,
        "requireContiguousTurns": true
      }
    }
  }
}
```

Rego policies can verify distance:

```rego
# Ensure attestations are from contiguous turns
deny contains msg if {
    some i in range(1, count(turns))
    current := turns[i]
    previous := turns[i-1]
    distance := current.predicate.turn - previous.predicate.turn
    distance > input.policy.materialsFrom.session.constraints.maxTurnDistance
    msg := sprintf("Turn gap %d exceeds max distance %d",
                   [distance, input.policy.materialsFrom.session.constraints.maxTurnDistance])
}
```

#### Git Tree Binding

Attestations are also bound to git state:

```json
{
  "materialsFrom": {
    "git": {
      "treeHash": "fbc8f78a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
      "branch": "feature/search"
    }
  }
}
```

This ensures the attestation references a specific codebase state.

#### Combined Binding Example

```json
{
  "materialsFrom": {
    "session": {
      "path": "~/.claude/projects/.../session.jsonl",
      "merkleRoot": "expected-root-hash",
      "algorithm": "sha256"
    },
    "git": {
      "treeHash": "abc123...",
      "branch": "main"
    },
    "artifacts": [
      {
        "name": "test-results",
        "digest": { "sha256": "..." },
        "uri": "file://./test-output.xml"
      }
    ]
  }
}
```

### Sublayouts: Delegating to Sub-Agents

Inspired by [in-toto sublayouts](https://github.com/in-toto/specification), the `.aflock` spec supports delegating verification to sub-agents with their own policy constraints.

#### Concept

When a parent agent spawns a sub-agent (via Claude Code's `Task` tool), the sub-agent can operate under its own `.aflock` policy. This creates a hierarchical verification structure:

![Sublayout Hierarchy](/img/diagrams/sublayout-hierarchy.svg)

#### Sublayout Definition

```json
{
  "sublayouts": [
    {
      "name": "research-agent",
      "policy": "./policies/research-agent.aflock",
      "policyDigest": { "sha256": "abc123..." },
      "limits": {
        "maxSpendUSD": { "value": 2.00, "enforcement": "fail-fast" },
        "maxTurns": { "value": 10, "enforcement": "fail-fast" }
      },
      "inherit": ["domains", "functionaries"],
      "attestationPrefix": "research-"
    },
    {
      "name": "testing-agent",
      "policy": "./policies/test-agent.aflock",
      "limits": {
        "maxSpendUSD": { "value": 3.00, "enforcement": "fail-fast" }
      },
      "inherit": ["files", "functionaries"],
      "attestationPrefix": "test-"
    }
  ]
}
```

#### Limit Inheritance and Constraints

Sub-agent limits must be **stricter** than parent limits:

| Parent Limit | Sub-Agent Limit | Allowed? |
|--------------|-----------------|----------|
| $10.00 | $5.00 | ✓ Yes (stricter) |
| $10.00 | $15.00 | ✗ No (looser) |
| 100 tokens | 50 tokens | ✓ Yes (stricter) |
| 100 tokens | - (not set) | ✓ Yes (inherits parent) |

**Cumulative limits**: Sub-agent spend counts toward parent's total. If parent has $10 limit and spawns two sub-agents with $5 each, only $10 total can be spent across all agents.

#### Attestation Namespacing

Sub-agent attestations are prefixed to distinguish them from parent attestations:

```
Parent attestations:     turn-1.json, turn-2.json, ...
Research sub-agent:      research-turn-1.json, research-turn-2.json, ...
Testing sub-agent:       test-turn-1.json, test-turn-2.json, ...
```

This matches [in-toto's namespacing approach](https://github.com/in-toto/specification/blob/v1.0/in-toto-spec.md) where sublayout links are stored in subdirectories named `<step name>.<keyid prefix>`.

#### Verification Recursion

Verification recurses into sublayouts:

```
1. Verify parent policy attestations
2. For each sublayout:
   a. Load sublayout policy
   b. Verify policy digest matches expected
   c. Collect sublayout attestations (by prefix)
   d. Recursively verify sublayout attestations against sublayout policy
   e. Add sublayout metrics to parent cumulative totals
3. Run parent evaluators (Rego + AI)
4. Verify cumulative limits (parent + all sublayouts)
```

#### Session Merkle Tree with Sublayouts

Sub-agent sessions create nested merkle trees:

![Session Merkle Tree](/img/diagrams/merkle-tree.svg)

The parent's materialsFrom can reference sub-agent session roots:

```json
{
  "materialsFrom": {
    "session": {
      "path": "${CLAUDE_SESSION_PATH}",
      "merkleRoot": "parent-root-hash"
    },
    "sublayoutSessions": {
      "research-agent": {
        "merkleRoot": "research-session-hash",
        "spawnedAtTurn": 2
      },
      "testing-agent": {
        "merkleRoot": "testing-session-hash",
        "spawnedAtTurn": 3
      }
    }
  }
}
```

This proves:
- **Order**: Which parent turn spawned each sub-agent
- **Completeness**: All sub-agent turns are accounted for
- **Isolation**: Sub-agent sessions are separate but linked to parent

---

## Verification Algorithm

### Phase 1: Load Policy and Attestations

```
1. Parse .aflock file
2. Verify policy signature against functionaries
3. Load attestations matching attestationsFrom patterns
4. Bind attestations to current git tree hash
```

### Phase 1.5: Materials Verification

```
1. If materialsFrom.session is defined:
   a. Load session JSONL file
   b. Compute merkle tree over session entries
   c. Verify computed merkle root matches expected
   d. For each turn attestation:
      - Verify merkle proof links attestation to session
      - Verify turn ordering is correct
      - Check distance constraints (maxTurnDistance)
      - Check contiguity (requireContiguousTurns)

2. If materialsFrom.git is defined:
   a. Get current git tree hash
   b. Verify it matches expected treeHash
   c. Optionally verify branch name

3. If materialsFrom.artifacts is defined:
   a. For each artifact:
      - Load artifact from URI
      - Compute digest
      - Verify digest matches expected
```

### Phase 1.75: Sublayout Verification

```
1. For each sublayout in policy.sublayouts:
   a. Load sublayout policy from path
   b. Verify policy digest matches expected policyDigest
   c. Verify sublayout limits are stricter than parent:
      - maxSpendUSD <= parent.maxSpendUSD
      - maxTokensIn <= parent.maxTokensIn
      - etc.
   d. Collect sublayout attestations (matching attestationPrefix)
   e. RECURSE: Run full verification on sublayout policy
      - This creates a recursive verification tree
   f. Aggregate sublayout metrics into parent cumulative totals:
      - sumSpend += sublayout.sumSpend
      - sumTokens += sublayout.sumTokens
      - etc.

2. If materialsFrom.sublayoutSessions is defined:
   a. For each sublayout session:
      - Verify merkle root matches expected
      - Verify spawnedAtTurn exists in parent session
      - Verify parent turn contains sub-agent spawn event
```

### Phase 2: Rego Cross-Step Evaluation

Using go-witness cross-step access:

```rego
package agentflow

import rego.v1

# Access all turn attestations via cross-step
turns := [t | some t in input.attestationsFrom["turn-*"]]

# Calculate cumulative spend
sum_spend := sum([t.predicate.metrics.costUSD | some t in turns])

# Calculate cumulative tokens
sum_tokens_in := sum([t.predicate.metrics.tokensIn | some t in turns])
sum_tokens_out := sum([t.predicate.metrics.tokensOut | some t in turns])

# Calculate total tool calls
sum_tool_calls := sum([count(t.predicate.tools) | some t in turns])

# Enforce spend limit
deny contains msg if {
    sum_spend > input.policy.limits.maxSpendUSD.value
    msg := sprintf("Cumulative spend $%.2f exceeds limit $%.2f",
                   [sum_spend, input.policy.limits.maxSpendUSD.value])
}

# Enforce token limit
deny contains msg if {
    sum_tokens_in > input.policy.limits.maxTokensIn.value
    msg := sprintf("Cumulative input tokens %d exceeds limit %d",
                   [sum_tokens_in, input.policy.limits.maxTokensIn.value])
}

# Enforce turn limit
deny contains msg if {
    count(turns) > input.policy.limits.maxTurns.value
    msg := sprintf("Turn count %d exceeds limit %d",
                   [count(turns), input.policy.limits.maxTurns.value])
}

# Enforce tool allowlist
deny contains msg if {
    some t in turns
    some tool in t.predicate.tools
    not tool.allowed
    msg := sprintf("Turn %d used disallowed tool %s", [t.predicate.turn, tool.name])
}

# Enforce file access
deny contains msg if {
    some t in turns
    some f in t.predicate.files.written
    file_denied(f)
    msg := sprintf("Turn %d wrote to denied path %s", [t.predicate.turn, f])
}

file_denied(path) if {
    some pattern in input.policy.files.deny
    glob.match(pattern, [], path)
}
```

### Phase 3: AI Evaluation

For each AI evaluator in the policy:

```
1. Collect all attestations and final output
2. Construct evaluation prompt with context
3. Call AI model for PASS/FAIL judgment
4. Record evaluation result as attestation
```

### Phase 4: Final Verdict

```
1. All Rego deny rules must be empty
2. All AI evaluators must return PASS
3. All required attestations must exist
4. Policy must not be expired

If all pass → VERIFIED
If any fail → FAILED with detailed report
```

---

## Workflow Integration

### CLI Usage

#### Start Agent Run

```bash
# Load .aflock policy and start monitored execution
ai-notary agentflow start --policy=feature-search.aflock

# Output: Run ID, attestation directory, active limits
```

#### Verify Agent Run

```bash
# On agent completion or exit
ai-notary agentflow verify \
    --policy=feature-search.aflock \
    --run-id=abc123

# Loads all turn-* attestations
# Runs cross-step Rego evaluation
# Runs AI quality evaluators
# Returns PASS/FAIL with detailed report
```

#### Pre-Push Hook

```bash
# In .git/hooks/pre-push
if [ -f ".aflock" ]; then
    ai-notary agentflow verify --policy=.aflock --run-id=$CURRENT_RUN
    if [ $? -ne 0 ]; then
        echo "Agent constraints violated"
        exit 1
    fi
fi

# Then run normal attestation verification
ai-notary verify --policy=policy-signed.json
```

### Judge AgentFlow Integration

The primary implementation will be in Judge's agentflow system.

#### Phase 1: Policy Loading

```go
// WorkflowBuilder extension
workflow := agentflow.New("search-feature").
    WithPolicy("feature-search.aflock").  // Load and validate .aflock
    Do("implement", agentflow.ClaudeCode("Implement search feature"))

// Policy parsed and constraints injected into task context
// Fail-fast limits monitored during execution
```

#### Phase 2: Attestation Generation

```go
// In ClaudeCodeTask.Run()
func (t *ClaudeCodeTask) Run(ctx context.Context) (*Result, error) {
    // ... execute task ...

    // Generate attestation with metrics from Result
    attestation := t.generateAttestation(result)
    t.signer.Sign(attestation)
    t.store.Save(attestation)

    return result, nil
}
```

#### Phase 3: Cumulative Limit Checking

```go
// LimitChecker runs after each task
type LimitChecker struct {
    policy     *AflockPolicy
    cumulative *CumulativeMetrics
}

func (lc *LimitChecker) Check() error {
    for _, limit := range lc.policy.Limits {
        if limit.Enforcement == "fail-fast" {
            if lc.cumulative.Exceeds(limit) {
                return fmt.Errorf("limit breached: %s", limit.Name)
            }
        }
    }
    return nil
}
```

#### Phase 4: Final Verification

```go
// AgentflowVerify task runs Rego + AI evaluators
workflow := agentflow.New("search-feature").
    WithPolicy("feature-search.aflock").
    Do("implement", agentflow.ClaudeCode("...")).
    Do("verify", agentflow.AflockVerify())  // Runs post-hoc checks

// Exports attestations in ai-notary compatible format
// ai-notary CLI can also verify independently
```

---

## Primary Use Case: Compliance Control Evaluation

The first implementation focuses on **compliance control evaluation** - an AI agent that evaluates security/compliance controls and produces attestations proving the evaluation was performed correctly.

### Why Compliance First

1. **Judge already has OSCAL tooling** (`tools/oscal.go`)
2. **Compliance requires audit trail** (attestations)
3. **Quality evaluation is critical** (AI evaluators)
4. **Cost control matters** for large control sets
5. **Natural fit for cross-step verification** (cumulative checks)

### Example: OSCAL Control Evaluation

```json
{
  "version": "1.0",
  "name": "oscal-control-evaluation",
  "expires": "2026-06-01T00:00:00Z",

  "limits": {
    "maxSpendUSD": { "value": 25.00, "enforcement": "fail-fast" },
    "maxTokensIn": { "value": 1000000, "enforcement": "post-hoc" }
  },

  "requiredAttestations": [
    "control-assessment",
    "evidence-collection",
    "finding-generation"
  ],

  "evaluators": {
    "rego": [
      {
        "name": "all-controls-assessed",
        "policy": "package compliance\nimport rego.v1\nassessed_controls := {c | some t in input.attestationsFrom[\"control-*\"]; c := t.predicate.controlId}\nexpected_controls := input.policy.expectedControls\nmissing := expected_controls - assessed_controls\ndeny contains msg if { count(missing) > 0; msg := sprintf(\"Missing control assessments: %v\", [missing]) }"
      }
    ],
    "ai": [
      {
        "name": "assessment-quality",
        "prompt": "PASS if each control assessment includes: (1) clear pass/fail determination, (2) supporting evidence references, (3) remediation guidance for failures. FAIL if assessments are superficial or lack evidence.",
        "model": "claude-opus-4-5-20251101"
      }
    ]
  },

  "functionaries": [
    {
      "type": "keyless",
      "issuer": "https://accounts.google.com",
      "subject": "compliance-agent@testifysec.com"
    }
  ]
}
```

### Workflow

```
1. Load .aflock policy for compliance evaluation task
2. Agent evaluates each OSCAL control
3. Agent generates attestations:
   - control-assessment: Per-control evaluation results
   - evidence-collection: Evidence gathered for each control
   - finding-generation: Consolidated findings report
4. Verification runs:
   - Rego: All expected controls were assessed
   - AI: Assessment quality meets standards
5. Signed attestations prove compliant evaluation process
```

---

## Judge Integration Details

### Existing Judge Infrastructure

The `.aflock` implementation leverages existing Judge systems:

#### 1. PolicyVerify Framework (`judge-api/pkg/policyverify/`)

Judge already has a pluggable evaluator system:

```go
// Evaluator interface (existing)
type Evaluator interface {
    Name() string
    Type() string  // "rego" or "ai"
    Evaluate(ctx context.Context, attestation []byte) (*Result, error)
}

// AIConfig structure (existing)
type AIConfig struct {
    Prompt string `json:"prompt"`
    Model  string `json:"model"`
}

// Result structure (existing)
type Result struct {
    Status   Status         `json:"status"`  // PASS or FAIL
    Reason   string         `json:"reason"`
    Details  map[string]any `json:"details,omitempty"`
    Duration time.Duration  `json:"duration,omitempty"`
}
```

`.aflock` AI evaluators map directly to this structure.

#### 2. OSCAL Tools (`judge-api/pkg/agentflow/tools/oscal/`)

Judge provides comprehensive OSCAL tooling:

| Tool | Purpose |
|------|---------|
| `SearchControlsTool` | Query NIST 800-53 controls |
| `GetControlTool` | Retrieve specific control details |
| `GetFamilyTool` | Get control family information |
| `CreateSSPTool` | Generate System Security Plans |
| `AddControlImplementationTool` | Document control implementations |
| `FedRAMPCloudNativeGuidanceTool` | FedRAMP-specific guidance |
| `ManageSystemInventoryTool` | System component inventory |
| `ManageControlParametersTool` | Control parameter values |
| `DocumentAuthorizationBoundaryTool` | Authorization boundary docs |
| `UpdateControlRemarksTool` | Control assessment remarks |

These tools are allowlisted in compliance `.aflock` policies.

#### 3. Compliance Database Schema (`judge-api/ent/schema/compliance_*.go`)

Existing schema supports:
- `ComplianceControl` - Control definitions
- `ComplianceFramework` - Frameworks (NIST, FedRAMP)
- `ComplianceControlFamily` - Control families (AC, AU, etc.)
- `ComplianceDirective` - Implementation directives

### Files to Modify in Judge

| File | Purpose |
|------|---------|
| `judge-api/pkg/agentflow/policy/aflock.go` | Policy parsing |
| `judge-api/pkg/agentflow/task/claudecode.go` | Attestation generation |
| `judge-api/pkg/agentflow/engine/limits.go` | Cumulative limit checking |
| `judge-api/pkg/agentflow/task/aflock_verify.go` | Verification task |
| `judge-api/pkg/agentflow/workflow.go` | `WithPolicy()` method |

### AI Evaluator Response Format

Following Judge's existing pattern, AI evaluators must return structured JSON:

```json
{"status": "PASS", "reason": "explanation of why it passed"}
```

or

```json
{"status": "FAIL", "reason": "explanation of why it failed"}
```

The system prompt enforces this format (from Judge's `ai.go`):

```go
systemPrompt := `You are an attestation policy evaluator. Your job is to analyze attestation data
and determine if it satisfies a policy requirement.

You MUST respond with ONLY valid JSON in this exact format:
{"status": "PASS", "reason": "explanation of why it passed"}
or
{"status": "FAIL", "reason": "explanation of why it failed"}

Do not include any other text, markdown formatting, or code blocks.

Policy requirement to evaluate:
` + e.prompt
```

---

## Open Questions

### 1. Approval UX

How to prompt for human approval mid-execution when `requireApproval` patterns are matched?

**Options:**
- Pause and wait for CLI input
- Send notification and continue with default deny
- Integrate with external approval system (Slack, email)

### 2. Attestation Storage

Where should attestations be stored?

**Options:**
- Local files (current ai-notary approach)
- Remote storage (Archivista)
- Hybrid (local + remote sync)

### 3. Policy Inheritance

Can `.aflock` files extend a base policy?

**Example use case:** Organization-wide limits with project-specific allowlists.

```json
{
  "extends": "https://company.com/policies/base.aflock",
  "name": "project-specific",
  "limits": {
    "maxSpendUSD": { "value": 10.00 }
  }
}
```

---

## See Also

- [Two-Tier Policy Architecture](two-tier-policies.md) - Infrastructure vs feature policies
- [Mental Model](mental-model.md) - Core workflow philosophy
- [AI Evaluators](../skills/ai-evaluators.md) - Writing effective AI evaluation prompts
