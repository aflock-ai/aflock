# Attestation Demo

Full lifecycle demo: policy enforcement + attestation generation + verification with `requiredAttestations`.

## What's in here

```
attestation-demo/
  .aflock                       ← Policy with requiredAttestations: ["Read", "Bash"]
  .claude/settings.local.json   ← Hook config for Claude Code
  src/main.go                   ← Dummy source (allowed by policy)
  tests/main_test.go            ← Dummy test (allowed by policy)
  run-demo.sh                   ← Full lifecycle test script
  README.md                     ← This file
```

## Quick Run

```bash
cd /path/to/aflock-example/attestation-demo
chmod +x run-demo.sh
./run-demo.sh
```

## What the Demo Does

```
Step 1: SessionStart         → Load policy, discover identity
Step 2: PreToolUse (Read)    → Policy says: ALLOW (src/** matches)
Step 3: PostToolUse (Read)   → Sign attestation → store .intoto.json
Step 4: PreToolUse (Bash)    → Policy says: ALLOW (Bash in tools.allow)
Step 5: PostToolUse (Bash)   → Sign attestation → store .intoto.json
Step 6: PreToolUse (.env)    → Policy says: DENY (**/.env in files.deny)
Step 7: Stop                 → Check requiredAttestations: Read ✓, Bash ✓
Step 8: Inspect              → Show attestation files and contents
Step 9: Verify               → 12 structural checks on DSSE + in-toto v1
```

## The Policy

```json
{
  "requiredAttestations": ["Read", "Bash"]
}
```

This means: the session cannot stop unless attestation files exist for both `Read` and `Bash` tool calls. PostToolUse creates these attestations automatically.

## Testing with Claude Code (Live)

1. Open Claude Code in this directory:
   ```bash
   cd /path/to/aflock-example/attestation-demo
   claude
   ```

2. The `.claude/settings.local.json` hooks are auto-detected. Every tool call will:
   - Be checked against the `.aflock` policy (PreToolUse)
   - Produce a signed attestation (PostToolUse)

3. Ask Claude to read a file or run a command:
   ```
   > Read src/main.go
   > Run: ls src/
   ```

4. Check attestations:
   ```bash
   ../scripts/inspect-attestation.sh --list
   ```

## Testing with SPIRE (Full Identity Chain)

### Prerequisites

SPIRE running via Docker:

```bash
cd /path/to/aflock

# Start SPIRE (server + agent)
docker compose up -d spire-server spire-agent

# Wait for healthy
docker compose ps

# Generate join token (need new one each time agent restarts)
TOKEN=$(docker compose exec spire-server \
  /opt/spire/bin/spire-server token generate \
  -spiffeID spiffe://aflock.ai/agent/local-dev 2>&1 | grep "Token:" | awk '{print $2}')

# Restart agent with token
SPIRE_JOIN_TOKEN=$TOKEN docker compose up -d spire-agent

# Register your workload
docker compose exec spire-server /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://aflock.ai/agent/claude-opus-4-5 \
  -parentID spiffe://aflock.ai/agent/local-dev \
  -selector "unix:uid:$(id -u)" \
  -x509SVIDTTL 3600
```

### Verify socket exists

```bash
ls -la /tmp/spire-agent/public/api.sock
```

### Run the demo

```bash
cd /path/to/aflock-example/attestation-demo
./run-demo.sh
```

### Check signing mode

If SPIRE is running and the model is in the trusted list:
- `Signing mode: SPIRE`
- `Key ID: spiffe://aflock.ai/agent/claude-opus-4-5`

If SPIRE is not running or model not trusted:
- `Signing mode: Ephemeral`
- `Key ID: spiffe://aflock.ai/agent/ephemeral/<hash>`

Both produce valid DSSE envelopes.

### Stop SPIRE

```bash
cd /path/to/aflock && docker compose down
```

## How requiredAttestations Works

1. Policy defines `"requiredAttestations": ["Read", "Bash"]`
2. Each PostToolUse creates a `.intoto.json` file in `~/.aflock/sessions/<id>/attestations/`
3. When Stop fires, `handleStop()` checks:
   - For each required name, look for a file matching the tool name
   - The file must pass structural validation (valid DSSE with non-empty signatures)
4. If any required attestation is missing → Stop is **blocked**
5. If all present → Stop succeeds

## Attestation File Format

Each `.intoto.json` is a DSSE envelope:

```
┌─────────────────────────────────────────┐
│ DSSE Envelope                           │
│  payloadType: application/vnd.in-toto+json │
│  payload: base64(Statement)             │
│  signatures: [{keyid, sig, certificate}]│
└───────────────┬─────────────────────────┘
                │ base64 decode
┌───────────────▼─────────────────────────┐
│ in-toto v1 Statement                    │
│  _type: https://in-toto.io/Statement/v1 │
│  subject: [{name, digest}]              │
│  predicateType: action/v0.1             │
│  predicate: ActionPredicate             │
└───────────────┬─────────────────────────┘
                │
┌───────────────▼─────────────────────────┐
│ ActionPredicate                         │
│  toolName, toolInput, decision          │
│  agentIdentity (model, hash, binary)    │
│  metrics (tokens, cost, turns)          │
└─────────────────────────────────────────┘
```
