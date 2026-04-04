#!/usr/bin/env bash
# Inspect attestations for an aflock session
#
# Usage:
#   ./inspect-attestation.sh                    # auto-detect most recent session
#   ./inspect-attestation.sh <session-id>       # specific session
#   ./inspect-attestation.sh --list             # list all sessions with attestations

set -euo pipefail

SESSIONS_DIR="$HOME/.aflock/sessions"

# --- List mode ---
if [ "${1:-}" = "--list" ]; then
  echo "Sessions with attestations:"
  echo ""
  for dir in "$SESSIONS_DIR"/*/attestations; do
    [ -d "$dir" ] || continue
    sid=$(basename "$(dirname "$dir")")
    count=$(ls "$dir"/*.intoto.json 2>/dev/null | wc -l | tr -d ' ')
    echo "  $sid  ($count attestations)"
  done
  exit 0
fi

# --- Resolve session ---
if [ -n "${1:-}" ]; then
  SESSION_ID="$1"
else
  # Auto-detect most recent session with attestations
  SESSION_ID=$(ls -t "$SESSIONS_DIR"/*/attestations/*.intoto.json 2>/dev/null | head -1 | xargs dirname 2>/dev/null | xargs dirname 2>/dev/null | xargs basename 2>/dev/null || true)
  if [ -z "$SESSION_ID" ]; then
    echo "No sessions with attestations found in $SESSIONS_DIR"
    echo "Run some tool calls with aflock hooks first."
    exit 1
  fi
fi

ATTEST_DIR="$SESSIONS_DIR/$SESSION_ID/attestations"
if [ ! -d "$ATTEST_DIR" ]; then
  echo "No attestations directory for session: $SESSION_ID"
  exit 1
fi

FILES=$(ls "$ATTEST_DIR"/*.intoto.json 2>/dev/null)
COUNT=$(echo "$FILES" | wc -l | tr -d ' ')

echo "============================================"
echo "  Session: $SESSION_ID"
echo "  Attestations: $COUNT"
echo "============================================"
echo ""

# --- Summary table ---
echo "Tool        Decision  Timestamp            Model"
echo "----------  --------  -------------------  --------------------"
for f in $FILES; do
python3 << PYEOF
import json, base64
env = json.load(open("$f"))
stmt = json.loads(base64.b64decode(env["payload"]))
p = stmt["predicate"]
model = p.get("agentIdentity", {}).get("model", "?")
print(f"{p['toolName']:10}  {p['decision']:8}  {p['timestamp'][:19]}  {model}")
PYEOF
done

echo ""

# --- Signing mode ---
FIRST=$(echo "$FILES" | head -1)
python3 << PYEOF
import json
env = json.load(open("$FIRST"))
keyid = env["signatures"][0]["keyid"]
mode = "Ephemeral (self-signed)" if "ephemeral" in keyid else "SPIRE (X509-SVID)"
print(f"Signing mode: {mode}")
print(f"Key ID: {keyid}")
PYEOF

echo ""

# --- Decode first attestation ---
echo "============================================"
echo "  First Attestation (decoded)"
echo "============================================"
echo ""

echo "--- DSSE Envelope ---"
python3 << PYEOF
import json
env = json.load(open("$FIRST"))
print(f"payloadType: {env['payloadType']}")
print(f"signatures:  {len(env['signatures'])}")
sig = env["signatures"][0]
print(f"keyid:       {sig['keyid']}")
print(f"sig:         {sig['sig'][:40]}...")
has_cert = sig.get("certificate", "").startswith("-----BEGIN")
print(f"certificate: {'present' if has_cert else 'missing'}")
PYEOF

echo ""
echo "--- in-toto Statement ---"
python3 << PYEOF
import json, base64
env = json.load(open("$FIRST"))
stmt = json.loads(base64.b64decode(env["payload"]))
print(json.dumps(stmt, indent=2))
PYEOF
