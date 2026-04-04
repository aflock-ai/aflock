#!/usr/bin/env bash
# Attestation Demo — Full lifecycle with requiredAttestations
#
# Tests: SessionStart → PreToolUse → PostToolUse (attestation) → Stop (verify attestations)
#
# Usage: ./run-demo.sh [path-to-aflock-binary]

set -euo pipefail

AFLOCK="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/bin/aflock}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_ID="demo-$(date +%s)"

bold() { printf "\033[1m%s\033[0m\n" "$1"; }
green() { printf "\033[32m%s\033[0m\n" "$1"; }
red() { printf "\033[31m%s\033[0m\n" "$1"; }

if [ ! -x "$AFLOCK" ]; then
  red "Binary not found: $AFLOCK"
  echo "Build: cd /Users/rahulxf/work-dir/aflock && make build"
  exit 1
fi

bold ""
bold "============================================"
bold "  Attestation Demo (with requiredAttestations)"
bold "  Session: $SESSION_ID"
bold "============================================"

# ============================================================
bold ""
bold "--- Step 1: SessionStart ---"
echo '{"cwd":"'"$DIR"'","session_id":"'"$SESSION_ID"'"}' | \
  bash -c "cd $DIR && $AFLOCK hook SessionStart 2>&1"

# ============================================================
bold ""
bold "--- Step 2: PreToolUse (Read — allowed) ---"
echo '{"tool_name":"Read","tool_input":{"file_path":"src/main.go"},"session_id":"'"$SESSION_ID"'","tool_use_id":"tu_read_1"}' | \
  bash -c "cd $DIR && $AFLOCK hook PreToolUse 2>&1"

# ============================================================
bold ""
bold "--- Step 3: PostToolUse (Read — creates attestation) ---"
echo '{"tool_name":"Read","tool_input":{"file_path":"src/main.go"},"session_id":"'"$SESSION_ID"'","tool_use_id":"tu_read_1"}' | \
  bash -c "cd $DIR && $AFLOCK hook PostToolUse 2>&1"

# ============================================================
bold ""
bold "--- Step 4: PreToolUse (Bash — allowed) ---"
echo '{"tool_name":"Bash","tool_input":{"command":"go test ./..."},"session_id":"'"$SESSION_ID"'","tool_use_id":"tu_bash_1"}' | \
  bash -c "cd $DIR && $AFLOCK hook PreToolUse 2>&1"

# ============================================================
bold ""
bold "--- Step 5: PostToolUse (Bash — creates attestation) ---"
echo '{"tool_name":"Bash","tool_input":{"command":"go test ./..."},"session_id":"'"$SESSION_ID"'","tool_use_id":"tu_bash_1"}' | \
  bash -c "cd $DIR && $AFLOCK hook PostToolUse 2>&1"

# ============================================================
bold ""
bold "--- Step 6: PreToolUse (Read .env — DENIED) ---"
echo '{"tool_name":"Read","tool_input":{"file_path":".env"},"session_id":"'"$SESSION_ID"'","tool_use_id":"tu_deny_1"}' | \
  bash -c "cd $DIR && $AFLOCK hook PreToolUse 2>&1"

# ============================================================
bold ""
bold "--- Step 7: Stop (checks requiredAttestations) ---"
bold "  Policy requires attestations for: Read, Bash"
OUT=$(echo '{"session_id":"'"$SESSION_ID"'"}' | \
  bash -c "cd $DIR && $AFLOCK hook Stop 2>&1")
echo "$OUT"
if echo "$OUT" | grep -q "missing"; then
  red "  FAIL: Stop reported missing attestations"
else
  green "  PASS: All required attestations found"
fi

# ============================================================
bold ""
bold "--- Step 8: Inspect Attestations ---"
ATTEST_DIR="$HOME/.aflock/sessions/$SESSION_ID/attestations"
echo "  Attestation directory: $ATTEST_DIR"
echo ""

if [ -d "$ATTEST_DIR" ]; then
  echo "  Files:"
  ls -1 "$ATTEST_DIR" | while read f; do echo "    $f"; done
  echo ""

  echo "  Summary:"
  echo "  Tool        Decision  Timestamp            Signing Mode"
  echo "  ----------  --------  -------------------  ------------------"
  for f in "$ATTEST_DIR"/*.intoto.json; do
python3 << PYEOF
import json, base64
env = json.load(open("$f"))
stmt = json.loads(base64.b64decode(env["payload"]))
p = stmt["predicate"]
mode = "Ephemeral" if "ephemeral" in env["signatures"][0]["keyid"] else "SPIRE"
print(f"  {p['toolName']:10}  {p['decision']:8}  {p['timestamp'][:19]}  {mode}")
PYEOF
  done

  echo ""
  bold "--- Step 9: Verify DSSE Structure ---"
  FIRST=$(ls "$ATTEST_DIR"/*.intoto.json | head -1)
python3 << PYEOF
import json, base64

env = json.load(open("$FIRST"))

checks = []
checks.append(("payloadType = application/vnd.in-toto+json", env.get("payloadType") == "application/vnd.in-toto+json"))
checks.append(("payload is base64",                          len(env.get("payload", "")) > 0))
checks.append(("has signatures",                             len(env.get("signatures", [])) > 0))

sig = env["signatures"][0]
checks.append(("sig is non-empty",                           len(sig.get("sig", "")) > 0))
checks.append(("keyid is SPIFFE format",                     sig.get("keyid", "").startswith("spiffe://")))
checks.append(("certificate present",                        sig.get("certificate", "").startswith("-----BEGIN")))

stmt = json.loads(base64.b64decode(env["payload"]))
checks.append(("Statement type = v1",                        stmt.get("_type") == "https://in-toto.io/Statement/v1"))
checks.append(("predicateType = action/v0.1",                stmt.get("predicateType") == "https://aflock.ai/attestations/action/v0.1"))
checks.append(("has subject",                                len(stmt.get("subject", [])) > 0))
checks.append(("predicate has toolName",                     "toolName" in stmt.get("predicate", {})))
checks.append(("predicate has agentIdentity",                "agentIdentity" in stmt.get("predicate", {})))
checks.append(("predicate has metrics",                      "metrics" in stmt.get("predicate", {})))

passed = sum(1 for _, ok in checks if ok)
for name, ok in checks:
    print(f"  {'PASS' if ok else 'FAIL'}: {name}")
print(f"\n  {passed}/{len(checks)} checks passed")
PYEOF

else
  red "  No attestations directory found!"
fi

bold ""
bold "============================================"
bold "  Demo complete. Session: $SESSION_ID"
bold "============================================"
bold ""
echo "  To inspect further:"
echo "    ../scripts/inspect-attestation.sh $SESSION_ID"
echo ""
echo "  To clean up:"
echo "    rm -rf ~/.aflock/sessions/$SESSION_ID"
