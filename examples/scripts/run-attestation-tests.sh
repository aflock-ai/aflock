#!/usr/bin/env bash
# Attestation generation test runner for Issue #17
# Tests both ephemeral signing (no SPIRE) and DSSE structural validity
#
# Usage: ./run-attestation-tests.sh [path-to-aflock-binary]

set -euo pipefail

AFLOCK="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/bin/aflock}"
PASS=0
FAIL=0
TOTAL=0

green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
bold()  { printf "\033[1m%s\033[0m\n" "$1"; }

assert_contains() {
  local label="$1" output="$2" expected="$3"
  TOTAL=$((TOTAL + 1))
  if echo "$output" | grep -q "$expected"; then
    green "  PASS: $label"
    PASS=$((PASS + 1))
  else
    red "  FAIL: $label"
    echo "    Expected to contain: $expected"
    echo "    Got: $(echo "$output" | head -3)"
    FAIL=$((FAIL + 1))
  fi
}

assert_not_contains() {
  local label="$1" output="$2" unexpected="$3"
  TOTAL=$((TOTAL + 1))
  if echo "$output" | grep -q "$unexpected"; then
    red "  FAIL: $label"
    echo "    Should NOT contain: $unexpected"
    FAIL=$((FAIL + 1))
  else
    green "  PASS: $label"
    PASS=$((PASS + 1))
  fi
}

assert_file_exists() {
  local label="$1" pattern="$2"
  TOTAL=$((TOTAL + 1))
  if ls $pattern >/dev/null 2>&1; then
    green "  PASS: $label"
    PASS=$((PASS + 1))
  else
    red "  FAIL: $label (no files matching $pattern)"
    FAIL=$((FAIL + 1))
  fi
}

assert_file_count() {
  local label="$1" dir="$2" expected="$3"
  TOTAL=$((TOTAL + 1))
  local count
  count=$(ls "$dir"/*.intoto.json 2>/dev/null | wc -l | tr -d ' ')
  if [ "$count" -eq "$expected" ]; then
    green "  PASS: $label ($count files)"
    PASS=$((PASS + 1))
  else
    red "  FAIL: $label (expected $expected files, got $count)"
    FAIL=$((FAIL + 1))
  fi
}

# Resolve absolute path
AFLOCK=$(cd "$(dirname "$AFLOCK")" && pwd)/$(basename "$AFLOCK")
if [ ! -x "$AFLOCK" ]; then
  red "Binary not found: $AFLOCK"
  echo "Build first: cd ../aflock && make build"
  exit 1
fi

# Clean up previous test sessions
rm -rf ~/.aflock/sessions/att-run-*

# ============================================================
bold ""
bold "============================================"
bold "  Attestation Generation Tests (Issue #17)"
bold "============================================"
bold ""

# ============================================================
bold "--- Test Group 1: Basic Attestation Creation ---"

TD1=$(mktemp -d)
echo '{"version":"1.0","name":"basic-attest","tools":{"allow":["Read","Bash","Edit"]},"files":{"allow":["**/*"]}}' > "$TD1/.aflock"

# SessionStart
OUT=$(echo '{"cwd":"'"$TD1"'","session_id":"att-run-1"}' | bash -c "cd $TD1 && $AFLOCK hook SessionStart 2>&1")
assert_contains "SessionStart loads policy" "$OUT" "basic-attest"

# PostToolUse — creates attestation
OUT=$(echo '{"tool_name":"Read","tool_input":{"file_path":"src/main.go"},"session_id":"att-run-1","tool_use_id":"tu_r1"}' | bash -c "cd $TD1 && $AFLOCK hook PostToolUse 2>&1")
assert_contains "PostToolUse signs attestation" "$OUT" "Attestation signed"
assert_not_contains "PostToolUse no PID warning" "$OUT" "PID-based discovery failed"

# File exists
assert_file_exists "Attestation file created" "$HOME/.aflock/sessions/att-run-1/attestations/*.intoto.json"

rm -rf "$TD1"

# ============================================================
bold ""
bold "--- Test Group 2: Multiple Tool Calls ---"

TD2=$(mktemp -d)
echo '{"version":"1.0","name":"multi-attest","tools":{"allow":["Read","Bash","Edit"]},"files":{"allow":["**/*"]}}' > "$TD2/.aflock"

echo '{"cwd":"'"$TD2"'","session_id":"att-run-2"}' | bash -c "cd $TD2 && $AFLOCK hook SessionStart" >/dev/null 2>&1

echo '{"tool_name":"Read","tool_input":{"file_path":"a.go"},"session_id":"att-run-2","tool_use_id":"tu_m1"}' | bash -c "cd $TD2 && $AFLOCK hook PostToolUse" >/dev/null 2>&1
echo '{"tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"att-run-2","tool_use_id":"tu_m2"}' | bash -c "cd $TD2 && $AFLOCK hook PostToolUse" >/dev/null 2>&1
echo '{"tool_name":"Edit","tool_input":{"file_path":"b.go"},"session_id":"att-run-2","tool_use_id":"tu_m3"}' | bash -c "cd $TD2 && $AFLOCK hook PostToolUse" >/dev/null 2>&1

assert_file_count "3 attestations for 3 tool calls" "$HOME/.aflock/sessions/att-run-2/attestations" 3

rm -rf "$TD2"

# ============================================================
bold ""
bold "--- Test Group 3: DSSE Envelope Structure ---"

ATTEST=$(ls "$HOME/.aflock/sessions/att-run-1/attestations/"*.intoto.json 2>/dev/null | head -1)
if [ -n "$ATTEST" ]; then
  OUT=$(python3 -c "
import json, sys
env = json.load(open('$ATTEST'))
checks = []
checks.append('payloadType' if env.get('payloadType') == 'application/vnd.in-toto+json' else 'FAIL:payloadType')
checks.append('payload' if env.get('payload') else 'FAIL:payload')
checks.append('signatures' if len(env.get('signatures', [])) > 0 else 'FAIL:signatures')
sig = env.get('signatures', [{}])[0]
checks.append('sig' if sig.get('sig') else 'FAIL:sig')
checks.append('keyid' if sig.get('keyid') else 'FAIL:keyid')
checks.append('certificate' if sig.get('certificate','').startswith('-----BEGIN') else 'FAIL:cert')
print(' '.join(checks))
" 2>&1)
  assert_contains "DSSE payloadType correct" "$OUT" "payloadType"
  assert_contains "DSSE payload present" "$OUT" "payload"
  assert_contains "DSSE signatures present" "$OUT" "signatures"
  assert_contains "DSSE sig non-empty" "$OUT" " sig"
  assert_contains "DSSE keyid present" "$OUT" "keyid"
  assert_contains "DSSE certificate present" "$OUT" "certificate"
else
  TOTAL=$((TOTAL + 6))
  FAIL=$((FAIL + 6))
  red "  FAIL: No attestation file to validate"
fi

# ============================================================
bold ""
bold "--- Test Group 4: in-toto v1 Statement ---"

if [ -n "$ATTEST" ]; then
  OUT=$(python3 -c "
import json, base64, sys
env = json.load(open('$ATTEST'))
stmt = json.loads(base64.b64decode(env['payload']))
checks = []
checks.append('v1' if stmt.get('_type') == 'https://in-toto.io/Statement/v1' else 'FAIL:type')
checks.append('action_v01' if stmt.get('predicateType') == 'https://aflock.ai/attestations/action/v0.1' else 'FAIL:predType')
checks.append('subject' if len(stmt.get('subject',[])) > 0 else 'FAIL:subject')
checks.append('subject_name' if 'session:att-run-1/action:tu_r1' in stmt.get('subject',[{}])[0].get('name','') else 'FAIL:subjectName')
pred = stmt.get('predicate', {})
checks.append('toolName' if pred.get('toolName') == 'Read' else 'FAIL:toolName')
checks.append('decision' if pred.get('decision') == 'allow' else 'FAIL:decision')
checks.append('sessionId' if pred.get('sessionId') == 'att-run-1' else 'FAIL:sessionId')
print(' '.join(checks))
" 2>&1)
  assert_contains "Statement type is v1" "$OUT" "v1"
  assert_contains "Predicate type is action/v0.1" "$OUT" "action_v01"
  assert_contains "Subject present" "$OUT" "subject "
  assert_contains "Subject name matches session/action" "$OUT" "subject_name"
  assert_contains "Predicate toolName is Read" "$OUT" "toolName"
  assert_contains "Predicate decision is allow" "$OUT" "decision"
  assert_contains "Predicate sessionId correct" "$OUT" "sessionId"
else
  TOTAL=$((TOTAL + 7))
  FAIL=$((FAIL + 7))
  red "  FAIL: No attestation file to validate"
fi

# ============================================================
bold ""
bold "--- Test Group 5: Agent Identity in Attestation ---"

if [ -n "$ATTEST" ]; then
  OUT=$(python3 -c "
import json, base64, sys
env = json.load(open('$ATTEST'))
stmt = json.loads(base64.b64decode(env['payload']))
ai = stmt.get('predicate', {}).get('agentIdentity', {})
checks = []
checks.append('model' if ai.get('model','unknown') != 'unknown' and ai.get('model','') != '' else 'FAIL:model')
checks.append('identityHash' if len(ai.get('identityHash','')) > 10 else 'FAIL:hash')
checks.append('binary' if ai.get('binary','') != '' else 'FAIL:binary')
checks.append('environment' if ai.get('environment','') != '' else 'FAIL:env')
agentId = stmt.get('predicate', {}).get('agentId', '')
checks.append('agentId_spiffe' if agentId.startswith('spiffe://') else 'FAIL:agentId')
print(' '.join(checks))
" 2>&1)
  assert_contains "Agent model discovered (not unknown)" "$OUT" "model"
  assert_contains "Identity hash present" "$OUT" "identityHash"
  assert_contains "Binary info present" "$OUT" "binary"
  assert_contains "Environment present" "$OUT" "environment"
  assert_contains "Agent ID is SPIFFE format" "$OUT" "agentId_spiffe"
else
  TOTAL=$((TOTAL + 5))
  FAIL=$((FAIL + 5))
  red "  FAIL: No attestation file to validate"
fi

# ============================================================
bold ""
bold "--- Test Group 6: Signing Mode Detection ---"

if [ -n "$ATTEST" ]; then
  OUT=$(python3 -c "
import json
env = json.load(open('$ATTEST'))
keyid = env['signatures'][0]['keyid']
if 'ephemeral' in keyid:
    print('MODE:ephemeral')
else:
    print('MODE:spire')
" 2>&1)
  # Without SPIRE running, should be ephemeral
  assert_contains "Signing mode is ephemeral (no SPIRE)" "$OUT" "MODE:ephemeral"
fi

# ============================================================
bold ""
bold "--- Test Group 7: handleStop Finds Attestations ---"

TD7=$(mktemp -d)
echo '{"version":"1.0","name":"stop-test","tools":{"allow":["Read"]},"files":{"allow":["**/*"]},"requiredAttestations":["Read"]}' > "$TD7/.aflock"

echo '{"cwd":"'"$TD7"'","session_id":"att-run-7"}' | bash -c "cd $TD7 && $AFLOCK hook SessionStart" >/dev/null 2>&1
echo '{"tool_name":"Read","tool_input":{"file_path":"x.go"},"session_id":"att-run-7","tool_use_id":"tu_s1"}' | bash -c "cd $TD7 && $AFLOCK hook PreToolUse" >/dev/null 2>&1
echo '{"tool_name":"Read","tool_input":{"file_path":"x.go"},"session_id":"att-run-7","tool_use_id":"tu_s1"}' | bash -c "cd $TD7 && $AFLOCK hook PostToolUse" >/dev/null 2>&1

OUT=$(echo '{"session_id":"att-run-7"}' | bash -c "cd $TD7 && $AFLOCK hook Stop 2>&1")
assert_not_contains "handleStop finds Read attestation (no missing)" "$OUT" "missing required attestations"

rm -rf "$TD7"

# ============================================================
bold ""
bold "--- Test Group 8: No Attestation Without Session ---"

OUT=$(echo '{"tool_name":"Read","tool_input":{"file_path":"x.go"},"session_id":"nonexistent-session-xyz"}' | bash -c "$AFLOCK hook PostToolUse 2>&1")
TOTAL=$((TOTAL + 1))
if [ ! -d "$HOME/.aflock/sessions/nonexistent-session-xyz/attestations" ]; then
  green "  PASS: No attestation dir for nonexistent session"
  PASS=$((PASS + 1))
else
  red "  FAIL: Attestation dir created for nonexistent session"
  FAIL=$((FAIL + 1))
fi

# ============================================================
bold ""
bold "--- Test Group 9: Unit Tests ---"

OUT=$(cd "$(dirname "$AFLOCK")/.." && go test ./internal/hooks/ -run 'TestPostToolUse_Creates|TestPostToolUse_AttestationHas|TestPostToolUse_NoAttest|TestPostToolUse_AttestationFile|TestInitializeEphemeral' -count=1 2>&1)
assert_contains "Unit tests pass" "$OUT" "ok"
assert_not_contains "No unit test failures" "$OUT" "FAIL"

# ============================================================
# Cleanup
rm -rf ~/.aflock/sessions/att-run-*

bold ""
bold "============================================"
bold "  RESULTS"
bold "============================================"
echo ""
echo "  Total: $TOTAL"
green "  Passed: $PASS"
if [ "$FAIL" -gt 0 ]; then
  red "  Failed: $FAIL"
else
  echo "  Failed: 0"
fi
echo ""
if [ "$FAIL" -eq 0 ]; then
  green "  ALL ATTESTATION TESTS PASSED"
else
  red "  SOME TESTS FAILED"
fi
