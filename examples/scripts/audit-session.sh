#!/usr/bin/env bash
# Audit a session — shows WHO did WHAT, WHEN, and the cryptographic proof
#
# Usage:
#   ./audit-session.sh                    # auto-detect most recent session
#   ./audit-session.sh <session-id>       # specific session
#   ./audit-session.sh --list             # list all sessions

set -euo pipefail

SESSIONS_DIR="$HOME/.aflock/sessions"

# --- List mode ---
if [ "${1:-}" = "--list" ]; then
  echo ""
  echo "Sessions:"
  echo ""
  printf "  %-45s  %-8s  %-8s  %s\n" "SESSION ID" "ACTIONS" "ATTESTS" "POLICY"
  printf "  %-45s  %-8s  %-8s  %s\n" "----------" "-------" "-------" "------"
  for dir in "$SESSIONS_DIR"/*/; do
    [ -d "$dir" ] || continue
    sid=$(basename "$dir")
    attest_count=0
    [ -d "$dir/attestations" ] && attest_count=$(ls "$dir/attestations/"*.intoto.json 2>/dev/null | wc -l | tr -d ' ')
python3 << PYEOF
import json, os
try:
    s = json.load(open("$dir/state.json"))
    actions = len(s.get("actions", []))
    policy = s.get("policy", {}).get("name", "?")
    print(f"  {'$sid':45}  {actions:<8}  {$attest_count:<8}  {policy}")
except:
    print(f"  {'$sid':45}  {'?':<8}  {$attest_count:<8}  ?")
PYEOF
  done
  echo ""
  exit 0
fi

# --- Resolve session ---
if [ -n "${1:-}" ]; then
  SESSION_ID="$1"
else
  SESSION_ID=$(ls -t "$SESSIONS_DIR"/*/state.json 2>/dev/null | head -1 | xargs dirname 2>/dev/null | xargs basename 2>/dev/null || true)
  if [ -z "$SESSION_ID" ]; then
    echo "No sessions found. Run aflock hooks first."
    exit 1
  fi
fi

STATE="$SESSIONS_DIR/$SESSION_ID/state.json"
ATTEST_DIR="$SESSIONS_DIR/$SESSION_ID/attestations"

if [ ! -f "$STATE" ]; then
  echo "No state.json for session: $SESSION_ID"
  exit 1
fi

# ============================================================
echo ""
echo "============================================"
echo "  Session Audit: $SESSION_ID"
echo "============================================"
echo ""

# --- WHO ---
echo "--- WHO (Agent Identity) ---"
echo ""
python3 << PYEOF
import json
s = json.load(open("$STATE"))
ai = s.get("agent_identity_meta", {})
if ai:
    print(f"  Model:        {ai.get('model', '?')}")
    print(f"  Version:      {ai.get('model_version', '?')}")
    print(f"  Binary:       {ai.get('binary_name', '?')}@{ai.get('binary_version', '?')}")
    print(f"  Binary hash:  {ai.get('binary_digest', '?')[:32]}...")
    print(f"  Environment:  {ai.get('environment', '?')}")
    print(f"  Identity:     {ai.get('identity_hash', '?')}")
else:
    print("  (no identity recorded)")
PYEOF

# --- WHAT (actions) ---
echo ""
echo "--- WHAT (All Actions — allow + deny) ---"
echo ""
python3 << PYEOF
import json
s = json.load(open("$STATE"))
actions = s.get("actions", [])
if not actions:
    print("  (no actions recorded)")
else:
    print(f"  {'#':>3}  {'TIME':19}  {'DECISION':8}  {'TOOL':12}  {'TOOL USE ID':25}  INPUT")
    print(f"  {'─'*3}  {'─'*19}  {'─'*8}  {'─'*12}  {'─'*25}  {'─'*30}")
    for i, a in enumerate(actions, 1):
        ts = a.get("timestamp", "?")[:19]
        dec = a.get("decision", "?")
        tool = a.get("tool_name", "?")
        tuid = a.get("tool_use_id", "")[:25]
        inp = ""
        try:
            ti = json.loads(a.get("tool_input", "{}")) if isinstance(a.get("tool_input"), str) else a.get("tool_input", {})
            if "file_path" in ti:
                inp = ti["file_path"]
            elif "command" in ti:
                inp = ti["command"][:40]
            elif "pattern" in ti:
                inp = ti["pattern"]
        except:
            pass
        color = "\033[32m" if dec == "allow" else "\033[31m"
        reset = "\033[0m"
        print(f"  {i:3}  {ts}  {color}{dec:8}{reset}  {tool:12}  {tuid:25}  {inp}")
PYEOF

# --- WHEN (metrics) ---
echo ""
echo "--- WHEN (Session Metrics) ---"
echo ""
python3 << PYEOF
import json
s = json.load(open("$STATE"))
m = s.get("metrics", {})
print(f"  Started:     {s.get('started_at', '?')}")
print(f"  Turns:       {m.get('turns', 0)}")
print(f"  Tool calls:  {m.get('toolCalls', 0)}")
print(f"  Tokens in:   {m.get('tokensIn', 0)}")
print(f"  Tokens out:  {m.get('tokensOut', 0)}")
print(f"  Cost USD:    \${m.get('costUSD', 0):.4f}")
tools = m.get("tools", {})
if tools:
    print(f"  By tool:     {', '.join(f'{k}={v}' for k,v in tools.items())}")
PYEOF

# --- PROOF (attestations) ---
echo ""
echo "--- PROOF (Signed Attestations) ---"
echo ""

if [ -d "$ATTEST_DIR" ] && ls "$ATTEST_DIR"/*.intoto.json >/dev/null 2>&1; then
  COUNT=$(ls "$ATTEST_DIR"/*.intoto.json | wc -l | tr -d ' ')
  echo "  $COUNT attestation(s) in $ATTEST_DIR"
  echo ""
  printf "  %-19s  %-10s  %-8s  %-18s  %s\n" "TIMESTAMP" "TOOL" "DECISION" "SIGNING MODE" "SUBJECT"
  printf "  %-19s  %-10s  %-8s  %-18s  %s\n" "─────────────────" "──────────" "────────" "──────────────────" "───────────────────────────"

  for f in "$ATTEST_DIR"/*.intoto.json; do
python3 << PYEOF
import json, base64
env = json.load(open("$f"))
stmt = json.loads(base64.b64decode(env["payload"]))
p = stmt["predicate"]
mode = "Ephemeral" if "ephemeral" in env["signatures"][0]["keyid"] else "SPIRE"
subj = stmt["subject"][0]["name"]
print(f"  {p['timestamp'][:19]}  {p['toolName']:10}  {p['decision']:8}  {mode:18}  {subj}")
PYEOF
  done

  # Structural validation
  echo ""
  echo "  Structural checks on first attestation:"
  FIRST=$(ls "$ATTEST_DIR"/*.intoto.json | head -1)
python3 << PYEOF
import json, base64
env = json.load(open("$FIRST"))
stmt = json.loads(base64.b64decode(env["payload"]))
sig = env["signatures"][0]

checks = [
    ("DSSE payloadType",     env.get("payloadType") == "application/vnd.in-toto+json"),
    ("DSSE payload",         len(env.get("payload", "")) > 0),
    ("DSSE signature",       len(sig.get("sig", "")) > 0),
    ("DSSE certificate",     sig.get("certificate", "").startswith("-----BEGIN")),
    ("SPIFFE keyid",         sig.get("keyid", "").startswith("spiffe://")),
    ("in-toto v1",           stmt.get("_type") == "https://in-toto.io/Statement/v1"),
    ("action/v0.1 predicate",stmt.get("predicateType") == "https://aflock.ai/attestations/action/v0.1"),
    ("subject present",      len(stmt.get("subject", [])) > 0),
    ("toolName present",     "toolName" in stmt.get("predicate", {})),
    ("agentIdentity",        "agentIdentity" in stmt.get("predicate", {})),
    ("metrics",              "metrics" in stmt.get("predicate", {})),
]
passed = sum(1 for _, ok in checks if ok)
for name, ok in checks:
    mark = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
    print(f"    {mark}: {name}")
print(f"\n  {passed}/{len(checks)} valid")
PYEOF

else
  echo "  (no attestations for this session)"
fi

# --- Policy ---
echo ""
echo "--- POLICY ---"
echo ""
python3 << PYEOF
import json
s = json.load(open("$STATE"))
pol = s.get("policy", {})
print(f"  Name:     {pol.get('name', '?')}")
print(f"  Tools:    allow={pol.get('tools',{}).get('allow',[])}  deny={pol.get('tools',{}).get('deny',[])}")
print(f"  Files:    deny={pol.get('files',{}).get('deny',[])}")
ra = pol.get("requiredAttestations", [])
if ra:
    print(f"  Required: {ra}")
limits = pol.get("limits", {})
if limits:
    parts = []
    for k, v in limits.items():
        if isinstance(v, dict):
            parts.append(f"{k}={v.get('value','?')} ({v.get('enforcement','?')})")
    print(f"  Limits:   {', '.join(parts)}")
PYEOF

echo ""
echo "============================================"
echo ""
