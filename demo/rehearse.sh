#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# demo/rehearse.sh -- the one-command dress rehearsal of the AWS demo, four steps:
#
#   1. Strands on Amazon Bedrock: the agent's refund held, approved, run once, replay refused, checked offline
#   2. the AgentCore Gateway REQUEST interceptor, run locally (demo/run_interceptor_local.py)
#   3. Requisition as the Gateway TARGET, run locally (demo/run_target_local.py)
#   4. airgap: step 1's records re-checked in docker --network none, and a one-character change FAILS
#
# Steps 1-3 call the live lab (and step 1, Amazon Bedrock); each step stops at "APPROVE AT" until two
# approver accounts approve in the console. Each step's full transcript is written under $OUT; the screen shows a short version
# (demo/present.py: no lab-verify raw output, credentials elided).
#
#   export REQUISITION_URL=http://127.0.0.1:4103 REQUISITION_CRED=... REQUISITION_PRINCIPAL=...
#   export REQUISITION_LAB_KEY_FILE=...       # required; steps 1 and 3 refuse unless GET /v1/keys serves the
#                                             # same bytes; step 2 checks every signature against it
#   export REQUISITION_DEMO_DIR=...           # required; see below
#   demo/rehearse.sh
#
# Knobs (environment):
#   STRANDS_MODE=bedrock|scripted   step 1's model (default bedrock; scripted calls no model)
#   REQUIRE_PQ=1|0                  require each record's ML-DSA-87 co-signature (default 1; 0 against a server without co-signatures),
#                                   at RUN time in all three forms (the tool runs only on a checked record) and in
#                                   the offline and airgap checks
#   STEPS="1 2 3 4"                 which steps
#   REQUISITION_DEMO_DIR=<dir>      REQUIRED, no default: the demo folder (req/ is a Requisition checkout;
#                                   transcripts go to log/)
#   REQUISITION_LOAD_WRAPPER=<cmd>  optional: a command placed before docker in step 4 (a resource-limit script, say)
#   OUT=<dir>                       where transcripts go (default $REQUISITION_DEMO_DIR/log/rehearsal-<UTC>)
#   REHEARSE_DRY=1                  a DRY RUN: a local fake /v1 (tests/fake_server_main.py, NOT Requisition)
#                                   that auto-approves, STRANDS_MODE=scripted; no live server, no Bedrock
set -uo pipefail
cd "$(dirname "$0")/.."
REPO=$(pwd)
: "${REQUISITION_DEMO_DIR:?set REQUISITION_DEMO_DIR to the demo folder (req/ is a Requisition checkout; transcripts go to log/)}"
export REQUISITION_DEMO_DIR   # the demos read it
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=${OUT:-$REQUISITION_DEMO_DIR/log/rehearsal-$STAMP}
STEPS=${STEPS:-"1 2 3 4"}
REQUIRE_PQ=${REQUIRE_PQ:-1}
STRANDS_MODE=${STRANDS_MODE:-bedrock}
mkdir -p "$OUT"
FAKE_PID=
cleanup() { [ -n "$FAKE_PID" ] && kill "$FAKE_PID" 2>/dev/null; }
trap cleanup EXIT

if [ "${REHEARSE_DRY:-0}" = 1 ]; then
  STRANDS_MODE=scripted
  uv run python -m tests.fake_server_main --env-out "$OUT/dry-env.sh" --keys-out "$OUT/dry-lab-keys.json" \
    --newer-routes --cosign signed --auto-approve-after 2 > "$OUT/dry-server.log" 2>&1 &
  FAKE_PID=$!
  for _ in $(seq 50); do [ -s "$OUT/dry-env.sh" ] && break; sleep 0.2; done
  # shellcheck disable=SC1091
  . "$OUT/dry-env.sh"
  echo "DRY RUN: a local fake /v1 ($REQUISITION_URL), NOT Requisition; no Bedrock"
fi

: "${REQUISITION_URL:?set REQUISITION_URL}" "${REQUISITION_CRED:?set REQUISITION_CRED}"
: "${REQUISITION_PRINCIPAL:?set REQUISITION_PRINCIPAL}" "${REQUISITION_LAB_KEY_FILE:?set REQUISITION_LAB_KEY_FILE}"
if [ "$REQUIRE_PQ" = 1 ]; then PQ=--require-pq; else PQ=--no-require-pq; fi
export REQUISITION_REQUIRE_PQ=$REQUIRE_PQ   # the interceptor (step 2) reads it at run time

declare -A RESULT
banner() { printf '\n==== %s ====\n' "$1"; }
show() { python3 -I demo/present.py "$1"; }

for step in $STEPS; do
  case $step in
    1)
      banner "1. Strands agent on Amazon Bedrock ($STRANDS_MODE): the refund held, approved, run once"
      args=(--transcript "$OUT/1-strands.txt" "$PQ")
      [ "$STRANDS_MODE" = scripted ] && args+=(--scripted)
      [ "${REHEARSE_DRY:-0}" = 1 ] && args+=(--poll 0.2 --timeout 30)
      uv run python demo/run_demo.py "${args[@]}" > "$OUT/1-strands.log" 2>&1; RESULT[1]=$?
      show "$OUT/1-strands.txt" ;;
    2)
      banner "2. AgentCore Gateway REQUEST interceptor, run locally (not deployed)"
      args=(--transcript "$OUT/2-interceptor.txt")
      [ "${REHEARSE_DRY:-0}" = 1 ] && args+=(--poll 0.2 --timeout 30)
      uv run python demo/run_interceptor_local.py "${args[@]}" > "$OUT/2-interceptor.log" 2>&1; RESULT[2]=$?
      show "$OUT/2-interceptor.txt" ;;
    3)
      banner "3. Requisition as the Gateway TARGET (MCP server), run locally (not deployed)"
      args=(--transcript "$OUT/3-target.txt" "$PQ")
      [ "${REHEARSE_DRY:-0}" = 1 ] && args+=(--poll 0.2 --timeout 30)
      uv run python demo/run_target_local.py "${args[@]}" > "$OUT/3-target.log" 2>&1; RESULT[3]=$?
      show "$OUT/3-target.txt" ;;
    4)
      banner "4. Airgap: step 1's records re-checked with no network; a one-character change fails"
      if [ -f "$OUT/1-strands-records/manifest.json" ]; then
        uv run python demo/run_airgap.py --records "$OUT/1-strands-records" --transcript "$OUT/4-airgap.txt" "$PQ" \
          > "$OUT/4-airgap.log" 2>&1; RESULT[4]=$?
        show "$OUT/4-airgap.txt"
      else
        echo "no records from step 1 in $OUT/1-strands-records"; RESULT[4]=1
      fi ;;
    *) echo "unknown step $step"; RESULT[$step]=2 ;;
  esac
done

banner "Rehearsal summary ($OUT)"
rc=0
for step in $STEPS; do
  r=${RESULT[$step]:-1}
  [ "$r" = 0 ] && word=PASS || { word="FAIL (exit $r; see $OUT/$step-*.log)"; rc=1; }
  echo "  step $step: $word"
done
exit $rc
