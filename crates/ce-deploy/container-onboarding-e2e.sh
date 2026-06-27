#!/usr/bin/env bash
# Container-backend onboarding E2E (no nested virt / no Hetzner quota needed). Runs on any Docker
# host (e.g. the relay): spins up fresh Ubuntu containers and runs the EXACT developer flow —
# `curl install.sh | bash` then `ce start` — asserting a clean machine installs the released binary
# and SYNCS the live ce-net.com network (the failure the desktop hit before the v0.1.4 reset).
#
# This is the "real VM" suite's lightweight sibling for environments that can't nest VMs; the full
# VM version (real Hetzner VMs) is tests/onboarding_e2e.rs. Usage:  ./container-onboarding-e2e.sh
set -uo pipefail
IMG="ubuntu:24.04"
PASS_HEIGHT="${PASS_HEIGHT:-50}"   # reaching this proves it's on the canonical chain, not a genesis fork

echo "=== onboarding: fresh container installs v0.1.4 and joins the live network ==="
OUT=$(docker run --rm "$IMG" bash -c '
  set -e
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq curl python3 ca-certificates procps >/dev/null 2>&1
  curl -sSL https://raw.githubusercontent.com/ce-net/ce/main/install.sh | bash >/dev/null
  export PATH=$HOME/.local/bin:$PATH
  echo "VERSION: $(ce --version)"
  rm -rf ~/.local/share/ce/chain
  nohup ce start --light > /tmp/ce.log 2>&1 &
  H=0
  for i in $(seq 1 40); do
    sleep 6
    H=$(curl -s --max-time 6 http://127.0.0.1:8844/status | python3 -c "import sys,json;print(json.load(sys.stdin)[\"height\"])" 2>/dev/null | tr -dc 0-9)
    H=${H:-0}
    [ "$H" -ge '"$PASS_HEIGHT"' ] && break
  done
  echo "HEIGHT: $H"
  # Reaching a high height = applied the canonical blocks 0..H (bulk-sync path doesnt log per block).
  echo "MISMATCH: $(grep -c "mismatch" /tmp/ce.log 2>/dev/null || true)"
  echo "RELAY_CIRCUIT: $(grep -c "relay circuit listening" /tmp/ce.log 2>/dev/null || true)"
  echo "FORKLINE: $(grep -c "we.re at 1" /tmp/ce.log 2>/dev/null || true)"
')
echo "$OUT"

VER=$(printf '%s\n' "$OUT" | sed -n 's/^VERSION: //p')
H=$(printf '%s\n' "$OUT" | sed -n 's/^HEIGHT: //p' | tr -dc 0-9); H=${H:-0}

echo "--- verdict ---"
case "$VER" in *0.1.4*) : ;; *) echo "RESULT: FAIL — install did not yield v0.1.4 (got '$VER')"; exit 1;; esac
# A fork (the old failure) stays stuck near its own genesis (height ~1); a synced node climbs to the
# live tip. Reaching PASS_HEIGHT proves it adopted the canonical chain.
if [ "$H" -ge "$PASS_HEIGHT" ]; then
  echo "RESULT: PASS — fresh machine installed $VER and SYNCED the live network to height $H (canonical chain, no fork)."
  exit 0
else
  echo "RESULT: FAIL — did not sync (height=$H; need >=$PASS_HEIGHT). Stuck on a fork / not joined."
  exit 1
fi
