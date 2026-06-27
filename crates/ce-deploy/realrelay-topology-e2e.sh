#!/usr/bin/env bash
# Same as relay-topology-e2e but through the REAL ce-net.com relay (which grants reservations).
# Two isolated containers (A on net cea, B on net ceb) both bootstrap+relay the real relay; can A
# reach B through it? This isolates whether cross-NAT-via-a-working-relay actually functions.
set -uo pipefail
RELAY_MA="/ip4/178.105.145.170/tcp/4001/p2p/12D3KooWC6vyMMrtmdWEdpcMx7JZ4Ze5scUhA6BbMdYqnUDC7nr7"
cleanup(){ docker rm -f tA tB >/dev/null 2>&1 || true; docker network rm na nb >/dev/null 2>&1 || true; }
trap cleanup EXIT; cleanup
docker network create na >/dev/null; docker network create nb >/dev/null
mk(){ docker run -d --name "$1" --network "$2" ubuntu:24.04 sleep infinity >/dev/null
  docker exec "$1" bash -c 'apt-get update -qq>/dev/null 2>&1; apt-get install -y -qq curl python3 ca-certificates procps>/dev/null 2>&1; curl -sSL https://raw.githubusercontent.com/ce-net/ce/main/install.sh|bash>/dev/null'; }
cein(){ docker exec "$1" bash -lc "export PATH=\$HOME/.local/bin:\$PATH; $2"; }
echo "=== install A, B (isolated nets) ==="; mk tA na; mk tB nb
echo "=== start both, bootstrap+relay the REAL relay ==="
cein tA "CE_NO_AUTOBOOTSTRAP=1 nohup ce start --light --no-mdns --api-bind 0.0.0.0 --bootstrap '$RELAY_MA' --relay '$RELAY_MA' >/tmp/ce.log 2>&1 & sleep 14; true"
cein tB "CE_NO_AUTOBOOTSTRAP=1 nohup ce start --light --no-mdns --api-bind 0.0.0.0 --bootstrap '$RELAY_MA' --relay '$RELAY_MA' >/tmp/ce.log 2>&1 & sleep 14; true"
A=$(cein tA 'ce id|grep -oE "[0-9a-f]{64}"|head -1'); B=$(cein tB 'ce id|grep -oE "[0-9a-f]{64}"|head -1')
echo "A=$A"; echo "B=$B"
echo "circuit addr on A:"; cein tA 'grep -oE "listening on .*/p2p-circuit/.*" /tmp/ce.log | tail -1 || echo NONE'
echo "circuit addr on B:"; cein tB 'grep -oE "listening on .*/p2p-circuit/.*" /tmp/ce.log | tail -1 || echo NONE'
echo "heights: A=$(cein tA 'curl -s 127.0.0.1:8844/status|python3 -c "import sys,json;print(json.load(sys.stdin)[\"height\"])" 2>/dev/null') B=$(cein tB 'curl -s 127.0.0.1:8844/status|python3 -c "import sys,json;print(json.load(sys.stdin)[\"height\"])" 2>/dev/null')"
echo "=== B grants A, A deploys on B through the real relay ==="
G=$(cein tB "ce grant $A --can deploy,kill,status --resource self 2>/dev/null|tail -1")
cein tA "ce wallet add b $B --cap $G >/dev/null 2>&1; true"
D=$(cein tA "ce deploy alpine:latest --on b --cmd 'echo ok' --fund 1000 --duration 60 2>&1|head -4")
echo "deploy A->B: $D"
if printf '%s' "$D"|grep -qi 'during discovery'; then echo "RESULT: FAIL — even through the REAL relay, A could not reach B"; cein tA 'grep -iE "get_record|put_record|circuit|dial" /tmp/ce.log|tail -15'; else echo "RESULT: PASS — A reached B through the real relay"; fi
