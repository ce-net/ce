#!/usr/bin/env bash
# Relay-topology E2E: reproduce "two NAT'd nodes + one relay" in containers and test whether node A
# can send a directed RPC (ce deploy) to node B THROUGH the relay — the exact laptop<->desktop path.
#
# NAT is simulated with Docker networks: nodeA lives on net `cea`, nodeB on `ceb`, and only `relaysim`
# is attached to BOTH — so A and B can reach the relay but NOT each other directly. If A can still
# deploy on B, relay-routed directed RPC works; if it times out "during discovery", we've reproduced
# the bug in a controlled place we can debug.
#
# Run on any Docker host (e.g. the relay):  ./relay-topology-e2e.sh
set -uo pipefail
IMG=ubuntu:24.04

cleanup() {
  docker rm -f relaysim nodeA nodeB >/dev/null 2>&1 || true
  docker network rm cea ceb >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker network create cea >/dev/null
docker network create ceb >/dev/null

install_ce() { # $1=name $2=network
  docker run -d --name "$1" --network "$2" "$IMG" sleep infinity >/dev/null
  docker exec "$1" bash -c '
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq curl python3 ca-certificates procps iputils-ping >/dev/null 2>&1
    curl -sSL https://raw.githubusercontent.com/ce-net/ce/main/install.sh | bash >/dev/null'
}
ce_in() { docker exec "$1" bash -lc "export PATH=\$HOME/.local/bin:\$PATH; $2"; }
id_of()  { ce_in "$1" 'ce id | grep -oE "[0-9a-f]{64}" | head -1'; }
peer_of(){ ce_in "$1" 'ce id | grep -oE "12D3[A-Za-z0-9]+" | head -1'; }
height_of(){ ce_in "$1" 'curl -s --max-time 6 http://127.0.0.1:8844/status | python3 -c "import sys,json;print(json.load(sys.stdin)[\"height\"])" 2>/dev/null | tr -dc 0-9'; }

echo "=== [1/6] install ce in three containers ==="
install_ce relaysim cea
docker network connect ceb relaysim          # relay is reachable from BOTH nets
install_ce nodeA cea
install_ce nodeB ceb

RELAY_IP_A=$(docker inspect -f '{{(index .NetworkSettings.Networks "cea").IPAddress}}' relaysim)
RELAY_IP_B=$(docker inspect -f '{{(index .NetworkSettings.Networks "ceb").IPAddress}}' relaysim)

echo "=== [2/6] start the relay node (acts as relay + bootstrap) ==="
ce_in relaysim 'CE_NO_AUTOBOOTSTRAP=1 nohup ce start --no-mine --no-mdns --api-bind 0.0.0.0 >/tmp/ce.log 2>&1 & sleep 8; true'
RELAY_PEER=$(peer_of relaysim)
RELAY_MA_A="/ip4/$RELAY_IP_A/tcp/4001/p2p/$RELAY_PEER"
RELAY_MA_B="/ip4/$RELAY_IP_B/tcp/4001/p2p/$RELAY_PEER"
echo "relay peer $RELAY_PEER  (A dials $RELAY_IP_A, B dials $RELAY_IP_B)"

echo "=== [3/6] start A and B, each bootstrapping+relaying ONLY through relaysim ==="
ce_in nodeA "CE_NO_AUTOBOOTSTRAP=1 nohup ce start --light --no-mdns --api-bind 0.0.0.0 --bootstrap '$RELAY_MA_A' --relay '$RELAY_MA_A' >/tmp/ce.log 2>&1 & sleep 10; true"
ce_in nodeB "CE_NO_AUTOBOOTSTRAP=1 nohup ce start --light --no-mdns --api-bind 0.0.0.0 --bootstrap '$RELAY_MA_B' --relay '$RELAY_MA_B' >/tmp/ce.log 2>&1 & sleep 10; true"
A_ID=$(id_of nodeA); B_ID=$(id_of nodeB)
echo "A=$A_ID"; echo "B=$B_ID"

echo "=== [4/6] prove the NAT: A and B can reach relaysim but NOT each other ==="
B_IP=$(docker inspect -f '{{(index .NetworkSettings.Networks "ceb").IPAddress}}' nodeB)
echo -n "A -> relay ping: "; ce_in nodeA "ping -c1 -W2 $RELAY_IP_A >/dev/null 2>&1 && echo OK || echo FAIL"
echo -n "A -> B   ping: "; ce_in nodeA "ping -c1 -W2 $B_IP >/dev/null 2>&1 && echo 'REACHABLE (isolation failed)' || echo 'unreachable (good, simulated NAT)'"

echo "=== [5/6] B grants A deploy authority, then A deploys ON B through the relay ==="
GRANT=$(ce_in nodeB "ce grant $A_ID --can deploy,kill,status --resource self 2>/dev/null | tail -1")
ce_in nodeA "ce wallet add b $B_ID --cap $GRANT >/dev/null 2>&1; true"
echo "circuit listen on A:"; ce_in nodeA 'grep -c p2p-circuit /tmp/ce.log'
echo "circuit listen on B:"; ce_in nodeB 'grep -c p2p-circuit /tmp/ce.log'
echo "--- deploy A -> B ---"
DEPLOY=$(ce_in nodeA "ce deploy alpine:latest --on b --cmd 'echo through-relay-ok' --fund 1000 --duration 60 2>&1 | head -4")
echo "$DEPLOY"

echo "=== [6/6] verdict ==="
if printf '%s' "$DEPLOY" | grep -qi 'during discovery'; then
  echo "RESULT: FAIL (reproduced) — A could NOT reach B through the relay: directed RPC timed out in discovery."
  echo "--- A mesh log (dial/circuit/get_record) ---"; ce_in nodeA 'grep -iE "circuit|dial|get_record|put_record|reservation|discover" /tmp/ce.log | tail -20'
  exit 1
else
  echo "RESULT: PASS — A reached B through the relay (got an application-level reply, not a discovery timeout):"
  echo "  $DEPLOY"
  exit 0
fi
