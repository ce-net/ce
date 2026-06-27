#!/usr/bin/env bash
# Scalability + reliability E2E for the relay/cross-NAT path. Runs on any Docker host (e.g. the
# relay). Builds a controlled mesh of CONTAINERS on one network, but forces relay-routing between
# clients with iptables (each client DROPs traffic to the others, so peer<->peer MUST traverse a
# relay — the firewall-NAT case). Covers what hand-testing can't:
#
#   1) multi-relay        — clients reserve on TWO relays; A reaches B through a relay.
#   2) FAILOVER mid-life  — kill the relay in use; A must reach B through the OTHER relay (v0.1.7
#                           relay_keepalive re-dials + re-reserves). "remove a relay -> just works".
#   3) disconnect/recover — restart a relay; reservations + reachability come back on their own.
#   4) heavy load         — N clients each deploy across the mesh concurrently; measure success rate.
#   5) longevity          — repeat reachability checks over a window; must stay green.
#
# Uses a provided ce binary (default: the host's /usr/local/bin/ce) copied into every container so
# all nodes run the SAME version. Usage:  ./scale-reliability-e2e.sh [CE_BINARY] [NUM_LOAD_CLIENTS]
set -uo pipefail
CE_BIN="${1:-/usr/local/bin/ce}"
LOAD_N="${2:-6}"
NET=cescale
IMG=ubuntu:24.04
PASS=0; FAIL=0
pass(){ echo "  PASS: $*"; PASS=$((PASS+1)); }
fail(){ echo "  FAIL: $*"; FAIL=$((FAIL+1)); }

cleanup(){
  docker ps -aq --filter "name=cs-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create "$NET" >/dev/null

# Spawn a bare container (NET_ADMIN for iptables isolation), drop in the ce binary + deps.
spawn(){ # $1=name
  docker run -d --name "$1" --network "$NET" --cap-add NET_ADMIN "$IMG" sleep infinity >/dev/null
  docker cp "$CE_BIN" "$1:/usr/local/bin/ce" >/dev/null
  docker exec "$1" bash -c 'apt-get update -qq>/dev/null 2>&1; apt-get install -y -qq python3 iptables iproute2 curl ca-certificates>/dev/null 2>&1; chmod +x /usr/local/bin/ce'
}
ip_of(){ docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$1"; }
cein(){ docker exec "$1" bash -lc "$2"; }
nid(){ cein "$1" 'ce id | grep -oE "[0-9a-f]{64}" | head -1'; }
pid(){ cein "$1" 'ce id | grep -oE "12D3[A-Za-z0-9]+" | head -1'; }
height(){ cein "$1" 'curl -s --max-time 6 http://127.0.0.1:8844/status|python3 -c "import sys,json;print(json.load(sys.stdin)[\"height\"])" 2>/dev/null|tr -dc 0-9'; }
# A deploy "reached" the target if it is NOT a discovery timeout (any app-level reply counts).
reached(){ # $1=from $2=alias  -> echoes REACHED / UNREACHABLE
  out=$(cein "$1" "ce deploy alpine:latest --on $2 --cmd echo --cmd ok --fund 1000 --duration 30 2>&1 | head -2")
  if printf '%s' "$out" | grep -qi 'during discovery'; then echo "UNREACHABLE"; else echo "REACHED"; fi
}

start_relay(){ # $1=name
  spawn "$1"; local ip; ip=$(ip_of "$1")
  cein "$1" "CE_EXTERNAL_IP=$ip CE_NO_AUTOBOOTSTRAP=1 nohup ce start --no-mine --no-mdns --api-bind 0.0.0.0 >/tmp/ce.log 2>&1 & sleep 7; true"
}
start_client(){ # $1=name  $2..=relay multiaddrs
  spawn "$1"; local name="$1"; shift
  local args=""; for r in "$@"; do args="$args --bootstrap '$r' --relay '$r'"; done
  cein "$name" "CE_NO_AUTOBOOTSTRAP=1 nohup ce start --light --no-mdns --api-bind 0.0.0.0 $args >/tmp/ce.log 2>&1 & sleep 10; true"
}

echo "=== build mesh: 2 relays + 2 clients (binary: $CE_BIN) ==="
start_relay cs-relayA; start_relay cs-relayB
RA="/ip4/$(ip_of cs-relayA)/tcp/4001/p2p/$(pid cs-relayA)"
RB="/ip4/$(ip_of cs-relayB)/tcp/4001/p2p/$(pid cs-relayB)"
echo "relayA=$RA"; echo "relayB=$RB"
start_client cs-cliA "$RA" "$RB"
start_client cs-cliB "$RA" "$RB"
A_ID=$(nid cs-cliA); B_ID=$(nid cs-cliB)
# iptables: clients cannot talk DIRECTLY (force relay routing). Allow only the two relay IPs.
RA_IP=$(ip_of cs-relayA); RB_IP=$(ip_of cs-relayB); A_IP=$(ip_of cs-cliA); B_IP=$(ip_of cs-cliB)
cein cs-cliA "iptables -A OUTPUT -d $B_IP -j DROP; iptables -A INPUT -s $B_IP -j DROP"
cein cs-cliB "iptables -A OUTPUT -d $A_IP -j DROP; iptables -A INPUT -s $A_IP -j DROP"
echo "isolation: cliA<->cliB direct traffic dropped (must use a relay)"
# B authorizes A so deploys are accepted (else discovery still proves reachability via error type).
G=$(cein cs-cliB "ce grant $A_ID --can deploy,kill,status --resource self 2>/dev/null|tail -1")
cein cs-cliA "ce wallet add b $B_ID --cap $G >/dev/null 2>&1; true"
sleep 8

echo "=== [1] multi-relay reachability: cliA -> cliB ==="
[ "$(reached cs-cliA b)" = REACHED ] && pass "A reached B through a relay (2 relays available)" || fail "A could not reach B with 2 relays up"

echo "=== [2] FAILOVER mid-life: kill relayA, A must reach B via relayB ==="
docker rm -f cs-relayA >/dev/null 2>&1; echo "relayA KILLED"
ok=UNREACHABLE
for i in $(seq 1 8); do sleep 8; r=$(reached cs-cliA b); echo "  t=$((i*8))s after kill: $r"; [ "$r" = REACHED ] && { ok=REACHED; break; }; done
[ "$ok" = REACHED ] && pass "after relayA removed, A failed over to relayB and reached B" || fail "A did NOT fail over to the second relay"

echo "=== [3] disconnect/recover: restart relayB, reachability must self-heal ==="
cein cs-relayB "pkill -f 'ce start'; sleep 1; CE_EXTERNAL_IP=$RB_IP CE_NO_AUTOBOOTSTRAP=1 nohup ce start --no-mine --no-mdns --api-bind 0.0.0.0 >/tmp/ce.log 2>&1 & sleep 2; true"; echo "relayB ce restarted in place (IP preserved)"
ok=UNREACHABLE
for i in $(seq 1 10); do sleep 8; r=$(reached cs-cliA b); echo "  t=$((i*8))s after restart: $r"; [ "$r" = REACHED ] && { ok=REACHED; break; }; done
[ "$ok" = REACHED ] && pass "reachability recovered on its own after relay restart (no node restart)" || fail "reachability did NOT recover after relay restart"

echo "=== [4] heavy load: $LOAD_N clients each deploy across the mesh concurrently ==="
# bring relayA back so there are 2 relays again
start_relay cs-relayA; RA="/ip4/$(ip_of cs-relayA)/tcp/4001/p2p/$(pid cs-relayA)"
RB="/ip4/$(ip_of cs-relayB)/tcp/4001/p2p/$(pid cs-relayB)"
for i in $(seq 1 "$LOAD_N"); do start_client "cs-load$i" "$RA" "$RB" & done; wait
sleep 12
# each load client targets cliB (B grants each)
ok=0
for i in $(seq 1 "$LOAD_N"); do
  LID=$(nid "cs-load$i")
  g=$(cein cs-cliB "ce grant $LID --can deploy,kill,status --resource self 2>/dev/null|tail -1")
  cein "cs-load$i" "ce wallet add b $B_ID --cap $g >/dev/null 2>&1; true"
done
results=$(for i in $(seq 1 "$LOAD_N"); do ( [ "$(reached "cs-load$i" b)" = REACHED ] && echo ok ) & done; wait)
ok=$(printf '%s' "$results" | grep -c ok)
echo "  $ok/$LOAD_N load clients reached B through the relays"
[ "$ok" -ge $(( (LOAD_N*3+3)/4 )) ] && pass "$ok/$LOAD_N concurrent clients reached B under load" || fail "only $ok/$LOAD_N reached under load"

echo "=== [5] longevity: cliA->cliB stays reachable over a 90s window ==="
green=0; total=6
for i in $(seq 1 $total); do [ "$(reached cs-cliA b)" = REACHED ] && green=$((green+1)); sleep 15; done
echo "  $green/$total reachability checks green over 90s"
[ "$green" -ge $((total-1)) ] && pass "stayed reachable over time ($green/$total)" || fail "flaky over time ($green/$total)"

echo "==================== SUMMARY: $PASS passed, $FAIL failed ===================="
[ "$FAIL" -eq 0 ] && echo "RESULT: PASS" || { echo "RESULT: FAIL"; exit 1; }
