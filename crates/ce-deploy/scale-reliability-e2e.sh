#!/usr/bin/env bash
# Scalability + reliability E2E for the relay/cross-NAT path. Runs on any Docker host (e.g. the
# relay). Builds a controlled mesh of CONTAINERS and forces relay-routing between clients by putting
# each client behind its OWN NAT — faithfully modelling the real home/office router case instead of
# a hard packet DROP.
#
# WHY A REAL NAT, NOT iptables DROP (the old bug):
#   The previous version isolated clients with `iptables -A OUTPUT/-A INPUT ... -j DROP` between the
#   two client IPs. That blackholes ALL peer traffic in both directions — including the simultaneous
#   outbound SYN/QUIC packets that libp2p DCUtR uses to hole-punch. Real NAT does the opposite: it
#   *permits* outbound connections and lets the return path of an outbound flow back in (conntrack),
#   which is exactly what makes hole-punching work. So the hard DROP produced false "connection lost"
#   failures that DO NOT happen behind a real router (proven: the live Debian desktop behind real NAT
#   does multi-MB SSH-over-tunnel + deploys fine). This rewrite models NAT faithfully:
#
#   Topology per client:  cli ──(private --internal LAN)── rtr ──(MASQUERADE)── public net ── relays
#     * Each client sits alone on its OWN `--internal` docker network (no docker egress of its own).
#     * A per-client router container is dual-homed (LAN + public) and does
#         `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE` + ip_forward.
#       The client's default route is the router, so it can make OUTBOUND connections (reach the
#       relays) and the return traffic of those flows comes back (conntrack) — but it CANNOT receive
#       unsolicited inbound, and the two clients live on different private subnets that docker network
#       isolation keeps from routing to each other directly. Peer<->peer therefore needs a relay, and
#       DCUtR hole-punch through the two cone-NATs still works (the realistic case). This is what a
#       NAT'd laptop + NAT'd desktop actually look like.
#     * Each router DROPs forwarding to 178.105.145.170 and the public gateway, so test clients can
#       never flap-connect to the real ce-net.com relay on the host and pollute results.
#
# DEPLOY TARGET RUNS A REAL WORKLOAD: reached() requires an ACTUAL successful deploy (a job_id), not
# just "the RPC didn't time out" — a relayed RPC that connects then dies (e.g. a circuit byte/time
# cap) must count as FAILURE. To emit a real job_id the target node needs a runtime, so the deploy
# TARGET container (cli B, and the load target) mounts the host docker socket → it actually launches
# the alpine cell on the host docker and returns a job_id, exercising the full request/response over
# the cross-NAT circuit. (v0.1.12 raised the relay circuit limits to 12h / u64::MAX so a long deploy
# over a relay circuit is not killed mid-stream.)
#
#   1) multi-relay        — clients reserve on TWO relays; A reaches B through a relay.
#   2) FAILOVER mid-life  — kill the relay in use (process, in place); A must reach B through the
#                           OTHER relay (v0.1.7 relay_keepalive re-dials + re-reserves).
#   3) disconnect/recover — restore relayA, then restart relayB in place; the surviving relay carries
#                           discovery + circuits so reachability self-heals (a NAT'd node redials and
#                           re-reserves on its own). NB: a node's SOLE relay restarting is a known
#                           single point of failure (the relay's DHT record store is in-memory and
#                           starts empty) — multi-relay is precisely what masks it, which is why this
#                           scenario keeps relayA live throughout relayB's restart.
#   4) heavy load         — N clients (behind a shared NAT) each deploy onto B concurrently; rate.
#   5) longevity          — repeat reachability checks over a window; must stay green.
#
# Uses a provided ce binary (default: the host's /usr/local/bin/ce) copied into every container so
# all nodes run the SAME version. Usage:  ./scale-reliability-e2e.sh [CE_BINARY] [NUM_LOAD_CLIENTS]
set -uo pipefail
CE_BIN="${1:-/usr/local/bin/ce}"
LOAD_N="${2:-6}"
PUB=natnet-pub
IMG=nat-ce-base
SOCK=/var/run/docker.sock
PASS=0; FAIL=0
pass(){ echo "  PASS: $*"; PASS=$((PASS+1)); }
fail(){ echo "  FAIL: $*"; FAIL=$((FAIL+1)); }

cleanup(){
  docker ps -aq --filter "name=nat-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  for n in "$PUB" natnet-lanA natnet-lanB natnet-lanLoad; do docker network rm "$n" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT
cleanup

# Base image with deps baked in (built once) — avoids slow/flaky per-container apt and keeps spawn
# fast enough for the load + longevity scenarios.
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "building $IMG (one time)..."
  d=$(mktemp -d)
  cat > "$d/Dockerfile" <<'DF'
FROM ubuntu:24.04
RUN apt-get update -qq && apt-get install -y -qq python3 iptables iproute2 curl ca-certificates procps >/dev/null 2>&1
DF
  docker build -q -t "$IMG" "$d" >/dev/null; rm -rf "$d"
fi

docker network create "$PUB" >/dev/null
docker network create --internal natnet-lanA >/dev/null
docker network create --internal natnet-lanB >/dev/null
docker network create --internal natnet-lanLoad >/dev/null
PUB_GW=$(docker network inspect "$PUB" -f '{{(index .IPAM.Config 0).Gateway}}')

cein(){ docker exec "$1" bash -lc "$2"; }
ip_on(){ docker inspect -f "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$1"; }
nid(){ cein "$1" 'ce id | grep -oE "[0-9a-f]{64}" | head -1'; }
pid(){ cein "$1" 'ce id | grep -oE "12D3[A-Za-z0-9]+" | head -1'; }
# A deploy "reached" the target only if it returned a real job_id (a full request/response completed
# over the circuit) — a connect-then-die circuit yields no job_id and is correctly counted UNREACHABLE.
reached(){ # $1=from $2=alias  -> echoes REACHED / UNREACHABLE
  out=$(cein "$1" "ce deploy alpine:latest --on $2 --cmd echo --cmd ok --fund 1000 --duration 30 2>&1 | head -3")
  if printf '%s' "$out" | grep -qiE 'job_id|deployed on'; then echo "REACHED"; else echo "UNREACHABLE"; fi
}

# A relay lives on the public network with a public-style address.
start_relay(){ # $1=name
  docker run -d --name "$1" --network "$PUB" --cap-add NET_ADMIN "$IMG" sleep infinity >/dev/null
  docker cp "$CE_BIN" "$1:/usr/local/bin/ce" >/dev/null
  local ip; ip=$(ip_on "$1" "$PUB")
  cein "$1" "CE_EXTERNAL_IP=$ip CE_NO_AUTOBOOTSTRAP=1 nohup ce start --no-mine --no-mdns --api-bind 0.0.0.0 >/tmp/ce.log 2>&1 & sleep 7; true"
}

# Bring up a per-client (or shared) NAT router: dual-homed LAN+public, MASQUERADE out the public
# side, ip_forward on, and forwarding to the real relay / public gateway dropped (isolation).
start_router(){ # $1=name  $2=lan-network
  docker run -d --name "$1" --network "$PUB" --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 "$IMG" sleep infinity >/dev/null
  docker network connect "$2" "$1" >/dev/null
  cein "$1" "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -A FORWARD -d 178.105.145.170 -j DROP
    iptables -A FORWARD -d $PUB_GW -j DROP"
}

# Start a client BEHIND a NAT router: it joins only the private LAN, routes its default via the
# router, and (if it is a deploy target) mounts the host docker socket so it can run a real workload.
start_client(){ # $1=name  $2=lan-network  $3=router-name  $4=mount-docker(yes/no)  $5..=relay multiaddrs
  local name=$1 lan=$2 rtr=$3 mnt=$4; shift 4
  local extra=""; [ "$mnt" = yes ] && extra="-v $SOCK:$SOCK"
  docker run -d --name "$name" --network "$lan" --cap-add NET_ADMIN $extra "$IMG" sleep infinity >/dev/null
  docker cp "$CE_BIN" "$name:/usr/local/bin/ce" >/dev/null
  local rlan; rlan=$(ip_on "$rtr" "$lan")
  cein "$name" "ip route del default 2>/dev/null; ip route add default via $rlan"
  local args=""; for r in "$@"; do args="$args --bootstrap '$r' --relay '$r'"; done
  cein "$name" "CE_NO_AUTOBOOTSTRAP=1 nohup ce start --light --no-mdns --api-bind 0.0.0.0 $args >/tmp/ce.log 2>&1 & sleep 10; true"
}

echo "=== build mesh: 2 relays + 2 NAT'd clients (binary: $CE_BIN) ==="
start_relay nat-relayA; start_relay nat-relayB
RA="/ip4/$(ip_on nat-relayA "$PUB")/tcp/4001/p2p/$(pid nat-relayA)"
RB="/ip4/$(ip_on nat-relayB "$PUB")/tcp/4001/p2p/$(pid nat-relayB)"
echo "relayA=$RA"; echo "relayB=$RB"
start_router nat-rtrA natnet-lanA
start_router nat-rtrB natnet-lanB
start_client nat-cliA natnet-lanA nat-rtrA no  "$RA" "$RB"
start_client nat-cliB natnet-lanB nat-rtrB yes "$RA" "$RB"   # B is the deploy target -> real runtime
A_ID=$(nid nat-cliA); B_ID=$(nid nat-cliB)
echo "isolation: cliA and cliB are each behind their own MASQUERADE NAT on separate private subnets"
echo "           (outbound to relays OK; no direct route to each other; DCUtR hole-punch permitted)"
# B authorizes A so deploys are accepted.
G=$(cein nat-cliB "ce grant $A_ID --can deploy,kill,status --resource self 2>/dev/null|tail -1")
cein nat-cliA "ce wallet add b $B_ID --cap $G >/dev/null 2>&1; true"
sleep 8

echo "=== [1] multi-relay reachability: cliA -> cliB ==="
[ "$(reached nat-cliA b)" = REACHED ] && pass "A reached B through a relay (2 relays available)" || fail "A could not reach B with 2 relays up"

echo "=== [2] FAILOVER mid-life: kill relayA (process), A must reach B via relayB ==="
# Kill the relay PROCESS in place (keep the container/identity/IP) so the same relay can return in
# [3] — a relay restarting is far more common than one vanishing forever, and a stable multiaddr is
# what lets a NAT'd node redial+re-reserve it. The clients still know only relayA+relayB.
cein nat-relayA "pkill -f 'ce start'"; echo "relayA ce KILLED (container/identity/IP preserved)"
ok=UNREACHABLE
for i in $(seq 1 8); do sleep 8; r=$(reached nat-cliA b); echo "  t=$((i*8))s after kill: $r"; [ "$r" = REACHED ] && { ok=REACHED; break; }; done
[ "$ok" = REACHED ] && pass "after relayA removed, A failed over to relayB and reached B" || fail "A did NOT fail over to the second relay"

echo "=== [3] disconnect/recover: restore relayA, then restart relayB; reachability self-heals via the OTHER relay ==="
# A relay's local DHT record store is in-memory, so a restarted relay starts EMPTY: a node whose
# SOLE relay restarts is briefly undiscoverable until re-publish reconverges. The multi-relay design
# is exactly what hides that — so this scenario restores relayA first and keeps it live to carry
# discovery + circuits while relayB cycles. (A lone-relay restart is a known single-point-of-failure,
# not what "reservations come back on their own" promises; that promise is about the surviving relay.)
RA_IP=$(ip_on nat-relayA "$PUB"); RB_IP=$(ip_on nat-relayB "$PUB")
cein nat-relayA "CE_EXTERNAL_IP=$RA_IP CE_NO_AUTOBOOTSTRAP=1 nohup ce start --no-mine --no-mdns --api-bind 0.0.0.0 >/tmp/ce.log 2>&1 & sleep 2; true"; echo "relayA ce restored in place (same IP/peer-id)"
sleep 18  # let both clients redial + re-reserve on relayA (keepalive reconciles every 5s)
cein nat-relayB "pkill -f 'ce start'; sleep 1; CE_EXTERNAL_IP=$RB_IP CE_NO_AUTOBOOTSTRAP=1 nohup ce start --no-mine --no-mdns --api-bind 0.0.0.0 >/tmp/ce.log 2>&1 & sleep 2; true"; echo "relayB ce restarted in place (relayA stays up to carry reachability)"
ok=UNREACHABLE
for i in $(seq 1 10); do sleep 8; r=$(reached nat-cliA b); echo "  t=$((i*8))s after restart: $r"; [ "$r" = REACHED ] && { ok=REACHED; break; }; done
[ "$ok" = REACHED ] && pass "reachability recovered on its own after relay restart (no node restart)" || fail "reachability did NOT recover after relay restart"

echo "=== [4] heavy load: $LOAD_N clients (shared NAT) each deploy onto B concurrently ==="
# both relays are already live (relayA restored + relayB restarted in [3]); reuse their addrs.
RA="/ip4/$(ip_on nat-relayA "$PUB")/tcp/4001/p2p/$(pid nat-relayA)"
RB="/ip4/$(ip_on nat-relayB "$PUB")/tcp/4001/p2p/$(pid nat-relayB)"
# all load clients share one NAT (many devices behind one home router); B is on a different NAT.
start_router nat-rtrLoad natnet-lanLoad
for i in $(seq 1 "$LOAD_N"); do start_client "nat-load$i" natnet-lanLoad nat-rtrLoad no "$RA" "$RB" & done; wait
# Give the freshly-started fleet time to reserve circuits on BOTH relays + publish their addrs and
# let B discover them — more than a single client needs, and the relays were just cycled in [3].
sleep 20
for i in $(seq 1 "$LOAD_N"); do
  LID=$(nid "nat-load$i")
  g=$(cein nat-cliB "ce grant $LID --can deploy,kill,status --resource self 2>/dev/null|tail -1")
  cein "nat-load$i" "ce wallet add b $B_ID --cap $g >/dev/null 2>&1; true"
done
# Warm discovery cheaply first. A directed kill of a non-existent job is a peer-RPC that forces the
# DHT lookup + circuit dial but runs NOTHING — so we establish each fresh client's connection to B
# without a thundering herd of real containers. relayB's restart in [3] wiped its in-memory DHT
# records; B re-publishes its address on the 30s dht_refresh, so give each client up to ~60s to first
# reach B. Without this, the measured burst races cold post-restart discovery (all-or-nothing flaky).
DUMMY=0000000000000000000000000000000000000000000000000000000000000000
for i in $(seq 1 "$LOAD_N"); do (
  for a in $(seq 1 12); do
    o=$(cein "nat-load$i" "ce kill $DUMMY --on b 2>&1 | tail -1")
    printf '%s' "$o" | grep -qi discovery || break   # reached B (app-level reply) -> connection warm
    sleep 5
  done
) & done; wait
# Per-client outcome (kept as a diagnostic): a real deploy (job_id) = reach; otherwise the actual
# node error is recorded, so a discovery miss vs an execution error is visible in the log.
rm -f /tmp/nat-load-*.res
for i in $(seq 1 "$LOAD_N"); do (
  o=$(cein "nat-load$i" "ce deploy alpine:latest --on b --cmd echo --cmd ok --fund 1000 --duration 30 2>&1 | tail -1")
  if printf '%s' "$o" | grep -qiE 'job_id|deployed on'; then echo "load$i REACHED" >"/tmp/nat-load-$i.res"
  else echo "load$i FAIL: $o" >"/tmp/nat-load-$i.res"; fi
) & done; wait
cat /tmp/nat-load-*.res 2>/dev/null | sed 's/^/  /'
ok=$(grep -l REACHED /tmp/nat-load-*.res 2>/dev/null | wc -l | tr -d ' ')
echo "  $ok/$LOAD_N load clients reached B through the relays"
[ "$ok" -ge $(( (LOAD_N*3+3)/4 )) ] && pass "$ok/$LOAD_N concurrent clients reached B under load" || fail "only $ok/$LOAD_N reached under load"

echo "=== [5] longevity: cliA->cliB stays reachable over a 90s window ==="
green=0; total=6
for i in $(seq 1 $total); do [ "$(reached nat-cliA b)" = REACHED ] && green=$((green+1)); sleep 15; done
echo "  $green/$total reachability checks green over 90s"
[ "$green" -ge $((total-1)) ] && pass "stayed reachable over time ($green/$total)" || fail "flaky over time ($green/$total)"

echo "==================== SUMMARY: $PASS passed, $FAIL failed ===================="
[ "$FAIL" -eq 0 ] && echo "RESULT: PASS" || { echo "RESULT: FAIL"; exit 1; }
