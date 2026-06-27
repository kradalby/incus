#!/usr/bin/env bash
# Security probe #2: can a SEPARATE host (no Tailscale), reachable to a
# multi-homed incusd over a non-tunnel link, impersonate a tailnet identity by
# spoofing the source IP?
#
# Topology (all inside one rootless user namespace):
#   server netns: incus-ts0=100.64.0.1 (tailnet) + veth-srv=10.8.0.1 ; incusd :8443
#   attacker netns: veth-atk=10.8.0.2 (NO tailscale)
# The attacker tries: (a) an honest request (its own source), (b) a TCP SYN with
# spoofed source=100.64.0.1.
set -u

HEADSCALE="${HEADSCALE:-headscale}"; TAILSCALED="${TAILSCALED:-tailscaled}"; TAILSCALE="${TAILSCALE:-tailscale}"
INCUSD="${INCUSD:-incusd}"; INCUS="${INCUS:-incus}"
W="$(mktemp -d)"; mkdir -p "${W}/headscale" "${W}/ts" "${W}/incusd"
HPORT=$(shuf -i 20000-29000 -n1); MPORT=$(shuf -i 30000-39000 -n1)
GPORT=$(shuf -i 40000-49000 -n1); SPORT=$(shuf -i 50000-59000 -n1)
log(){ echo "=== $* ==="; }; fail(){ echo "PROBE ERROR: $*"; exit 1; }
ATK_PID=""
# shellcheck disable=SC2329  # invoked via trap below
cleanup(){ for p in "${W}"/ts/pid "${W}"/headscale/pid "${W}"/incusd/pid; do [ -f "${p}" ] && kill "$(cat "${p}")" 2>/dev/null; done; [ -n "${ATK_PID}" ] && kill "${ATK_PID}" 2>/dev/null; rm -rf "${W}"; }
trap cleanup EXIT

ip link set lo up 2>/dev/null || true
ip link add dummy0 type dummy 2>/dev/null || true
ip addr add 10.99.0.2/24 dev dummy0 2>/dev/null || true
ip link set dummy0 up 2>/dev/null || true
ip route add default via 10.99.0.1 dev dummy0 2>/dev/null || true

log "1. headscale + grant"
cat > "${W}/headscale/config.yaml" <<EOF
server_url: http://127.0.0.1:${HPORT}
listen_addr: 127.0.0.1:${HPORT}
metrics_listen_addr: 127.0.0.1:${MPORT}
grpc_listen_addr: 127.0.0.1:${GPORT}
unix_socket: ${W}/headscale/headscale.sock
unix_socket_permission: "0770"
noise: {private_key_path: ${W}/headscale/noise.key}
prefixes: {v4: 100.64.0.0/10, v6: "fd7a:115c:a1e0::/48"}
database: {type: sqlite, sqlite: {path: ${W}/headscale/db.sqlite}}
derp:
  server: {enabled: true, region_id: 999, region_code: test, region_name: test, stun_listen_addr: "127.0.0.1:${SPORT}", private_key_path: ${W}/headscale/derp.key}
  urls: []
  paths: []
  auto_update_enabled: false
  update_frequency: 24h
dns: {magic_dns: false, override_local_dns: false, base_domain: incus.test, nameservers: {global: []}}
policy: {mode: database}
log: {level: warn}
EOF
hs(){ "${HEADSCALE}" -c "${W}/headscale/config.yaml" "$@"; }
hs serve > "${W}/headscale/headscale.log" 2>&1 & echo $! > "${W}/headscale/pid"
for _ in $(seq 60); do hs users list >/dev/null 2>&1 && break; sleep 0.5; done
hs users list >/dev/null 2>&1 || fail "headscale down"
hs users create incusadmin >/dev/null 2>&1 || true
UID_N=$(hs users list -o json | python3 -c "import sys,json;print([u['id'] for u in json.load(sys.stdin) if u['name']=='incusadmin'][0])")
cat > "${W}/headscale/policy.json" <<EOF
{"tagOwners":{"tag:incus":["incusadmin@"]},"grants":[{"src":["tag:incus"],"dst":["tag:incus"],"ip":["*"]},{"src":["tag:incus"],"dst":["tag:incus"],"app":{"incus.com/cap/incus":[{"projects":["*"],"role":"admin"}]}}]}
EOF
hs policy set -f "${W}/headscale/policy.json" >/dev/null 2>&1 || fail "policy"
AUTHKEY=$(hs preauthkeys create --user "${UID_N}" --reusable --expiration 1h --tags tag:incus 2>/dev/null | tail -n1)

log "2. tailscaled (real TUN)"
"${TAILSCALED}" --tun=incus-ts0 --socket="${W}/ts/sock" --state="${W}/ts/state" --statedir="${W}/ts" --port=0 > "${W}/ts/tailscaled.log" 2>&1 & echo $! > "${W}/ts/pid"
for _ in $(seq 30); do [ -S "${W}/ts/sock" ] && break; sleep 0.5; done
ts(){ "${TAILSCALE}" --socket="${W}/ts/sock" "$@"; }
ts up --reset --timeout=60s --netfilter-mode=off --login-server="http://127.0.0.1:${HPORT}" --authkey="${AUTHKEY}" --hostname=incus-server --accept-routes=false --accept-dns=false || fail "ts up"
TS_IP=""; for _ in $(seq 20); do TS_IP=$(ts ip -4 2>/dev/null | head -n1); [ -n "${TS_IP}" ] && break; sleep 0.5; done
[ -n "${TS_IP}" ] || fail "no ts ip"

log "3. attacker netns over veth (no tailscale)"
ip link add veth-srv type veth peer name veth-atk
ip addr add 10.8.0.1/24 dev veth-srv
ip link set veth-srv up
unshare -n sleep 1200 & ATK_PID=$!
sleep 0.5
ip link set veth-atk netns "${ATK_PID}"
atk(){ nsenter -t "${ATK_PID}" -n "$@"; }
atk ip link set lo up
atk ip link set veth-atk up
atk ip addr add 10.8.0.2/24 dev veth-atk
echo "server: tailnet=${TS_IP} veth-srv=10.8.0.1 | attacker: veth-atk=10.8.0.2 (separate netns, no tailscale)"

log "4. incusd MULTI-HOMED (:8443 all interfaces)"
export INCUS_DIR="${W}/incusd"; incl(){ "${INCUS}" --force-local "$@"; }
start_incusd(){ "${INCUSD}" --logfile "${W}/incusd/incusd.log" >> "${W}/incusd/stdout.log" 2>&1 & echo $! > "${W}/incusd/pid"; incl admin waitready --timeout=60 || fail "incusd not ready"; }
start_incusd
incl config set tailscale.socket="${W}/ts/sock"; incl config set tailscale.enabled=true; incl config set core.https_address=":8443"
kill "$(cat "${W}/incusd/pid")" 2>/dev/null; for _ in $(seq 30); do [ -S "${W}/incusd/unix.socket" ] || break; sleep 0.5; done
start_incusd; sleep 1

log "5. attacker probes"
RESULT=0

# (a) Honest request from the attacker's own (non-tailnet) source.
HONEST=$(atk curl -sk --max-time 10 "https://10.8.0.1:8443/1.0" | python3 -c "import sys,json;print(json.load(sys.stdin)['metadata']['auth'])" 2>/dev/null)
echo "(a) honest  attacker request (src=10.8.0.2)         -> auth: ${HONEST:-<no response>}"
[ "${HONEST}" = "untrusted" ] || { echo "    SECURITY FAIL: attacker authenticated"; RESULT=1; }

# (b) TCP reachability baseline + spoofed-source SYN, via scapy in the attacker netns.
cat > "${W}/spoof.py" <<'PY'
from scapy.all import IP, TCP, sr1, conf
conf.verb = 0
DST, DPORT = "10.8.0.1", 8443
def synack(pkt):
    return bool(pkt and pkt.haslayer(TCP) and (pkt[TCP].flags & 0x12) == 0x12)
honest = sr1(IP(dst=DST)/TCP(sport=40000, dport=DPORT, flags="S"), timeout=4, iface="veth-atk")
print("BASELINE_REACHABLE", synack(honest))
spoof = sr1(IP(src="100.64.0.1", dst=DST)/TCP(sport=40001, dport=DPORT, flags="S"), timeout=4, iface="veth-atk")
print("SPOOF_SYNACK", synack(spoof))
PY
SPOUT=$(atk python3 "${W}/spoof.py" 2>/dev/null)
REACH=$(echo "${SPOUT}" | awk '/BASELINE_REACHABLE/{print $2}')
SPOOF=$(echo "${SPOUT}" | awk '/SPOOF_SYNACK/{print $2}')
echo "(b) attacker can reach incusd:8443 (honest SYN)      -> SYN-ACK: ${REACH:-?}"
echo "    spoofed SYN src=100.64.0.1 gets a SYN-ACK back   -> ${SPOOF:-?}"
[ "${REACH}" = "True" ]  || echo "    (note: attacker could not even reach the port; spoof test inconclusive)"
[ "${SPOOF}" = "False" ] || { echo "    SECURITY FAIL: spoofed-source handshake completed to attacker"; RESULT=1; }

echo
if [ "${RESULT}" = 0 ]; then
  echo "PROBE RESULT: a separate non-tailscale host reaching the multi-homed incusd"
  echo "is 'untrusted' on its honest source, and a spoofed source=100.64.0.1 SYN gets"
  echo "no SYN-ACK back (the reply is routed to the server's own tailnet interface,"
  echo "not the attacker) -- so it cannot complete a handshake or impersonate a peer."
fi
exit "${RESULT}"
