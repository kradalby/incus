#!/usr/bin/env bash
#
# Self-contained end-to-end test for Tailscale authentication: brings up a local
# headscale control server, a tailscaled node joined to it, and incusd, then
# drives the incus CLI over the tailnet to confirm that an app-capability grant
# of role "admin" permits writes while "viewer" permits only reads.
#
# It needs a private network namespace with TUN access, which an unprivileged
# user can get via a user namespace:
#
#   nix-shell -p rsync attr gnutar squashfsTools xz --run \
#     'unshare -rn env INCUSD=/path/to/incusd INCUS=/path/to/incus \
#       bash test/extras/tailscale-e2e.sh'
#
# Binaries are taken from $HEADSCALE, $TAILSCALED, $TAILSCALE, $INCUSD, $INCUS
# (default: looked up in PATH). incusd additionally needs ip, rsync, setfattr,
# tar, unsquashfs and xz in PATH.
set -u

HEADSCALE="${HEADSCALE:-headscale}"
TAILSCALED="${TAILSCALED:-tailscaled}"
TAILSCALE="${TAILSCALE:-tailscale}"
INCUSD="${INCUSD:-incusd}"
INCUS="${INCUS:-incus}"

W="$(mktemp -d)"
mkdir -p "${W}/headscale" "${W}/ts" "${W}/incusd" "${W}/clientconf"

HPORT=$(shuf -i 20000-29000 -n1)
MPORT=$(shuf -i 30000-39000 -n1)
GPORT=$(shuf -i 40000-49000 -n1)
SPORT=$(shuf -i 50000-59000 -n1)
IPORT=8443

log()  { echo "=== $* ==="; }
fail() { echo "E2E FAIL: $*"; exit 1; }

cleanup() {
    for p in "${W}"/ts/pid "${W}"/headscale/pid "${W}"/incusd/pid; do
        [ -f "${p}" ] && kill "$(cat "${p}")" 2>/dev/null
    done
    rm -rf "${W}"
}
trap cleanup EXIT

# Loopback is required for the daemons to talk over 127.0.0.1. A dummy uplink
# with a default route makes tailscaled's link monitor believe it is online so
# the control client registers (control traffic still goes via loopback).
ip link set lo up 2>/dev/null || true
ip link add dummy0 type dummy 2>/dev/null || true
ip addr add 10.99.0.2/24 dev dummy0 2>/dev/null || true
ip link set dummy0 up 2>/dev/null || true
ip route add default via 10.99.0.1 dev dummy0 2>/dev/null || true

############################################
log "1. headscale"
cat > "${W}/headscale/config.yaml" <<EOF
server_url: http://127.0.0.1:${HPORT}
listen_addr: 127.0.0.1:${HPORT}
metrics_listen_addr: 127.0.0.1:${MPORT}
grpc_listen_addr: 127.0.0.1:${GPORT}
unix_socket: ${W}/headscale/headscale.sock
unix_socket_permission: "0770"
noise:
  private_key_path: ${W}/headscale/noise.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
database:
  type: sqlite
  sqlite:
    path: ${W}/headscale/db.sqlite
derp:
  server:
    enabled: true
    region_id: 999
    region_code: test
    region_name: test
    stun_listen_addr: 127.0.0.1:${SPORT}
    private_key_path: ${W}/headscale/derp.key
  urls: []
  paths: []
  auto_update_enabled: false
  update_frequency: 24h
dns:
  magic_dns: false
  override_local_dns: false
  base_domain: incus.test
  nameservers:
    global: []
policy:
  mode: database
log:
  level: warn
EOF

hs() { "${HEADSCALE}" -c "${W}/headscale/config.yaml" "$@"; }

hs serve > "${W}/headscale/headscale.log" 2>&1 &
echo $! > "${W}/headscale/pid"
for _ in $(seq 60); do hs users list >/dev/null 2>&1 && break; sleep 0.5; done
hs users list >/dev/null 2>&1 || fail "headscale did not come up"
hs users create incusadmin >/dev/null 2>&1 || true
UID_N=$(hs users list -o json | python3 -c "import sys,json;print([u['id'] for u in json.load(sys.stdin) if u['name']=='incusadmin'][0])")

set_policy() {
    cat > "${W}/headscale/policy.json" <<EOF
{
  "tagOwners": {"tag:incus": ["incusadmin@"]},
  "grants": [
    {"src": ["tag:incus"], "dst": ["tag:incus"], "ip": ["*"]},
    {"src": ["tag:incus"], "dst": ["tag:incus"], "app": {"incus.com/cap/incus": [{"projects": ["*"], "role": "$1"}]}}
  ]
}
EOF
    hs policy set -f "${W}/headscale/policy.json" >/dev/null 2>&1 || fail "policy set $1"
}
set_policy admin
AUTHKEY=$(hs preauthkeys create --user "${UID_N}" --reusable --expiration 1h --tags tag:incus 2>/dev/null | tail -n1)
[ -n "${AUTHKEY}" ] || fail "no auth key"

############################################
log "2. tailscaled + join (real TUN)"
"${TAILSCALED}" --tun=incus-ts0 --socket="${W}/ts/sock" --state="${W}/ts/state" --statedir="${W}/ts" --port=0 > "${W}/ts/tailscaled.log" 2>&1 &
echo $! > "${W}/ts/pid"
for _ in $(seq 30); do [ -S "${W}/ts/sock" ] && break; sleep 0.5; done
ts() { "${TAILSCALE}" --socket="${W}/ts/sock" "$@"; }
ts up --reset --timeout=60s --netfilter-mode=off --login-server="http://127.0.0.1:${HPORT}" --authkey="${AUTHKEY}" --hostname=incus-server --accept-routes=false --accept-dns=false || fail "tailscale up (see ${W}/ts/tailscaled.log)"
TS_IP=""
for _ in $(seq 20); do TS_IP=$(ts ip -4 2>/dev/null | head -n1); [ -n "${TS_IP}" ] && break; sleep 0.5; done
[ -n "${TS_IP}" ] || fail "no tailscale IP"
echo "TS_IP=${TS_IP}"
ts whois --json "${TS_IP}" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'incus.com/cap/incus' in (d.get('CapMap') or {});print('WhoIs CapMap OK:', json.dumps(d['CapMap']['incus.com/cap/incus']))" || fail "WhoIs CapMap missing"

############################################
log "3. incusd"
export INCUS_DIR="${W}/incusd"
incl() { "${INCUS}" --force-local "$@"; }
start_incusd() {
    "${INCUSD}" --logfile "${W}/incusd/incusd.log" >> "${W}/incusd/stdout.log" 2>&1 &
    echo $! > "${W}/incusd/pid"
    incl admin waitready --timeout=60 || fail "incusd did not become ready (see ${W}/incusd/stdout.log)"
}
stop_incusd() {
    kill "$(cat "${W}/incusd/pid")" 2>/dev/null
    for _ in $(seq 30); do [ -S "${W}/incusd/unix.socket" ] || break; sleep 0.5; done
}

start_incusd
incl config set tailscale.socket="${W}/ts/sock"
incl config set tailscale.enabled=true
incl config set core.https_address="${TS_IP}:${IPORT}"
# Tailscale auth is wired at startup, so restart to activate it.
stop_incusd
start_incusd
sleep 1

############################################
log "4. incus CLI over Tailscale — admin grant"
export INCUS_CONF="${W}/clientconf"
"${INCUS}" remote add tsincus "https://${TS_IP}:${IPORT}" --accept-certificate || fail "remote add (tailscale auth rejected?)"
"${INCUS}" info tsincus: | grep -q "auth: trusted" || fail "not authenticated as trusted over tailscale"
"${INCUS}" project list tsincus: >/dev/null || fail "admin: project list denied"
"${INCUS}" project create tsincus:e2e-admin >/dev/null 2>&1 || fail "admin: project create denied (should be allowed)"
echo "admin grant: project create ALLOWED (correct)"

############################################
log "5. incus CLI over Tailscale — viewer grant (downgrade)"
set_policy viewer
sleep 3
"${INCUS}" project list tsincus: >/dev/null || fail "viewer: project list denied (read should be allowed)"
if "${INCUS}" project create tsincus:e2e-viewer >/dev/null 2>&1; then
    fail "viewer: project create ALLOWED (should be denied)"
fi
echo "viewer grant: read ALLOWED, create DENIED (correct)"

echo
echo "E2E PASS: headscale + tailscaled + incus CLI — grant-based authz green"
