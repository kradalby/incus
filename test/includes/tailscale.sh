# Helpers for the Tailscale authentication suite: a local headscale control
# server plus a tailscaled node joined to it, used to exercise the "tailscale"
# authentication method and grant-based authorization end to end.
#
# Requirements to actually run (the suite skips if unmet):
#   - headscale, tailscaled and tailscale binaries in PATH
#   - root and /dev/net/tun: incusd binds to the node's Tailscale IP, which needs
#     real (kernel) TUN networking. WhoIs alone works in userspace-networking
#     mode, but binding a normal listener to the Tailscale IP does not.

hs() {
    headscale -c "${TEST_DIR}/headscale/config.yaml" "${@}"
}

headscale_url() {
    cat "${TEST_DIR}/headscale/url"
}

spawn_headscale() {
    mkdir -p "${TEST_DIR}/headscale"

    HS_PORT="$(local_tcp_port)"
    HS_METRICS_PORT="$(local_tcp_port)"
    HS_GRPC_PORT="$(local_tcp_port)"
    HS_STUN_PORT="$(local_tcp_port)"
    echo "http://127.0.0.1:${HS_PORT}" > "${TEST_DIR}/headscale/url"

    cat > "${TEST_DIR}/headscale/config.yaml" <<EOF
server_url: http://127.0.0.1:${HS_PORT}
listen_addr: 127.0.0.1:${HS_PORT}
metrics_listen_addr: 127.0.0.1:${HS_METRICS_PORT}
grpc_listen_addr: 127.0.0.1:${HS_GRPC_PORT}
unix_socket: ${TEST_DIR}/headscale/headscale.sock
unix_socket_permission: "0770"
noise:
  private_key_path: ${TEST_DIR}/headscale/noise.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
database:
  type: sqlite
  sqlite:
    path: ${TEST_DIR}/headscale/db.sqlite
derp:
  server:
    enabled: true
    region_id: 999
    region_code: test
    region_name: test
    stun_listen_addr: 127.0.0.1:${HS_STUN_PORT}
    private_key_path: ${TEST_DIR}/headscale/derp.key
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

    headscale -c "${TEST_DIR}/headscale/config.yaml" serve > "${TEST_DIR}/headscale/headscale.log" 2>&1 &
    echo "$!" > "${TEST_DIR}/headscale/pid"

    for _ in $(seq 60); do
        if hs users list > /dev/null 2>&1; then
            break
        fi

        sleep 0.5
    done

    hs users create incusadmin > /dev/null 2>&1 || true
}

# headscale_set_policy <role> installs a grants policy giving tag:incus the given
# Incus role (admin or viewer) over the default project on tag:incus. Database
# policy mode lets us swap the role at runtime.
headscale_set_policy() {
    cat > "${TEST_DIR}/headscale/policy.json" <<EOF
{
  "tagOwners": {"tag:incus": ["incusadmin@"]},
  "grants": [
    {"src": ["tag:incus"], "dst": ["tag:incus"], "ip": ["*"]},
    {"src": ["tag:incus"], "dst": ["tag:incus"], "app": {"incus.com/cap/incus": [{"projects": ["default"], "role": "${1}"}]}}
  ]
}
EOF

    hs policy set -f "${TEST_DIR}/headscale/policy.json"
}

# headscale_authkey prints a reusable pre-auth key that forces tag:incus onto the
# node (forced tags avoid having to authorize advertised tags separately).
headscale_authkey() {
    uid="$(hs users list -o json | jq -r '.[] | select(.name=="incusadmin") | .id')"
    hs preauthkeys create --user "${uid}" --reusable --expiration 1h --tags tag:incus 2>/dev/null | tail -n1
}

ts() {
    tailscale --socket="${TEST_DIR}/tailscale/tailscaled.sock" "${@}"
}

spawn_tailscaled() {
    mkdir -p "${TEST_DIR}/tailscale"

    tailscaled \
        --tun=incus-ts0 \
        --socket="${TEST_DIR}/tailscale/tailscaled.sock" \
        --state="${TEST_DIR}/tailscale/tailscaled.state" \
        --statedir="${TEST_DIR}/tailscale" \
        --port=0 > "${TEST_DIR}/tailscale/tailscaled.log" 2>&1 &
    echo "$!" > "${TEST_DIR}/tailscale/pid"

    for _ in $(seq 30); do
        [ -S "${TEST_DIR}/tailscale/tailscaled.sock" ] && break
        sleep 0.5
    done
}

# tailscale_up <authkey> joins the node to headscale.
tailscale_up() {
    ts up --reset --timeout=60s \
        --login-server="$(headscale_url)" \
        --authkey="${1}" \
        --hostname=incus-server \
        --accept-routes=false \
        --accept-dns=false
}

tailscale_ip() {
    ts ip -4 | head -n1
}

shutdown_tailscale() {
    if [ -f "${TEST_DIR}/tailscale/pid" ]; then
        kill "$(cat "${TEST_DIR}/tailscale/pid")" 2>/dev/null || true
    fi

    if [ -f "${TEST_DIR}/headscale/pid" ]; then
        kill "$(cat "${TEST_DIR}/headscale/pid")" 2>/dev/null || true
    fi

    rm -rf "${TEST_DIR}/tailscale" "${TEST_DIR}/headscale"
}
