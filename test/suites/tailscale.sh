test_tailscale() {
    if ! command -v headscale > /dev/null 2>&1 || ! command -v tailscaled > /dev/null 2>&1 || ! command -v tailscale > /dev/null 2>&1; then
        echo "==> SKIP: Missing headscale/tailscale binaries"
        return
    fi

    if [ ! -e /dev/net/tun ]; then
        echo "==> SKIP: No /dev/net/tun (Tailscale auth e2e needs real TUN networking)"
        return
    fi

    ensure_import_testimage
    ensure_has_localhost_remote "${INCUS_ADDR}"

    # Bring up the control server and a node joined to it, tagged tag:incus.
    spawn_headscale
    headscale_set_policy admin

    spawn_tailscaled
    tailscale_up "$(headscale_authkey)"
    TS_IP="$(tailscale_ip)"

    # Point incusd's Tailscale auth at this node's tailscaled, and have it listen
    # on the node's Tailscale IP so a caller's source address is a tailnet IP that
    # WhoIs can resolve. Enabling tailscale.enabled also installs the grant
    # authorizer (the verifier and authorizer are wired together).
    incus config set tailscale.socket "${TEST_DIR}/tailscale/tailscaled.sock"
    incus config set tailscale.enabled true
    incus config set core.https_address "${TS_IP}:8443"

    # Use a throwaway client config so the connection presents an untrusted
    # certificate and is therefore authenticated purely by Tailscale identity
    # (a trusted cert would short-circuit to TLS auth and never hit WhoIs).
    TS_CONF="$(mktemp -d)"
    INCUS_CONF_SAVED="${INCUS_CONF}"
    export INCUS_CONF="${TS_CONF}"

    incus remote add tsincus "https://${TS_IP}:8443" --accept-certificate

    # The admin grant allows reading and creating instances.
    echo "==> admin grant: read and create allowed"
    incus list tsincus: > /dev/null
    incus init testimage tsincus:c1 > /dev/null
    incus delete tsincus:c1 > /dev/null

    # Downgrade the grant to viewer; database policy mode applies it live, and the
    # node receives the updated map over its control connection.
    headscale_set_policy viewer
    sleep 2

    # The viewer grant allows reading but denies creating instances.
    echo "==> viewer grant: read allowed, create denied"
    incus list tsincus: > /dev/null
    ! incus init testimage tsincus:c2 > /dev/null 2>&1

    # Restore the original client config and clean up.
    export INCUS_CONF="${INCUS_CONF_SAVED}"
    incus config unset core.https_address
    incus config unset tailscale.enabled
    incus config unset tailscale.socket
    rm -rf "${TS_CONF}"
    shutdown_tailscale
}
