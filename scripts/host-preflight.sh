#!/usr/bin/env bash
set -uo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

failures=0
warnings=0

pass() {
    printf '[PASS] %s\n' "$*"
}

warn() {
    warnings=$((warnings + 1))
    printf '[WARN] %s\n' "$*"
}

fail() {
    failures=$((failures + 1))
    printf '[FAIL] %s\n' "$*"
}

info() {
    printf '[INFO] %s\n' "$*"
}

have() {
    command -v "$1" >/dev/null 2>&1
}

unit_active() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

unit_enabled() {
    systemctl is-enabled --quiet "$1" 2>/dev/null
}

printf 'NFT Firewall V2 host preflight (read-only)\n'
printf 'No firewall, network, sysctl, service, or file changes are performed.\n\n'

if [[ ${EUID} -eq 0 ]]; then
    pass "running with enough privilege for complete read-only inspection"
else
    warn "not running as root; nftables, sockets, Docker, and file checks may be incomplete"
fi

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    info "operating system: ${PRETTY_NAME:-unknown}"
else
    warn "cannot read /etc/os-release"
fi

info "kernel: $(uname -srmo)"

if [[ -d /run/systemd/system ]] && have systemctl; then
    pass "systemd is available"
else
    fail "systemd is required"
fi

for command_name in nft ip wg ss; do
    if have "${command_name}"; then
        pass "required command available: ${command_name}"
    else
        fail "required command missing: ${command_name}"
    fi
done

if have nft; then
    info "nftables: $(nft --version 2>/dev/null || printf 'version unavailable')"
    if nft -j list ruleset >/dev/null 2>&1; then
        pass "nftables ruleset is readable as JSON"
    else
        fail "cannot read the nftables ruleset as JSON"
    fi
fi

if have systemctl; then
    competing_units=(
        firewalld.service
        ufw.service
        nftables.service
        netfilter-persistent.service
    )
    for unit_name in "${competing_units[@]}"; do
        if unit_active "${unit_name}"; then
            fail "competing firewall manager is active: ${unit_name}"
        elif unit_enabled "${unit_name}"; then
            warn "competing firewall manager is enabled but inactive: ${unit_name}"
        fi
    done

    if unit_active nftfwd.service; then
        warn "nftfwd.service is already active; treat this as an upgrade or recovery audit"
    elif unit_enabled nftfwd.service; then
        info "nftfwd.service is installed/enabled but inactive"
    else
        info "no active NFTFW daemon detected"
    fi
fi

if have ip; then
    default_v4_count="$(ip -4 route show default 2>/dev/null | wc -l)"
    default_v6_count="$(ip -6 route show default 2>/dev/null | wc -l)"

    if [[ ${default_v4_count} -eq 1 ]]; then
        pass "exactly one IPv4 default route is present"
    elif [[ ${default_v4_count} -eq 0 ]]; then
        fail "no IPv4 default route is present"
    else
        warn "multiple IPv4 default routes are present; policy routing must be reviewed"
    fi

    info "IPv6 default-route count: ${default_v6_count}"
fi

if have sysctl; then
    ipv4_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || printf unknown)"
    ipv6_disabled="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || printf unknown)"

    if [[ ${ipv4_forward} == 1 ]]; then
        pass "runtime IPv4 forwarding is enabled"
    else
        warn "runtime IPv4 forwarding is ${ipv4_forward}; container forwarding needs value 1"
    fi
    info "runtime global IPv6 disable flag: ${ipv6_disabled}"
else
    warn "sysctl command is unavailable"
fi

if have wg; then
    wg_interfaces="$(wg show interfaces 2>/dev/null || true)"
    if [[ -n ${wg_interfaces} ]]; then
        pass "at least one WireGuard interface is present"
        info "WireGuard interface count: $(wc -w <<<"${wg_interfaces}")"
    else
        warn "no WireGuard interface is currently present; NFTFW does not create the tunnel"
    fi
fi

if have docker || [[ -S /var/run/docker.sock || -S /run/docker.sock ]]; then
    info "Docker is present or its socket exists"
    docker_config=/etc/docker/daemon.json

    if [[ ! -f ${docker_config} ]]; then
        fail "Docker daemon configuration is missing: ${docker_config}"
    elif [[ ! -r ${docker_config} ]]; then
        warn "Docker daemon configuration is not readable at current privilege"
    elif ! have python3; then
        fail "python3 is required to validate Docker daemon JSON"
    else
        docker_bad_keys="$(
            python3 - "${docker_config}" <<'PY'
import json
import sys

path = sys.argv[1]
required = ("iptables", "ip6tables", "ip-forward", "ip-masq", "userland-proxy")
try:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
except Exception as exc:
    print(f"invalid-json:{type(exc).__name__}")
    raise SystemExit(0)

for key in required:
    if data.get(key) is not False:
        print(key)
PY
        )"
        if [[ -z ${docker_bad_keys} ]]; then
            pass "Docker explicitly disables all five firewall/proxy ownership settings"
        else
            fail "Docker settings not explicitly false: $(tr '\n' ' ' <<<"${docker_bad_keys}")"
        fi
    fi

    if [[ -e ${docker_config} ]]; then
        docker_mode="$(stat -c '%a' "${docker_config}" 2>/dev/null || printf unknown)"
        docker_owner="$(stat -c '%U:%G' "${docker_config}" 2>/dev/null || printf unknown)"
        info "Docker daemon configuration owner/mode: ${docker_owner} ${docker_mode}"
    fi
else
    info "Docker not detected; Docker integration can remain disabled"
fi

if have ss; then
    listening_tcp="$(ss -H -lnt 2>/dev/null | wc -l)"
    listening_udp="$(ss -H -lnu 2>/dev/null | wc -l)"
    info "listening socket counts: TCP=${listening_tcp} UDP=${listening_udp}"
    info "review exact listeners locally with: sudo ss -lntup"
fi

if [[ -e /etc/nftfw/nftfw.toml ]]; then
    config_mode="$(stat -c '%a' /etc/nftfw/nftfw.toml 2>/dev/null || printf unknown)"
    config_owner="$(stat -c '%U:%G' /etc/nftfw/nftfw.toml 2>/dev/null || printf unknown)"
    info "existing NFTFW configuration owner/mode: ${config_owner} ${config_mode}"

    if have nftfw; then
        if nftfw config validate /etc/nftfw/nftfw.toml >/dev/null 2>&1; then
            pass "existing NFTFW configuration passes strict validation"
        else
            fail "existing NFTFW configuration failed strict validation"
        fi
    else
        warn "existing NFTFW configuration found but nftfw is not installed"
    fi
else
    info "no existing /etc/nftfw/nftfw.toml found"
fi

printf '\nSummary: %d failure(s), %d warning(s).\n' "${failures}" "${warnings}"
printf 'A clean preflight does not prove that the example policy matches this host.\n'

if (( failures > 0 )); then
    exit 1
fi
