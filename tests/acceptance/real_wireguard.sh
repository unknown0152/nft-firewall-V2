#!/usr/bin/env bash
set -euo pipefail

config=${1:-/root/nft-firewall-work/test-data/wg-test.conf}
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "BLOCKED: real WireGuard acceptance requires root"; exit 77; fi
for tool in ip nft wg wg-quick curl getent tcpdump timeout awk stat; do
    command -v "$tool" >/dev/null || { echo "BLOCKED: missing $tool"; exit 77; }
done
docker_mode=${NFTFW_DOCKER_ACCEPTANCE:-0}
if [[ "$docker_mode" == 1 ]]; then
    command -v docker >/dev/null || { echo "BLOCKED: Docker acceptance requested but docker is missing"; exit 77; }
fi
[[ -f "$config" && ! -L "$config" ]] || { echo "BLOCKED: WireGuard fixture is absent or unsafe"; exit 77; }
[[ "$(stat -c '%a:%u:%g' "$config")" = 600:0:0 ]] || { echo "BLOCKED: WireGuard fixture must be root:root mode 0600"; exit 77; }
wg-quick strip "$config" >/dev/null || { echo "FAIL: WireGuard fixture did not parse"; exit 1; }

suffix=$(printf '%05d' "$(( $$ % 100000 ))")
vpn_ns="nftfw-real-$suffix"
ctr_ns="nftfw-ctr-$suffix"
host_if="nfh$suffix"
ns_if="nfn$suffix"
nat_table="nftfw_accept_$suffix"
lab_tmp=$(mktemp -d /tmp/nftfw-real.XXXXXX)
daemon_pid=""
capture_pid=""
docker_container=""
old_forward=$(sysctl -n net.ipv4.ip_forward)
cleanup() {
    set +e
    [[ -n "$capture_pid" ]] && kill "$capture_pid" 2>/dev/null
    [[ -n "$daemon_pid" ]] && kill "$daemon_pid" 2>/dev/null
    [[ -n "$daemon_pid" ]] && wait "$daemon_pid" 2>/dev/null
    ip netns del "$ctr_ns" 2>/dev/null
    [[ -n "$docker_container" ]] && docker rm -f "$docker_container" >/dev/null 2>&1
    ip netns del "$vpn_ns" 2>/dev/null
    ip link del "$host_if" 2>/dev/null
    nft delete table ip "$nat_table" 2>/dev/null
    sysctl -qw net.ipv4.ip_forward="$old_forward"
    rm -rf "$lab_tmp"
}
trap cleanup EXIT

public_ipv4() {
    local namespace=$1 value url trace
    trace=$(ip netns exec "$namespace" curl -4fsS --max-time 15 https://1.1.1.1/cdn-cgi/trace 2>/dev/null || true)
    value=$(awk -F= '$1 == "ip" { print $2; exit }' <<<"$trace")
    if [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        printf '%s' "$value"
        return 0
    fi
    for url in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
        value=$(ip netns exec "$namespace" curl -4fsS --max-time 15 "$url" 2>/dev/null || true)
        value=${value//$'\n'/}
        value=${value//$'\r'/}
        if [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            printf '%s' "$value"
            return 0
        fi
    done
    return 1
}

endpoint=$(awk -F= '/^[[:space:]]*Endpoint[[:space:]]*=/ { value=$2 } END { gsub(/[[:space:]]/, "", value); print value }' "$config")
[[ -n "$endpoint" ]] || { echo "FAIL: no WireGuard endpoint"; exit 1; }
if [[ "$endpoint" == \[* ]]; then
    echo "BLOCKED: live harness currently requires an IPv4-reachable outer endpoint"
    exit 77
fi
endpoint_host=${endpoint%:*}
endpoint_port=${endpoint##*:}
[[ "$endpoint_port" =~ ^[0-9]+$ && "$endpoint_port" -ge 1 && "$endpoint_port" -le 65535 ]] || { echo "FAIL: invalid endpoint port"; exit 1; }
mapfile -t resolved_endpoints < <(getent ahostsv4 "$endpoint_host" | awk '{ print $1 }' | sort -u)
[[ ${#resolved_endpoints[@]} -gt 0 ]] || { echo "FAIL: endpoint has no IPv4 resolution"; exit 1; }
endpoint_ip=${resolved_endpoints[0]}
[[ "$endpoint_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "FAIL: endpoint resolution was not IPv4"; exit 1; }
bootstrap_v4=""
for resolved in "${resolved_endpoints[@]}"; do
    [[ "$resolved" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    [[ -n "$bootstrap_v4" ]] && bootstrap_v4+=", "
    bootstrap_v4+="\"$resolved/32\""
done
[[ -n "$bootstrap_v4" ]] || { echo "FAIL: endpoint resolution produced no usable IPv4 address"; exit 1; }

mapfile -t tunnel_addresses < <(awk -F= '/^[[:space:]]*Address[[:space:]]*=/ { value=$2; count=split(value, items, ","); for (i=1;i<=count;i++) { gsub(/[[:space:]]/, "", items[i]); if (items[i] != "") print items[i] } }' "$config")
[[ ${#tunnel_addresses[@]} -gt 0 ]] || { echo "FAIL: fixture has no tunnel address"; exit 1; }
has_ipv6=0
for address in "${tunnel_addresses[@]}"; do [[ "$address" == *:* ]] && has_ipv6=1; done

uplink=$(ip -4 route show default | awk '{ print $5 }')
[[ "$uplink" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || { echo "FAIL: could not identify host uplink"; exit 1; }
ip netns add "$vpn_ns"
if [[ "$docker_mode" == 1 ]]; then
    docker_container="nftfw-real-$suffix"
    docker run -d --name "$docker_container" --network none alpine:3.22 sleep 600 >/dev/null
    docker_pid=$(docker inspect --format '{{.State.Pid}}' "$docker_container")
    [[ "$docker_pid" =~ ^[0-9]+$ && "$docker_pid" -gt 1 ]] || { echo "FAIL: Docker test container has no network namespace"; exit 1; }
    mkdir -p /run/netns
    ln -s "/proc/$docker_pid/ns/net" "/run/netns/$ctr_ns"
else
    ip netns add "$ctr_ns"
fi
ip link add "$host_if" type veth peer name "$ns_if"
ip link set "$ns_if" netns "$vpn_ns"
ip -n "$vpn_ns" link set "$ns_if" name uplink0
ip -n "$vpn_ns" link set lo up
ip -n "$ctr_ns" link set lo up
ip address add 10.203.0.1/30 dev "$host_if"
ip link set "$host_if" up
ip -n "$vpn_ns" address add 10.203.0.2/30 dev uplink0
ip -n "$vpn_ns" link set uplink0 up
ip -n "$vpn_ns" route add default via 10.203.0.1
ip -n "$vpn_ns" route add "$endpoint_ip"/32 via 10.203.0.1

ip link add ctr-host type veth peer name ctr-eth
ip link set ctr-host netns "$vpn_ns"
ip link set ctr-eth netns "$ctr_ns"
ip -n "$vpn_ns" address add 10.204.0.1/24 dev ctr-host
ip -n "$vpn_ns" link set ctr-host up
ip -n "$ctr_ns" address add 10.204.0.2/24 dev ctr-eth
ip -n "$ctr_ns" link set ctr-eth up
ip -n "$ctr_ns" route add default via 10.204.0.1
ip netns exec "$vpn_ns" sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv4.ip_forward=1

nft -f - <<NFT
table ip $nat_table {
    chain forward {
        type filter hook forward priority -50; policy accept;
        iifname "$host_if" accept
        oifname "$host_if" ct state established,related accept
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 10.203.0.0/30 oifname "$uplink" masquerade
    }
}
NFT

physical_ip=$(public_ipv4 "$vpn_ns" || true)
[[ "$physical_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "FAIL: isolated physical baseline has no IPv4 Internet"; exit 1; }
echo "REAL PHYSICAL BASELINE: PASS"

configure_wireguard() {
    ip -n "$vpn_ns" link add wg-real type wireguard
    wg-quick strip "$config" | awk -v endpoint="$endpoint_ip:$endpoint_port" '
        /^[[:space:]]*Endpoint[[:space:]]*=/ { print "Endpoint = " endpoint; next }
        { print }
    ' | ip netns exec "$vpn_ns" wg setconf wg-real /dev/stdin
    ip netns exec "$vpn_ns" wg set wg-real fwmark 51820
    for address in "${tunnel_addresses[@]}"; do ip -n "$vpn_ns" address add "$address" dev wg-real; done
    ip -n "$vpn_ns" link set wg-real up
    ip -n "$vpn_ns" route add default dev wg-real table 51820
    if (( has_ipv6 )); then ip -n "$vpn_ns" -6 route add default dev wg-real table 51820; fi
}

configure_wireguard
ip netns exec "$vpn_ns" ip rule add table main suppress_prefixlength 0 priority 100
ip netns exec "$vpn_ns" ip rule add not fwmark 51820 table 51820 priority 101
if (( has_ipv6 )); then
    ip netns exec "$vpn_ns" ip -6 rule add table main suppress_prefixlength 0 priority 100
    ip netns exec "$vpn_ns" ip -6 rule add not fwmark 51820 table 51820 priority 101
fi

ipv6_mode=disabled
(( has_ipv6 )) && ipv6_mode=vpn
cat > "$lab_tmp/nftfw.toml" <<TOML
[system]
ipv6_mode = "$ipv6_mode"
strict_vpn = true
[[interfaces]]
name = "uplink0"
role = "uplink"
provenance_id = 1
[[interfaces]]
name = "wg-real"
role = "vpn"
provenance_id = 2
[[interfaces]]
name = "ctr-host"
role = "container"
provenance_id = 3
cidrs = ["10.204.0.0/24"]
[[zones]]
name = "container"
networks = ["10.204.0.0/24"]
[[services]]
name = "https"
protocol = "tcp"
ports = [443]
[[services]]
name = "dns-tcp"
protocol = "tcp"
ports = [53]
[[services]]
name = "dns-udp"
protocol = "udp"
ports = [53]
[[services]]
name = "ping"
protocol = "icmp"
ports = []
[[policies]]
name = "host-https"
from = "host"
to = "any"
service = "https"
action = "allow"
[[policies]]
name = "host-dns-tcp"
from = "host"
to = "any"
service = "dns-tcp"
action = "allow"
[[policies]]
name = "host-dns-udp"
from = "host"
to = "any"
service = "dns-udp"
action = "allow"
[[policies]]
name = "host-ping"
from = "host"
to = "any"
service = "ping"
action = "allow"
[[policies]]
name = "container-https"
from = "container"
to = "any"
service = "https"
action = "allow"
[[policies]]
name = "container-dns-tcp"
from = "container"
to = "any"
service = "dns-tcp"
action = "allow"
[[policies]]
name = "container-dns-udp"
from = "container"
to = "any"
service = "dns-udp"
action = "allow"
[[policies]]
name = "container-ping"
from = "container"
to = "any"
service = "ping"
action = "allow"
[wireguard]
interface = "wg-real"
endpoint_port = $endpoint_port
fwmark = "0xca6c"
bootstrap_ips = [$bootstrap_v4]
bootstrap_ips_v6 = []
[runtime]
max_block_claims = 100000
max_set_members = 65536
[state]
directory = "$lab_tmp/state"
database = "$lab_tmp/state/generation-state/state.db"
provenance_ledger = "$lab_tmp/state/provenance-ledger.db"
[integrations]
docker_enabled = false
threat_feed = false
geoip = false
notifications = false
TOML
chmod 600 "$lab_tmp/nftfw.toml"

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "BLOCKED: unsupported architecture"; exit 77 ;; esac
nftfw="$root_dir/dist/nftfw-linux-$arch"
nftfwd="$root_dir/dist/nftfwd-linux-$arch"
[[ -x "$nftfw" && -x "$nftfwd" ]] || { echo "BLOCKED: release binaries are not built"; exit 77; }
local_cli=(env NFTFW_CONFIG="$lab_tmp/nftfw.toml" NFTFW_STATE_DB="$lab_tmp/state/generation-state/state.db" NFTFW_CONTROL_SOCKET="$lab_tmp/missing.sock" NFTFW_LOCAL=1 "$nftfw")
ip netns exec "$vpn_ns" "${local_cli[@]}" apply --unsafe >/dev/null

wait_handshake() {
    for _ in $(seq 1 30); do
        latest=$(ip netns exec "$vpn_ns" wg show wg-real latest-handshakes 2>/dev/null | awk '{ if ($2 > latest) latest=$2 } END { print latest+0 }')
        [[ "$latest" -gt 0 ]] && return 0
        # A valid profile need not configure PersistentKeepalive. Generate
        # synthetic traffic so WireGuard has a reason to initiate a handshake.
        ip netns exec "$vpn_ns" ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || true
        sleep 1
    done
    return 1
}
wait_handshake || { echo "FAIL: real WireGuard handshake timed out"; exit 1; }
echo "REAL WIREGUARD HANDSHAKE: PASS"

vpn_ip=$(public_ipv4 "$vpn_ns" || true)
[[ "$vpn_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$vpn_ip" != "$physical_ip" ]] || { echo "FAIL: real VPN public IPv4 did not change"; exit 1; }
echo "REAL VPN PUBLIC IPV4 CHANGE: PASS"
ip netns exec "$vpn_ns" getent ahostsv4 example.com >/dev/null || { echo "FAIL: DNS through real VPN"; exit 1; }
echo "REAL VPN DNS: PASS"
container_ip=$(public_ipv4 "$ctr_ns" || true)
if [[ ! "$container_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    route_status=FAIL
    ip netns exec "$vpn_ns" ip route get 1.1.1.1 from 10.204.0.2 iif ctr-host 2>/dev/null | grep -q 'dev wg-real' && route_status=PASS
    forward_packets=$(ip netns exec "$vpn_ns" nft list chain inet nftfw_filter forward 2>/dev/null | awk '/nftfw:container-vpn-egress/ { for (i=1; i<=NF; i++) if ($i == "packets") { print $(i+1); exit } }')
    [[ "$forward_packets" =~ ^[0-9]+$ ]] || forward_packets=0
    timeout 5 ip netns exec "$vpn_ns" tcpdump -qn -Q out -i wg-real -c 1 icmp >/dev/null 2>&1 & diag_out_pid=$!
    timeout 5 ip netns exec "$vpn_ns" tcpdump -qn -Q in -i wg-real -c 1 icmp >/dev/null 2>&1 & diag_in_pid=$!
    timeout 5 ip netns exec "$vpn_ns" tcpdump -qn -Q out -i ctr-host -c 1 icmp >/dev/null 2>&1 & diag_ctr_pid=$!
    sleep 0.3
    set +e
    ip netns exec "$ctr_ns" ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; diag_ping_rc=$?
    set -e
    set +e
    wait "$diag_out_pid"; diag_out_rc=$?
    wait "$diag_in_pid"; diag_in_rc=$?
    wait "$diag_ctr_pid"; diag_ctr_rc=$?
    set -e
    [[ "$diag_out_rc" -eq 0 ]] && diag_out=PASS || diag_out=FAIL
    [[ "$diag_in_rc" -eq 0 ]] && diag_in=PASS || diag_in=FAIL
    [[ "$diag_ctr_rc" -eq 0 ]] && diag_ctr=PASS || diag_ctr=FAIL
    [[ "$diag_ping_rc" -eq 0 ]] && diag_ping=PASS || diag_ping=FAIL
    ip netns exec "$ctr_ns" getent ahostsv4 api.ipify.org >/dev/null 2>&1 && diag_dns=PASS || diag_dns=FAIL
    ip netns exec "$ctr_ns" nc -z -w 5 1.1.1.1 443 >/dev/null 2>&1 && diag_tcp=PASS || diag_tcp=FAIL
    ip netns exec "$ctr_ns" ping -c 1 -W 2 -M 'do' -s 1300 1.1.1.1 >/dev/null 2>&1 && diag_mtu=PASS || diag_mtu=FAIL
    timeout 5 ip netns exec "$vpn_ns" tcpdump -nvv -i ctr-host -c 1 'tcp[tcpflags] & tcp-syn != 0 and dst port 443' >"$lab_tmp/mss-veth.txt" 2>/dev/null & diag_mss_veth_pid=$!
    timeout 5 ip netns exec "$vpn_ns" tcpdump -nvv -i wg-real -c 1 'tcp[tcpflags] & tcp-syn != 0 and dst port 443' >"$lab_tmp/mss-wg.txt" 2>/dev/null & diag_mss_wg_pid=$!
    sleep 0.3
    ip netns exec "$ctr_ns" nc -z -w 2 1.1.1.1 443 >/dev/null 2>&1 || true
    set +e
    wait "$diag_mss_veth_pid"
    wait "$diag_mss_wg_pid"
    set -e
    mss_veth=$(sed -n 's/.*mss \([0-9][0-9]*\).*/\1/p' "$lab_tmp/mss-veth.txt" | head -1)
    mss_wg=$(sed -n 's/.*mss \([0-9][0-9]*\).*/\1/p' "$lab_tmp/mss-wg.txt" | head -1)
    [[ "$mss_veth" =~ ^[0-9]+$ ]] || mss_veth=unavailable
    [[ "$mss_wg" =~ ^[0-9]+$ ]] || mss_wg=unavailable
    wg_ipv4=$(ip -n "$vpn_ns" -4 -o address show dev wg-real | awk '{ split($4, p, "/"); print p[1]; exit }')
    if [[ -n "$wg_ipv4" ]] && grep -Fq " $wg_ipv4." "$lab_tmp/mss-wg.txt"; then diag_nat=PASS; else diag_nat=FAIL; fi
    wg_mtu=$(ip -n "$vpn_ns" -o link show dev wg-real | awk '{ for (i=1; i<=NF; i++) if ($i == "mtu") { print $(i+1); exit } }')
    timeout 15 ip netns exec "$ctr_ns" openssl s_client -brief -connect 1.1.1.1:443 -servername one.one.one.one </dev/null >/dev/null 2>&1 && diag_tls=PASS || diag_tls=FAIL
    timeout 8 ip netns exec "$vpn_ns" tcpdump -ln -i ctr-host -c 20 'tcp port 443' >"$lab_tmp/tcp-veth.txt" 2>/dev/null & diag_tcp_veth_pid=$!
    timeout 8 ip netns exec "$vpn_ns" tcpdump -ln -i wg-real -c 20 'tcp port 443' >"$lab_tmp/tcp-wg.txt" 2>/dev/null & diag_tcp_wg_pid=$!
    sleep 0.3
    timeout 6 ip netns exec "$ctr_ns" openssl s_client -brief -connect 1.1.1.1:443 -servername one.one.one.one </dev/null >/dev/null 2>&1 || true
    set +e
    wait "$diag_tcp_veth_pid"
    wait "$diag_tcp_wg_pid"
    set -e
    tcp_veth_sequence=$(sed -n 's/.*Flags \(\[[^]]*\]\).*length \([0-9][0-9]*\).*/\1:\2/p' "$lab_tmp/tcp-veth.txt" | paste -sd, -)
    tcp_wg_sequence=$(sed -n 's/.*Flags \(\[[^]]*\]\).*length \([0-9][0-9]*\).*/\1:\2/p' "$lab_tmp/tcp-wg.txt" | paste -sd, -)
    [[ -n "$tcp_veth_sequence" ]] || tcp_veth_sequence=unavailable
    [[ -n "$tcp_wg_sequence" ]] || tcp_wg_sequence=unavailable
    curl_metrics=$(ip netns exec "$ctr_ns" curl -4sS -o /dev/null --max-time 15 -w 'exit=%{exitcode} http=%{http_code} connect=%{time_connect} tls=%{time_appconnect} total=%{time_total} bytes=%{size_download}' https://api.ipify.org 2>/dev/null || true)
    forward_drops=$(ip netns exec "$vpn_ns" nft list chain inet nftfw_filter forward 2>/dev/null | awk '/nftfw:forward-default-deny/ { for (i=1; i<=NF; i++) if ($i == "packets") { print $(i+1); exit } }')
    input_drops=$(ip netns exec "$vpn_ns" nft list chain inet nftfw_filter input 2>/dev/null | awk '/nftfw:input-default-deny/ { for (i=1; i<=NF; i++) if ($i == "packets") { print $(i+1); exit } }')
    output_drops=$(ip netns exec "$vpn_ns" nft list chain inet nftfw_filter output 2>/dev/null | awk '/nftfw:output-default-deny/ { for (i=1; i<=NF; i++) if ($i == "packets") { print $(i+1); exit } }')
    [[ "$forward_drops" =~ ^[0-9]+$ ]] || forward_drops=unavailable
    [[ "$input_drops" =~ ^[0-9]+$ ]] || input_drops=unavailable
    [[ "$output_drops" =~ ^[0-9]+$ ]] || output_drops=unavailable
    echo "CONTAINER ROUTE VIA WIREGUARD: $route_status"
    echo "CONTAINER VPN RULE PACKETS: $forward_packets"
    echo "CONTAINER PACKET ON WG EGRESS: $diag_out"
    echo "CONTAINER REPLY ON WG INGRESS: $diag_in"
    echo "CONTAINER REPLY ON VETH: $diag_ctr"
    echo "CONTAINER PING: $diag_ping"
    echo "CONTAINER DNS: $diag_dns"
    echo "CONTAINER TCP CONNECT: $diag_tcp"
    echo "CONTAINER 1300-BYTE PATH: $diag_mtu"
    echo "CONTAINER SYN MSS BEFORE/AFTER: $mss_veth/$mss_wg"
    echo "CONTAINER NAT TO TUNNEL ADDRESS: $diag_nat"
    echo "WIREGUARD INTERFACE MTU: $wg_mtu"
    echo "CONTAINER TLS HANDSHAKE: $diag_tls"
    echo "CONTAINER TCP FLAGS/LENGTHS VETH: $tcp_veth_sequence"
    echo "CONTAINER TCP FLAGS/LENGTHS WG: $tcp_wg_sequence"
    echo "CONTAINER CURL METRICS: $curl_metrics"
    echo "NFT TERMINAL DROPS FORWARD/INPUT/OUTPUT: $forward_drops/$input_drops/$output_drops"
    echo "FAIL: container had no real VPN IPv4 egress"
    exit 1
fi
[[ "$container_ip" != "$physical_ip" ]] || { echo "FAIL: container used the physical IPv4 exit"; exit 1; }
echo "REAL VPN CONTAINER EGRESS: PASS"
if [[ "$docker_mode" == 1 ]]; then echo "REAL DOCKER CONTAINER VPN EGRESS: PASS"; fi
if (( has_ipv6 )); then
    vpn_ipv6=$(ip netns exec "$vpn_ns" curl -6fsS --max-time 15 https://api64.ipify.org 2>/dev/null || true)
    [[ "$vpn_ipv6" == *:* ]] || { echo "FAIL: real VPN IPv6 unavailable"; exit 1; }
    echo "REAL VPN IPV6 EGRESS: PASS"
fi

start_daemon() {
    rm -f "$lab_tmp/status.sock" "$lab_tmp/control.sock"
    ip netns exec "$vpn_ns" env NFTFW_STATE_DB="$lab_tmp/state/generation-state/state.db" "$nftfwd" --config "$lab_tmp/nftfw.toml" --status-socket "$lab_tmp/status.sock" --control-socket "$lab_tmp/control.sock" >"$lab_tmp/daemon.log" 2>&1 &
    daemon_pid=$!
    for _ in $(seq 1 100); do [[ -S "$lab_tmp/control.sock" ]] && return 0; sleep 0.05; done
    return 1
}
start_daemon || { echo "FAIL: nftfwd did not start in live namespace"; exit 1; }
env NFTFW_CONFIG="$lab_tmp/nftfw.toml" NFTFW_CONTROL_SOCKET="$lab_tmp/control.sock" "$nftfw" wg refresh >/dev/null
echo "REAL ENDPOINT SET REFRESH: PASS"
kill -TERM "$daemon_pid"; wait "$daemon_pid" || true; daemon_pid=""
start_daemon || { echo "FAIL: nftfwd did not restart"; exit 1; }
restart_ip=$(public_ipv4 "$vpn_ns" || true)
[[ "$restart_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$restart_ip" != "$physical_ip" ]] || { echo "FAIL: VPN egress unavailable after daemon restart"; exit 1; }
echo "REAL DAEMON RESTART: PASS"

ip -n "$vpn_ns" link del wg-real
capture="$lab_tmp/physical-capture.txt"
timeout 6 tcpdump -qn -i "$host_if" -c 1 "ip and not host $endpoint_ip" >"$capture" 2>&1 & capture_pid=$!
sleep 0.3
if ip netns exec "$vpn_ns" ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1; then echo "FAIL: real host traffic leaked after VPN loss"; exit 1; fi
if ip netns exec "$ctr_ns" ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1; then echo "FAIL: real container traffic leaked after VPN loss"; exit 1; fi
if ip netns exec "$vpn_ns" curl -4kfsS --max-time 3 https://1.1.1.1 >/dev/null 2>&1; then echo "FAIL: real host TCP leaked after VPN loss"; exit 1; fi
if ip netns exec "$ctr_ns" curl -4kfsS --max-time 3 https://1.1.1.1 >/dev/null 2>&1; then echo "FAIL: real container TCP leaked after VPN loss"; exit 1; fi
set +e; wait "$capture_pid"; capture_rc=$?; set -e; capture_pid=""
[[ "$capture_rc" -eq 124 ]] || { echo "FAIL: physical packet capture observed non-endpoint IPv4 traffic"; exit 1; }
echo "REAL VPN LOSS HOST: PASS"
echo "REAL VPN LOSS CONTAINER: PASS"
if [[ "$docker_mode" == 1 ]]; then echo "REAL DOCKER CONTAINER VPN LOSS: PASS"; fi
echo "REAL LEAKED PHYSICAL PACKETS: 0"

configure_wireguard
wait_handshake || { echo "FAIL: real WireGuard did not recover"; exit 1; }
recovered_ip=$(public_ipv4 "$vpn_ns" || true)
[[ "$recovered_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$recovered_ip" != "$physical_ip" ]] || { echo "FAIL: real VPN egress did not recover"; exit 1; }
recovered_container_ip=$(public_ipv4 "$ctr_ns" || true)
[[ "$recovered_container_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$recovered_container_ip" != "$physical_ip" ]] || { echo "FAIL: real container egress did not recover through VPN"; exit 1; }
echo "REAL WIREGUARD RESTART/RECOVERY: PASS"
if [[ "$docker_mode" == 1 ]]; then echo "REAL DOCKER CONTAINER RECOVERY: PASS"; fi
echo "REAL WIREGUARD ACCEPTANCE: PASS"
