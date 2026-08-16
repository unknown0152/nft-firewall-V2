#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "BLOCKED: namespace test requires root"; exit 77; fi
for tool in ip nft wg ping timeout tcpdump python3; do command -v "$tool" >/dev/null || { echo "BLOCKED: missing $tool"; exit 77; }; done

tag="nftfw-$PPID-$$"
host_ns="${tag}-host"; inet_ns="${tag}-inet"; vpn_ns="${tag}-vpn"; ctr_ns="${tag}-ctr"
lab_tmp=$(mktemp -d /tmp/nftfw-lab.XXXXXX)
lab_pids=()
cleanup(){ set +e; for pid in "${lab_pids[@]}"; do kill "$pid" 2>/dev/null; done; for ns in "$ctr_ns" "$host_ns" "$vpn_ns" "$inet_ns"; do ip netns del "$ns" 2>/dev/null; done; rm -rf "$lab_tmp"; }
trap cleanup EXIT

if ! ip netns add "$host_ns" 2>/dev/null; then echo "BLOCKED: CAP_NET_ADMIN/network namespace creation unavailable"; exit 77; fi
ip netns add "$inet_ns"; ip netns add "$vpn_ns"; ip netns add "$ctr_ns"

ip link add h-ext type veth peer name i-host; ip link set h-ext netns "$host_ns"; ip link set i-host netns "$inet_ns"
ip link add v-ext type veth peer name i-vpn; ip link set v-ext netns "$vpn_ns"; ip link set i-vpn netns "$inet_ns"
ip link add c-host type veth peer name c-eth; ip link set c-host netns "$host_ns"; ip link set c-eth netns "$ctr_ns"
for ns in "$host_ns" "$inet_ns" "$vpn_ns" "$ctr_ns"; do ip -n "$ns" link set lo up; done
ip -n "$host_ns" addr add 198.18.0.2/30 dev h-ext; ip -n "$host_ns" link set h-ext up
ip -n "$inet_ns" addr add 198.18.0.1/30 dev i-host; ip -n "$inet_ns" link set i-host up
ip -n "$vpn_ns" addr add 198.18.0.6/30 dev v-ext; ip -n "$vpn_ns" link set v-ext up
ip -n "$inet_ns" addr add 198.18.0.5/30 dev i-vpn; ip -n "$inet_ns" link set i-vpn up
ip -n "$host_ns" addr add 172.30.0.1/24 dev c-host; ip -n "$host_ns" link set c-host up
ip -n "$ctr_ns" addr add 172.30.0.2/24 dev c-eth; ip -n "$ctr_ns" link set c-eth up
ip -n "$host_ns" -6 addr add fd00:1::2/64 dev h-ext
ip -n "$inet_ns" -6 addr add fd00:1::1/64 dev i-host
ip -n "$vpn_ns" -6 addr add fd00:2::2/64 dev v-ext
ip -n "$inet_ns" -6 addr add fd00:2::1/64 dev i-vpn
ip -n "$host_ns" -6 addr add fd00:30::1/64 dev c-host
ip -n "$ctr_ns" -6 addr add fd00:30::2/64 dev c-eth
ip -n "$ctr_ns" route add default via 172.30.0.1
ip -n "$ctr_ns" -6 route add default via fd00:30::1
ip -n "$host_ns" route add default via 198.18.0.1
ip -n "$host_ns" -6 route add default via fd00:1::1
ip -n "$host_ns" route add 198.18.0.6/32 via 198.18.0.1
ip -n "$vpn_ns" route add default via 198.18.0.5
ip -n "$vpn_ns" -6 route add default via fd00:2::1
ip -n "$inet_ns" addr add 203.0.113.1/32 dev lo
ip -n "$inet_ns" -6 addr add 2001:db8:ffff::1/128 dev lo
ip -n "$inet_ns" -6 route add fd00:99::/64 via fd00:2::2
ip -n "$inet_ns" -6 route add fd00:30::/64 via fd00:2::2
ip netns exec "$inet_ns" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$host_ns" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$vpn_ns" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$inet_ns" sysctl -qw net.ipv6.conf.all.forwarding=1
ip netns exec "$host_ns" sysctl -qw net.ipv6.conf.all.forwarding=1
ip netns exec "$vpn_ns" sysctl -qw net.ipv6.conf.all.forwarding=1

umask 077
wg genkey > "$lab_tmp/host.key"; wg pubkey < "$lab_tmp/host.key" > "$lab_tmp/host.pub"
wg genkey > "$lab_tmp/vpn.key"; wg pubkey < "$lab_tmp/vpn.key" > "$lab_tmp/vpn.pub"
ip -n "$host_ns" link add wg-test type wireguard; ip -n "$vpn_ns" link add wg-test type wireguard
ip -n "$host_ns" addr add 10.99.0.1/24 dev wg-test; ip -n "$vpn_ns" addr add 10.99.0.2/24 dev wg-test
ip -n "$host_ns" -6 addr add fd00:99::1/64 dev wg-test; ip -n "$vpn_ns" -6 addr add fd00:99::2/64 dev wg-test
ip netns exec "$host_ns" wg set wg-test private-key "$lab_tmp/host.key" fwmark 51820 peer "$(<"$lab_tmp/vpn.pub")" endpoint 198.18.0.6:51820 allowed-ips 0.0.0.0/0,::/0 persistent-keepalive 1
ip netns exec "$vpn_ns" wg set wg-test listen-port 51820 private-key "$lab_tmp/vpn.key" peer "$(<"$lab_tmp/host.pub")" allowed-ips 10.99.0.1/32,172.30.0.0/24,fd00:99::1/128,fd00:30::/64
ip -n "$host_ns" link set wg-test up; ip -n "$vpn_ns" link set wg-test up
ip -n "$vpn_ns" route add 172.30.0.0/24 dev wg-test
ip -n "$vpn_ns" -6 route add fd00:30::/64 dev wg-test
if ! ip netns exec "$host_ns" ping -c 1 -W 2 198.18.0.6 >/dev/null; then
    echo "FAIL: physical endpoint path unavailable before firewall application"
    ip -n "$host_ns" route show table all || true
    ip -n "$inet_ns" route show table all || true
    ip -n "$vpn_ns" route show table all || true
    ip netns exec "$inet_ns" sysctl net.ipv4.ip_forward || true
    ip netns exec "$host_ns" ping -c 1 -W 1 198.18.0.1 || true
    ip netns exec "$inet_ns" ping -c 1 -W 1 198.18.0.6 || true
    exit 1
fi
ip -n "$host_ns" route add default dev wg-test table 51820
ip netns exec "$host_ns" ip rule add table main suppress_prefixlength 0 priority 100
ip netns exec "$host_ns" ip rule add not fwmark 51820 table 51820 priority 101
ip -n "$host_ns" -6 route add default dev wg-test table 51820
ip netns exec "$host_ns" ip -6 rule add table main suppress_prefixlength 0 priority 100
ip netns exec "$host_ns" ip -6 rule add not fwmark 51820 table 51820 priority 101
ip netns exec "$vpn_ns" nft -f - <<'NFT'
table ip test_vpn_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "v-ext" masquerade
    }
}
table inet test_vpn_filter {
    chain forward {
        type filter hook forward priority filter; policy accept;
    }
}
NFT

cat > "$lab_tmp/nftfw.toml" <<'TOML'
[system]
ipv6_mode = "vpn"
strict_vpn = true
[[interfaces]]
name = "h-ext"
role = "uplink"
[[interfaces]]
name = "wg-test"
role = "vpn"
[[interfaces]]
name = "c-host"
role = "container"
cidrs = ["172.30.0.0/24", "fd00:30::/64"]
[[zones]]
name = "lan"
networks = ["172.30.0.0/24", "fd00:30::/64"]
[[services]]
name = "probe"
protocol = "icmp"
ports = []
[[services]]
name = "active-tcp"
protocol = "tcp"
ports = [8080]
[[services]]
name = "active-udp"
protocol = "udp"
ports = [9090]
[[services]]
name = "dnat-probe"
protocol = "tcp"
ports = [10080]
[[policies]]
name = "host-to-internet-probe"
from = "host"
to = "any"
service = "probe"
action = "allow"
[[policies]]
name = "host-active-tcp"
from = "host"
to = "any"
service = "active-tcp"
action = "allow"
[[policies]]
name = "lan-active-tcp"
from = "lan"
to = "any"
service = "active-tcp"
action = "allow"
[[policies]]
name = "host-active-udp"
from = "host"
to = "any"
service = "active-udp"
action = "allow"
[[policies]]
name = "lan-active-udp"
from = "lan"
to = "any"
service = "active-udp"
action = "allow"
[[policies]]
name = "lan-to-internet-probe"
from = "lan"
to = "any"
service = "probe"
action = "allow"
[[policies]]
name = "published-probe"
from = "any"
to = "lan"
service = "dnat-probe"
action = "allow"
[[nat]]
name = "published-probe"
source = "any"
external_interface = "h-ext"
protocol = "tcp"
external_port = 18080
destination = "172.30.0.2"
destination_port = 10080
[wireguard]
interface = "wg-test"
endpoint_port = 51820
fwmark = "0xca6c"
bootstrap_ips = ["198.18.0.6/32"]
bootstrap_ips_v6 = []
[state]
directory = "/tmp/nftfw-lab-state"
database = "/tmp/nftfw-lab-state/state.db"
TOML
chmod 600 "$lab_tmp/nftfw.toml"

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
flow_probe="$root_dir/tests/namespaces/flow_probe.py"
case "$(uname -m)" in x86_64) build_arch=amd64 ;; aarch64|arm64) build_arch=arm64 ;; *) echo "BLOCKED: unsupported test architecture"; exit 77 ;; esac
nftfw_bin="$root_dir/dist/nftfw-linux-$build_arch"
nftfw_local=(env NFTFW_CONFIG="$lab_tmp/nftfw.toml" NFTFW_STATE_DB="$lab_tmp/state.db" NFTFW_CONTROL_SOCKET="$lab_tmp/no-control.sock" NFTFW_LOCAL=1 "$nftfw_bin")
ip netns exec "$host_ns" "${nftfw_local[@]}" apply --unsafe >/dev/null
ip netns exec "$host_ns" "${nftfw_local[@]}" apply --unsafe >/dev/null
echo "ATOMIC REPEATED APPLY: PASS"

ip netns exec "$host_ns" nft -f - <<'NFT'
table inet third_party_test {
    chain marker { comment "third-party-preserve"; }
}
NFT
marker_handle=$(ip netns exec "$host_ns" nft -a list chain inet nftfw_filter output | awk '/nftfw:vpn-only-egress/ { print $NF }')
[[ "$marker_handle" =~ ^[0-9]+$ ]] || { echo "FAIL: could not locate owned marker rule"; exit 1; }
ip netns exec "$host_ns" nft delete rule inet nftfw_filter output handle "$marker_handle"
ip netns exec "$host_ns" "${nftfw_local[@]}" reconcile >/dev/null
ip netns exec "$host_ns" nft list chain inet nftfw_filter output | grep -F 'nftfw:vpn-only-egress' >/dev/null
echo "DRIFT DELETED RULE: PASS"

marker_handle=$(ip netns exec "$host_ns" nft -a list chain inet nftfw_filter output | awk '/nftfw:vpn-only-egress/ { print $NF }')
ip netns exec "$host_ns" nft -f - <<NFT
replace rule inet nftfw_filter output handle $marker_handle counter accept comment "nftfw:vpn-only-egress"
NFT
ip netns exec "$host_ns" "${nftfw_local[@]}" reconcile >/dev/null
ip netns exec "$host_ns" nft list chain inet nftfw_filter output | grep -F 'nftfw:vpn-only-egress' >/dev/null
if ip netns exec "$host_ns" nft list chain inet nftfw_filter output | grep -F 'accept comment "nftfw:vpn-only-egress"' >/dev/null; then
    echo "FAIL: marker-preserving rule tampering was not repaired"
    exit 1
fi
echo "DRIFT MODIFIED RULE WITH MARKER RETAINED: PASS"

ip netns exec "$host_ns" nft delete table ip6 nftfw_filter6
ip netns exec "$host_ns" "${nftfw_local[@]}" reconcile >/dev/null
ip netns exec "$host_ns" nft list table ip6 nftfw_filter6 >/dev/null
ip netns exec "$host_ns" nft list table inet third_party_test | grep -F 'third-party-preserve' >/dev/null
echo "DRIFT DELETED TABLE: PASS"
echo "UNRELATED TABLE PRESERVED: PASS"

dnat_ready="$lab_tmp/dnat-ready"
ip netns exec "$ctr_ns" python3 "$root_dir/tests/namespaces/dnat_probe.py" server 172.30.0.2 10080 "$dnat_ready" & dnat_server_pid=$!; lab_pids+=("$dnat_server_pid")
for _ in $(seq 1 100); do [[ -e "$dnat_ready" ]] && break; sleep 0.05; done
[[ -e "$dnat_ready" ]] || { echo "FAIL: DNAT probe server did not bind"; exit 1; }
ip netns exec "$inet_ns" python3 "$root_dir/tests/namespaces/dnat_probe.py" client 198.18.0.2 18080
wait "$dnat_server_pid" || { echo "FAIL: DNAT probe server failed"; exit 1; }
echo "TYPED DNAT ROUND TRIP: PASS"

sleep 2
if ! ip netns exec "$host_ns" ping -c 2 -W 2 203.0.113.1 >/dev/null; then
    echo "FAIL: healthy host probe failed"
    ip netns exec "$host_ns" wg show wg-test latest-handshakes || true
    ip -n "$host_ns" route show table all || true
    ip netns exec "$host_ns" nft list chain inet nftfw_filter output || true
    exit 1
fi
if ! ip netns exec "$ctr_ns" ping -c 2 -W 2 203.0.113.1 >/dev/null; then
    echo "FAIL: healthy container probe failed"
    ip -n "$ctr_ns" route show table all || true
    ip -n "$vpn_ns" route show table all || true
    ip netns exec "$host_ns" nft list chain inet nftfw_filter forward || true
    exit 1
fi
if ! ip netns exec "$host_ns" ping -6 -c 2 -W 2 2001:db8:ffff::1 >/dev/null; then
    echo "FAIL: healthy IPv6 host probe failed"
    ip -n "$host_ns" -6 route show table all || true
    ip netns exec "$host_ns" nft list chain inet nftfw_filter output || true
    exit 1
fi
if ! ip netns exec "$ctr_ns" ping -6 -c 2 -W 2 2001:db8:ffff::1 >/dev/null; then
    echo "FAIL: healthy IPv6 container probe failed"
    ip -n "$ctr_ns" -6 address show || true
    ip -n "$ctr_ns" -6 route show table all || true
    ip netns exec "$ctr_ns" ping -6 -c 1 -W 1 fd00:30::1 || true
    ip netns exec "$host_ns" sysctl net.ipv6.conf.all.forwarding net.ipv6.conf.c-host.forwarding || true
    ip -n "$vpn_ns" -6 route show table all || true
    ip netns exec "$host_ns" wg show wg-test transfer || true
    ip netns exec "$host_ns" nft list set inet nftfw_filter docker_nets6 || true
    ip netns exec "$host_ns" nft list chain inet nftfw_filter forward || true
    exit 1
fi
echo "VPN HEALTHY HOST: PASS"
echo "VPN HEALTHY CONTAINER: PASS"
echo "VPN HEALTHY IPV6 HOST: PASS"
echo "VPN HEALTHY IPV6 CONTAINER: PASS"

trigger="$lab_tmp/release-active-flows"
tcp_ready="$lab_tmp/tcp-server-ready"; udp_ready="$lab_tmp/udp-server-ready"
tcp6_ready="$lab_tmp/tcp6-server-ready"; udp6_ready="$lab_tmp/udp6-server-ready"
ip netns exec "$inet_ns" python3 "$flow_probe" server tcp 203.0.113.1 8080 "$tcp_ready" "$trigger" --bound "$lab_tmp/tcp-bound" --count 2 & tcp_server_pid=$!; lab_pids+=("$tcp_server_pid")
ip netns exec "$inet_ns" python3 "$flow_probe" server udp 203.0.113.1 9090 "$udp_ready" "$trigger" --bound "$lab_tmp/udp-bound" --count 2 & udp_server_pid=$!; lab_pids+=("$udp_server_pid")
ip netns exec "$inet_ns" python3 "$flow_probe" server tcp 2001:db8:ffff::1 8080 "$tcp6_ready" "$trigger" --bound "$lab_tmp/tcp6-bound" --count 2 & tcp6_server_pid=$!; lab_pids+=("$tcp6_server_pid")
ip netns exec "$inet_ns" python3 "$flow_probe" server udp 2001:db8:ffff::1 9090 "$udp6_ready" "$trigger" --bound "$lab_tmp/udp6-bound" --count 2 & udp6_server_pid=$!; lab_pids+=("$udp6_server_pid")
for marker in "$lab_tmp/tcp-bound" "$lab_tmp/udp-bound" "$lab_tmp/tcp6-bound" "$lab_tmp/udp6-bound"; do
    for _ in $(seq 1 100); do [[ -e "$marker" ]] && break; sleep 0.05; done
    [[ -e "$marker" ]] || { echo "FAIL: active-flow server did not bind"; exit 1; }
done
ip netns exec "$host_ns" python3 "$flow_probe" client tcp 203.0.113.1 8080 "$lab_tmp/tcp-host-client" "$trigger" & tcp_host_pid=$!; lab_pids+=("$tcp_host_pid")
ip netns exec "$ctr_ns" python3 "$flow_probe" client tcp 203.0.113.1 8080 "$lab_tmp/tcp-ctr-client" "$trigger" & tcp_ctr_pid=$!; lab_pids+=("$tcp_ctr_pid")
ip netns exec "$host_ns" python3 "$flow_probe" client udp 203.0.113.1 9090 "$lab_tmp/udp-host-client" "$trigger" & udp_host_pid=$!; lab_pids+=("$udp_host_pid")
ip netns exec "$ctr_ns" python3 "$flow_probe" client udp 203.0.113.1 9090 "$lab_tmp/udp-ctr-client" "$trigger" & udp_ctr_pid=$!; lab_pids+=("$udp_ctr_pid")
ip netns exec "$host_ns" python3 "$flow_probe" client tcp 2001:db8:ffff::1 8080 "$lab_tmp/tcp6-host-client" "$trigger" & tcp6_host_pid=$!; lab_pids+=("$tcp6_host_pid")
ip netns exec "$ctr_ns" python3 "$flow_probe" client tcp 2001:db8:ffff::1 8080 "$lab_tmp/tcp6-ctr-client" "$trigger" & tcp6_ctr_pid=$!; lab_pids+=("$tcp6_ctr_pid")
ip netns exec "$host_ns" python3 "$flow_probe" client udp 2001:db8:ffff::1 9090 "$lab_tmp/udp6-host-client" "$trigger" & udp6_host_pid=$!; lab_pids+=("$udp6_host_pid")
ip netns exec "$ctr_ns" python3 "$flow_probe" client udp 2001:db8:ffff::1 9090 "$lab_tmp/udp6-ctr-client" "$trigger" & udp6_ctr_pid=$!; lab_pids+=("$udp6_ctr_pid")
for marker in "$tcp_ready" "$udp_ready" "$tcp6_ready" "$udp6_ready"; do
    for _ in $(seq 1 100); do [[ -e "$marker" ]] && break; sleep 0.05; done
    [[ -e "$marker" ]] || { echo "FAIL: active flow was not established through WireGuard"; exit 1; }
done

ip -n "$host_ns" link del wg-test
capture="$lab_tmp/capture.txt"
ip netns exec "$inet_ns" timeout 5 tcpdump -qn -i i-host -c 1 'dst host 203.0.113.1 and (icmp or tcp port 8080 or udp port 9090)' > "$capture" 2>&1 & capture_pid=$!; lab_pids+=("$capture_pid")
capture6="$lab_tmp/capture6.txt"
ip netns exec "$inet_ns" timeout 5 tcpdump -qn -i i-host -c 1 'ip6 and dst host 2001:db8:ffff::1' > "$capture6" 2>&1 & capture6_pid=$!; lab_pids+=("$capture6_pid")
sleep 0.3
touch "$trigger"
if ip netns exec "$host_ns" ping -c 1 -W 1 203.0.113.1 >/dev/null 2>&1; then echo "FAIL: host escaped after WireGuard removal"; exit 1; fi
if ip netns exec "$ctr_ns" ping -c 1 -W 1 203.0.113.1 >/dev/null 2>&1; then echo "FAIL: container escaped after WireGuard removal"; exit 1; fi
if ip netns exec "$host_ns" ping -6 -c 1 -W 1 2001:db8:ffff::1 >/dev/null 2>&1; then echo "FAIL: IPv6 host escaped after WireGuard removal"; exit 1; fi
if ip netns exec "$ctr_ns" ping -6 -c 1 -W 1 2001:db8:ffff::1 >/dev/null 2>&1; then echo "FAIL: IPv6 container escaped after WireGuard removal"; exit 1; fi
for pid in "$tcp_host_pid" "$tcp_ctr_pid" "$udp_host_pid" "$udp_ctr_pid" "$tcp6_host_pid" "$tcp6_ctr_pid" "$udp6_host_pid" "$udp6_ctr_pid"; do wait "$pid" || { echo "FAIL: active-flow client failed"; exit 1; }; done
set +e; wait "$capture_pid"; capture_rc=$?; wait "$capture6_pid"; capture6_rc=$?; set -e
if [[ $capture_rc -ne 124 && $capture_rc -ne 0 ]]; then echo "BLOCKED: packet capture failed (rc=$capture_rc)"; exit 77; fi
if [[ $capture6_rc -ne 124 && $capture6_rc -ne 0 ]]; then echo "BLOCKED: IPv6 packet capture failed (rc=$capture6_rc)"; exit 77; fi
if grep -q '203.0.113.1' "$capture"; then echo "LEAKED INTERNET PACKETS: 1"; exit 1; fi
if grep -q '2001:db8:ffff::1' "$capture6"; then echo "LEAKED IPV6 INTERNET PACKETS: 1"; exit 1; fi
echo "WIREGUARD REMOVED HOST: PASS"
echo "WIREGUARD REMOVED CONTAINER: PASS"
echo "ACTIVE TCP HOST/CONTAINER: PASS"
echo "ACTIVE UDP HOST/CONTAINER: PASS"
echo "WIREGUARD REMOVED IPV6 HOST: PASS"
echo "WIREGUARD REMOVED IPV6 CONTAINER: PASS"
echo "ACTIVE IPV6 TCP/UDP HOST/CONTAINER: PASS"
echo "LEAKED INTERNET PACKETS: 0"
echo "LEAKED IPV6 INTERNET PACKETS: 0"
