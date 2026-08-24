#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "BLOCKED: host safe-apply acceptance requires root"
    exit 77
fi
for tool in systemctl systemd-run nft ip ss jq sqlite3 tcpdump timeout curl ping flock python3; do
    command -v "$tool" >/dev/null || { echo "BLOCKED: missing $tool"; exit 77; }
done

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work_root=$(cd "$root_dir/.." && pwd)
helper="$root_dir/tests/acceptance/emergency_rollback.sh"
case "$(uname -m)" in
    x86_64) build_arch=amd64 ;;
    aarch64|arm64) build_arch=arm64 ;;
    *) echo "BLOCKED: unsupported host architecture"; exit 77 ;;
esac
nftfw="$root_dir/dist/nftfw-linux-$build_arch"
[[ -x "$nftfw" && -x "$helper" ]] || { echo "BLOCKED: release binary or rollback helper missing"; exit 77; }

exec {lock_fd}>/run/nftfw-host-acceptance.lock
flock -n "$lock_fd" || { echo "BLOCKED: another host acceptance run is active"; exit 77; }

run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
lab_tmp=$(mktemp -d "/run/nftfw-host-acceptance.${run_id}.XXXXXX")
result_dir="$work_root/test-results/host-safe-apply/$run_id"
state_dir="/var/lib/nftfw/host-acceptance-$run_id"
state_db="$state_dir/generation-state/state.db"
provenance_ledger="$state_dir/provenance-ledger.db"
config_path="/etc/nftfw/host-acceptance-$run_id.toml"
dropin_dir=/run/systemd/system/nftfw-rollback.service.d
dropin="$dropin_dir/90-host-acceptance.conf"
emergency_unit="nftfw-host-emergency-$run_id"
crash_unit="nftfw-host-crash-$run_id"
third_party=nftfw_host_acceptance_third_party
marker="$lab_tmp/commit.marker"
backup="$lab_tmp/previous-owned.nft"
emergency_result="$result_dir/emergency-rollback.txt"
daemon_was_active=0
web_was_active=0
armed=0
success=0

mkdir -p "$result_dir"
chmod 0700 "$result_dir"
: >"$backup"
chmod 0600 "$backup"
if systemctl is-active --quiet nftfwd.service; then daemon_was_active=1; fi
if systemctl is-active --quiet nftfw-web.service; then web_was_active=1; fi

owned_present() {
    nft list table inet nftfw_filter >/dev/null 2>&1 ||
        nft list table ip nftfw_nat >/dev/null 2>&1 ||
        nft list table ip6 nftfw_filter6 >/dev/null 2>&1
}

cleanup() {
    local rc=$?
    set +e
    if (( success == 0 )) && owned_present; then
        "$helper" "$marker" "$backup" "$result_dir/failure-cleanup.txt"
    fi
    systemctl stop "$emergency_unit.timer" "$emergency_unit.service" "$crash_unit.service" >/dev/null 2>&1
    if nft list table inet "$third_party" >/dev/null 2>&1; then
        nft delete table inet "$third_party" >/dev/null 2>&1
    fi
    rm -f "$dropin"
    rmdir "$dropin_dir" >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1
    systemctl restart nftfw-rollback.timer >/dev/null 2>&1
    (( daemon_was_active == 1 )) && systemctl restart nftfwd.service >/dev/null 2>&1
    (( web_was_active == 1 )) && systemctl restart nftfw-web.service >/dev/null 2>&1
    rm -f "$config_path"
    if [[ "$state_dir" == /var/lib/nftfw/host-acceptance-* ]]; then rm -rf "$state_dir"; fi
    if [[ "$lab_tmp" == /run/nftfw-host-acceptance.* ]]; then rm -rf "$lab_tmp"; fi
    (( armed == 1 && success == 0 )) && echo "HOST EMERGENCY CLEANUP: EXECUTED"
    exit "$rc"
}
trap cleanup EXIT

if owned_present; then
    echo "BLOCKED: pre-existing NFT Firewall-owned host tables found"
    exit 77
fi
if [[ -e "$dropin" ]]; then
    echo "BLOCKED: host acceptance rollback override already exists"
    exit 77
fi

# Prove the independent timer against hook-free fixtures before installing any
# base chain on the host. The unrelated table must survive.
nft -f - <<NFT
table inet nftfw_filter {
    chain proof {
        comment "nftfw:rollback-proof"
    }
}
table inet $third_party {
    chain marker {
        comment "third-party-preserve"
    }
}
NFT
proof_unit="nftfw-host-proof-$run_id"
proof_result="$result_dir/emergency-proof.txt"
systemd-run --quiet --unit="$proof_unit" --on-active=3s --timer-property=AccuracySec=100ms \
    "$helper" "$lab_tmp/proof.commit" "$backup" "$proof_result"
systemctl is-active --quiet "$proof_unit.timer" || { echo "FAIL: emergency proof timer was not active"; exit 1; }
for _ in $(seq 1 100); do
    ! nft list table inet nftfw_filter >/dev/null 2>&1 && break
    sleep 0.1
done
! nft list table inet nftfw_filter >/dev/null 2>&1 || { echo "FAIL: emergency proof did not remove the owned table"; exit 1; }
nft list table inet "$third_party" >/dev/null 2>&1 || { echo "FAIL: emergency proof removed an unrelated table"; exit 1; }
grep -Fx "EMERGENCY ROLLBACK: PASS" "$proof_result" >/dev/null || { echo "FAIL: emergency proof result missing"; exit 1; }
echo "INDEPENDENT EMERGENCY ROLLBACK PROOF: PASS"
echo "UNRELATED TABLE PRESERVATION PROOF: PASS"

mapfile -t ssh_peers < <(ss -Htn4 state established '( sport = :22 )' | awk '{print $NF}' | sed -E 's/:[0-9]+$//' | sort -u)
(( ${#ssh_peers[@]} > 0 )) || { echo "BLOCKED: no established IPv4 SSH management connection found"; exit 77; }
python3 - "${ssh_peers[@]}" <<'PY'
import ipaddress
import sys
for value in sys.argv[1:]:
    if ipaddress.ip_address(value).version != 4:
        raise SystemExit(1)
PY
admin_cidrs=$(jq -cn --args '$ARGS.positional | map(. + "/32")' "${ssh_peers[@]}")
uplink=$(ip -j route show default | jq -r '[.[] | select(.dst=="default") | .dev] | unique | if length==1 then .[0] else empty end')
[[ "$uplink" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || { echo "BLOCKED: host does not have exactly one safe IPv4 uplink"; exit 77; }

install -d -o root -g root -m 0700 "$state_dir"
install -o root -g root -m 0600 /dev/null "$config_path"
cat >"$config_path" <<TOML
[system]
ipv6_mode = "disabled"
strict_vpn = true

[[interfaces]]
name = "$uplink"
role = "uplink"
provenance_id = 1

[[interfaces]]
name = "wg-host-test"
role = "vpn"
provenance_id = 2

[[zones]]
name = "administration"
networks = $admin_cidrs

[[services]]
name = "ssh-management"
protocol = "tcp"
ports = [22]

[[services]]
name = "icmp-probe"
protocol = "icmp"
ports = []

[[services]]
name = "https-probe"
protocol = "tcp"
ports = [443]

[[policies]]
name = "declared-ssh-management"
from = "administration"
to = "host"
service = "ssh-management"
action = "allow"

[[policies]]
name = "host-probe-through-vpn"
from = "host"
to = "any"
service = "icmp-probe"
action = "allow"

[[policies]]
name = "host-https-through-vpn"
from = "host"
to = "any"
service = "https-probe"
action = "allow"

[wireguard]
interface = "wg-host-test"
endpoint_port = 51820
fwmark = "0xca6c"
bootstrap_ips = []
bootstrap_ips_v6 = []
keep_recent = 2
tcp_mss = 1360

[runtime]
max_block_claims = 100000
max_set_members = 65536
safe_apply_timeout_seconds = 30

[state]
directory = "$state_dir"
database = "$state_db"
provenance_ledger = "$provenance_ledger"

[integrations]
docker_enabled = false
threat_feed = false
geoip = false
notifications = false
TOML
chmod 0600 "$config_path"
"$nftfw" config validate "$config_path" >/dev/null

systemctl stop nftfwd.service
mkdir -p "$dropin_dir"
cat >"$dropin" <<EOF_DROPIN
[Service]
ExecStart=
ExecStart=/usr/lib/nftfw/nftfwd --rollback-expired --state-dir $state_dir
EOF_DROPIN
chmod 0600 "$dropin"
systemctl daemon-reload
systemctl restart nftfw-rollback.timer
systemctl is-enabled --quiet nftfw-rollback.timer || { echo "FAIL: product rollback timer is not enabled"; exit 1; }
systemctl is-active --quiet nftfw-rollback.timer || { echo "FAIL: product rollback timer is not active"; exit 1; }

systemd-run --quiet --unit="$emergency_unit" --on-active=180s --timer-property=AccuracySec=1s \
    "$helper" "$marker" "$backup" "$emergency_result"
systemctl is-active --quiet "$emergency_unit.timer" || { echo "FAIL: host emergency rollback timer is not active"; exit 1; }
armed=1
echo "HOST EMERGENCY ROLLBACK ARMED: PASS"

local_cli=(env NFTFW_CONFIG="$config_path" NFTFW_CONTROL_SOCKET="$lab_tmp/missing-control.sock" NFTFW_LOCAL=1 "$nftfw")
"${local_cli[@]}" plan >/dev/null
echo "HOST CANDIDATE NFT CHECK: PASS"
"${local_cli[@]}" apply --safe >/dev/null
first_generation=$(sqlite3 "$state_db" "SELECT id FROM generations WHERE status='applied' ORDER BY id DESC LIMIT 1")
[[ "$first_generation" =~ ^[0-9]+$ ]] || { echo "FAIL: safe generation was not persisted as applied"; exit 1; }
nft list chain inet nftfw_filter input | grep -F 'nftfw-policy:declared-ssh-management' >/dev/null
(( $(ss -Htn4 state established '( sport = :22 )' | wc -l) > 0 )) || { echo "FAIL: SSH management connection disappeared"; exit 1; }
echo "DECLARED SSH MANAGEMENT PATH RETAINED: PASS"

capture4="$lab_tmp/physical-v4.capture"
timeout 6 tcpdump -qn -i "$uplink" -c 1 'dst host 1.1.1.1 and (icmp or tcp dst port 443)' >"$capture4" 2>&1 &
capture4_pid=$!
capture6="$lab_tmp/physical-v6.capture"
timeout 6 tcpdump -qn -i "$uplink" -c 1 'ip6 and dst host 2606:4700:4700::1111' >"$capture6" 2>&1 &
capture6_pid=$!
sleep 0.3
if ping -c 1 -W 1 1.1.1 >/dev/null 2>&1; then echo "FAIL: IPv4 host traffic escaped the absent VPN"; exit 1; fi
if curl -4kfsS --interface "$uplink" --connect-timeout 2 --max-time 3 https://1.1.1.1/ >/dev/null 2>&1; then echo "FAIL: IPv4 TCP escaped the absent VPN"; exit 1; fi
if ping -6 -c 1 -W 1 2606:4700:4700::1111 >/dev/null 2>&1; then echo "FAIL: IPv6 host traffic escaped disabled mode"; exit 1; fi
set +e
wait "$capture4_pid"; capture4_rc=$?
wait "$capture6_pid"; capture6_rc=$?
set -e
[[ $capture4_rc -eq 124 ]] || { echo "FAIL: physical IPv4 capture observed synthetic leak traffic"; exit 1; }
[[ $capture6_rc -eq 124 ]] || { echo "FAIL: physical IPv6 capture observed synthetic leak traffic"; exit 1; }
echo "HOST IPV4 LEAKED INTERNET PACKETS: 0"
echo "HOST IPV6 LEAKED INTERNET PACKETS: 0"

"${local_cli[@]}" commit "$first_generation" >/dev/null
"${local_cli[@]}" rollback "$first_generation" >/dev/null
! owned_present || { echo "FAIL: explicit rollback left owned host tables"; exit 1; }
nft list table inet "$third_party" >/dev/null 2>&1 || { echo "FAIL: explicit rollback removed unrelated table"; exit 1; }
echo "HOST SAFE APPLY COMMIT: PASS"
echo "HOST EXPLICIT ROLLBACK: PASS"

"${local_cli[@]}" apply --safe >/dev/null
second_generation=$(sqlite3 "$state_db" "SELECT id FROM generations WHERE status='applied' ORDER BY id DESC LIMIT 1")
[[ "$second_generation" =~ ^[0-9]+$ ]] || { echo "FAIL: timeout candidate was not persisted"; exit 1; }
systemd-run --quiet --unit="$crash_unit" --property=Type=simple /usr/lib/nftfw/nftfwd \
    --config "$config_path" --status-socket "$lab_tmp/crash-status.sock" --control-socket "$lab_tmp/crash-control.sock"
for _ in $(seq 1 50); do systemctl is-active --quiet "$crash_unit.service" && break; sleep 0.1; done
systemctl is-active --quiet "$crash_unit.service" || { echo "FAIL: crash-test daemon did not start"; exit 1; }
systemctl kill --kill-who=all --signal=SIGKILL "$crash_unit.service"
echo "HOST DAEMON SIGKILL AFTER APPLY: PASS"

for _ in $(seq 1 80); do
    if ! owned_present && [[ $(sqlite3 "$state_db" "SELECT status FROM generations WHERE id=$second_generation") == rolled_back ]]; then
        break
    fi
    sleep 1
done
! owned_present || { echo "FAIL: independent timeout rollback left owned host tables"; exit 1; }
[[ $(sqlite3 "$state_db" "SELECT status FROM generations WHERE id=$second_generation") == rolled_back ]] || { echo "FAIL: timeout generation was not marked rolled_back"; exit 1; }
nft list table inet "$third_party" >/dev/null 2>&1 || { echo "FAIL: timeout rollback removed unrelated table"; exit 1; }
(( $(ss -Htn4 state established '( sport = :22 )' | wc -l) > 0 )) || { echo "FAIL: SSH management connection disappeared after rollback"; exit 1; }
echo "HOST TIMEOUT ROLLBACK AFTER DAEMON CRASH: PASS"

touch "$marker"
chmod 0600 "$marker"
systemctl stop "$emergency_unit.timer" >/dev/null 2>&1
success=1
echo "HOST SAFE-APPLY ACCEPTANCE: PASS"
