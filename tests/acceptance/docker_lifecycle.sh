#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "BLOCKED: Docker acceptance requires root"; exit 77; fi
for tool in docker ip jq nft sha256sum; do command -v "$tool" >/dev/null || { echo "BLOCKED: missing $tool"; exit 77; }; done
systemctl is-active --quiet docker.service || { echo "BLOCKED: Docker service is inactive"; exit 77; }

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
case "$(uname -m)" in
    x86_64) build_arch=amd64 ;;
    aarch64|arm64) build_arch=arm64 ;;
    *) echo "BLOCKED: unsupported architecture"; exit 77 ;;
esac
nftfw="$root_dir/dist/nftfw-linux-$build_arch"
[[ -x "$nftfw" ]] || { echo "BLOCKED: release CLI binary missing"; exit 77; }
uplink=$(ip -j route show default | jq -r '[.[] | select(.dst=="default") | .dev] | unique | if length==1 then .[0] else empty end')
[[ "$uplink" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || { echo "BLOCKED: no unique IPv4 uplink"; exit 77; }

run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
network="nftfw-accept-$run_id"
container="nftfw-accept-$run_id"
bridge_interface=$(printf 'nfa%08x' "$$")
config="/etc/nftfw/docker-acceptance-$run_id.toml"
state_dir="/var/lib/nftfw/docker-acceptance-$run_id"
state_db="$state_dir/generation-state/state.db"
provenance_ledger="$state_dir/provenance-ledger.db"
lab_tmp=$(mktemp -d "/run/nftfw-docker-acceptance.${run_id}.XXXXXX")

cleanup() {
    set +e
    docker rm -f "$container" >/dev/null 2>&1
    docker network rm "$network" >/dev/null 2>&1
    rm -f "$config"
    if [[ "$state_dir" == /var/lib/nftfw/docker-acceptance-* ]]; then rm -rf "$state_dir"; fi
    if [[ "$lab_tmp" == /run/nftfw-docker-acceptance.* ]]; then rm -rf "$lab_tmp"; fi
}
trap cleanup EXIT

[[ -f /etc/docker/daemon.json && ! -L /etc/docker/daemon.json ]] || { echo "FAIL: Docker daemon config is unsafe"; exit 1; }
[[ $(stat -c '%a:%u:%g' /etc/docker/daemon.json) == 600:0:0 ]] || { echo "FAIL: Docker daemon config permissions are unsafe"; exit 1; }
jq -e '.iptables == false and .ip6tables == false and ."ip-forward" == false and ."ip-masq" == false and ."userland-proxy" == false' /etc/docker/daemon.json >/dev/null || { echo "FAIL: Docker firewall/routing/proxy ownership is enabled"; exit 1; }

mapfile -t existing_bridges < <(docker network ls --filter driver=bridge --format '{{.Name}}')
if (( ${#existing_bridges[@]} != 1 )) || [[ ${existing_bridges[0]} != bridge ]]; then
    echo "BLOCKED: Docker lifecycle acceptance requires only the default bridge before the test"
    exit 77
fi
default_network=$(docker network inspect bridge)
default_bridge=$(jq -er '.[0].Options["com.docker.network.bridge.name"]' <<<"$default_network")
default_subnet=$(jq -er '.[0].IPAM.Config | select(length == 1) | .[0].Subnet' <<<"$default_network")
default_gateway=$(jq -er '.[0].IPAM.Config | select(length == 1) | .[0].Gateway' <<<"$default_network")
[[ "$default_bridge" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || { echo "BLOCKED: default Docker bridge name is not safely declarable"; exit 77; }

docker image inspect alpine:3.22 >/dev/null 2>&1 || docker pull --quiet alpine:3.22 >/dev/null
nft_before=$(nft -j list ruleset | jq -S '.nftables | map(select(.metainfo? | not))' | sha256sum | awk '{print $1}')
docker network create --driver bridge --opt "com.docker.network.bridge.name=$bridge_interface" \
    --subnet 172.30.55.0/24 --gateway 172.30.55.1 "$network" >/dev/null
docker run -d --name "$container" --network "$network" alpine:3.22 sleep 600 >/dev/null
first_ip=$(docker inspect --format "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}" "$container")
[[ "$first_ip" =~ ^172\.30\.55\.[0-9]+$ ]] || { echo "FAIL: Docker container did not receive the expected address"; exit 1; }

install -d -o root -g root -m 0700 "$state_dir"
install -o root -g root -m 0600 /dev/null "$config"
write_config() {
    local test_subnet=$1
    local test_gateway=$2
    cat >"$config" <<TOML
[system]
ipv6_mode = "disabled"
strict_vpn = true
[[interfaces]]
name = "$uplink"
role = "uplink"
provenance_id = 1
[[interfaces]]
name = "wg-docker-test"
role = "vpn"
provenance_id = 2
[[interfaces]]
name = "$default_bridge"
role = "container"
cidrs = ["$default_subnet"]
provenance_id = 3
[[interfaces]]
name = "$bridge_interface"
role = "container"
cidrs = ["$test_subnet"]
provenance_id = 4
[wireguard]
interface = "wg-docker-test"
endpoint_port = 51820
fwmark = "0xca6c"
[state]
directory = "$state_dir"
database = "$state_db"
provenance_ledger = "$provenance_ledger"
[integrations]
docker_enabled = true
threat_feed = false
geoip = false
notifications = false
[[docker_networks]]
name = "bridge"
driver = "bridge"
bridge_interface = "$default_bridge"
subnets = ["$default_subnet"]
gateways = ["$default_gateway"]
[[docker_networks]]
name = "$network"
driver = "bridge"
bridge_interface = "$bridge_interface"
subnets = ["$test_subnet"]
gateways = ["$test_gateway"]
TOML
}
write_config 172.30.55.0/24 172.30.55.1
chmod 0600 "$config"
legacy_static_config_hash=$(sha256sum "$config" | awk '{print $1}')
if grep -Eq '^[[:space:]]*(dynamic_bridge|provenance_name)[[:space:]]*=' "$config"; then
    echo "FAIL: v2.0.3 compatibility fixture unexpectedly uses managed Docker provenance"
    exit 1
fi
local_cli=(env NFTFW_CONFIG="$config" NFTFW_CONTROL_SOCKET="$lab_tmp/missing.sock" NFTFW_LOCAL=1 "$nftfw")
"${local_cli[@]}" plan --json --show-nft >"$lab_tmp/plan-first.json"
jq -er '.nft_transaction' "$lab_tmp/plan-first.json" | grep -F '172.30.55.0/24' >/dev/null || { echo "FAIL: V2 did not observe the Docker network"; exit 1; }
[[ $(sha256sum "$config" | awk '{print $1}') == "$legacy_static_config_hash" ]] || {
    echo "FAIL: planning rewrote the legacy static Docker configuration"
    exit 1
}
echo "DOCKER LEGACY STATIC PROVENANCE COMPATIBILITY: PASS"
echo "DOCKER NETWORK OBSERVATION: PASS"

docker restart "$container" >/dev/null
docker inspect --format '{{.State.Running}}' "$container" | grep -Fx true >/dev/null
"${local_cli[@]}" plan --json --show-nft >"$lab_tmp/plan-restart.json"
jq -er '.nft_transaction' "$lab_tmp/plan-restart.json" | grep -F '172.30.55.0/24' >/dev/null
echo "DOCKER CONTAINER RESTART OBSERVATION: PASS"

docker network disconnect "$network" "$container"
docker network connect --ip 172.30.55.200 "$network" "$container"
changed_ip=$(docker inspect --format "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}" "$container")
[[ "$changed_ip" == 172.30.55.200 && "$changed_ip" != "$first_ip" ]] || { echo "FAIL: Docker address change was not realized"; exit 1; }
"${local_cli[@]}" plan --json --show-nft >"$lab_tmp/plan-address-change.json"
jq -er '.nft_transaction' "$lab_tmp/plan-address-change.json" | grep -F '172.30.55.0/24' >/dev/null
echo "DOCKER CONTAINER ADDRESS CHANGE: PASS"

docker rm -f "$container" >/dev/null
docker network rm "$network" >/dev/null
docker network create --driver bridge --opt "com.docker.network.bridge.name=$bridge_interface" \
    --subnet 172.30.55.0/24 --gateway 172.30.55.1 "$network" >/dev/null
docker run -d --name "$container" --network "$network" alpine:3.22 sleep 600 >/dev/null
"${local_cli[@]}" plan --json --show-nft >"$lab_tmp/plan-recreated-stable.json"
jq -er '.nft_transaction' "$lab_tmp/plan-recreated-stable.json" | grep -F '172.30.55.0/24' >/dev/null || { echo "FAIL: stable Docker network recreation was not observed"; exit 1; }
echo "DOCKER NETWORK STABLE-TUPLE RECREATE: PASS"

docker rm -f "$container" >/dev/null
docker network rm "$network" >/dev/null
docker network create --driver bridge --opt "com.docker.network.bridge.name=$bridge_interface" \
    --subnet 172.30.56.0/24 --gateway 172.30.56.1 "$network" >/dev/null
docker run -d --name "$container" --network "$network" alpine:3.22 sleep 600 >/dev/null
if "${local_cli[@]}" plan --json --show-nft >"$lab_tmp/plan-drifted.json" 2>"$lab_tmp/plan-drifted.err"; then
    echo "FAIL: unapproved Docker subnet drift was accepted"
    exit 1
fi
echo "DOCKER NETWORK UNAPPROVED TUPLE DRIFT: REFUSED"

write_config 172.30.56.0/24 172.30.56.1
"${local_cli[@]}" plan --json --show-nft >"$lab_tmp/plan-approved-recreate.json"
transaction=$(jq -er '.nft_transaction' "$lab_tmp/plan-approved-recreate.json")
grep -F '172.30.56.0/24' <<<"$transaction" >/dev/null || { echo "FAIL: explicitly approved Docker tuple was not observed"; exit 1; }
if grep -F '172.30.55.0/24' <<<"$transaction" >/dev/null; then echo "FAIL: replaced Docker tuple remained effective"; exit 1; fi
echo "DOCKER NETWORK EXPLICIT TUPLE UPDATE: PASS"

nft_after=$(nft -j list ruleset | jq -S '.nftables | map(select(.metainfo? | not))' | sha256sum | awk '{print $1}')
[[ "$nft_before" == "$nft_after" ]] || { echo "FAIL: Docker lifecycle test changed nftables"; exit 1; }
echo "DOCKER FIREWALL OWNERSHIP PRESERVED: PASS"
echo "DOCKER LIFECYCLE ACCEPTANCE: PASS"
