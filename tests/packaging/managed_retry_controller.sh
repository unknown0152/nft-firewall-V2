#!/usr/bin/env bash
set -Eeuo pipefail
umask 0077

# Protected host-side controller for managed_retry_disposable.sh. The caller
# supplies the private Stage E-R root and private release-disposition package;
# neither artifact is deployable or publishable evidence.

if (( $# < 2 || $# > 3 )); then
    echo "usage: managed_retry_controller.sh R2_ROOT PRIVATE_AMD64_DEB [RUN_ID]" >&2
    exit 64
fi

readonly r2_root=$1
readonly private_deb=$2
readonly run_id=${3:-W1}
readonly harness=$r2_root/harness
readonly overlays=$r2_root/overlays
readonly raw=$r2_root/evidence-raw
readonly sanitized=$r2_root/evidence-sanitized
readonly provider=$run_id-retry-provider
readonly guest=$run_id-retry-client
readonly guest_script=/root/managed-retry-disposable.sh
readonly prerequisite_script=/root/r2-guest-prerequisites-v1.sh
readonly provider_script=/root/r2-managed-provider-guest-v1.sh
readonly provider_server=/root/r2-managed-provider-server-v1.py

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    echo "BLOCKED: Amendment W controller requires host root"
    exit 77
}
[[ $run_id =~ ^W[1-9][0-9]{0,2}$ ]]
[[ $r2_root == /* && $r2_root != / && -d $r2_root && ! -L $r2_root ]]
[[ -f $private_deb && ! -L $private_deb ]]
for tool in jq pgrep python3 qemu-img scp sha256sum ss ssh timeout; do
    command -v "$tool" >/dev/null || {
        echo "BLOCKED: missing Amendment W controller prerequisite"
        exit 77
    }
done
for input in \
    "$harness/managed_retry_disposable.sh" \
    "$harness/r2-guest-prerequisites-v1.sh" \
    "$harness/r2-managed-provider-guest-v1.sh" \
    "$harness/r2-managed-provider-server-v1.py"; do
    [[ -f $input && ! -L $input ]]
done
[[ ! -e $overlays/$provider.qcow2 && ! -e $overlays/$guest.qcow2 ]]
private_deb_sha=$(sha256sum "$private_deb" | awk '{print $1}')
readonly private_deb_sha
[[ $private_deb_sha =~ ^[0-9a-f]{64}$ ]]

provider_public_tmp=$(mktemp /run/nftfw-w-provider-public.XXXXXX)
client_public_tmp=$(mktemp /run/nftfw-w-client-public.XXXXXX)
chmod 0600 "$provider_public_tmp" "$client_public_tmp"

stop_if_running() {
    local vm=$1 provider_mode=${2:-false}
    if [[ -f $overlays/$vm.pid && ! -L $overlays/$vm.pid ]]; then
        if [[ $provider_mode == true ]]; then
            "$harness/nftfw-r2-vm-stop-provider-v1.sh" "$vm" graceful >/dev/null 2>&1 || true
        else
            "$harness/nftfw-r2-vm-stop.sh" "$vm" graceful >/dev/null 2>&1 || true
        fi
    fi
}

cleanup() {
    local rc=$?
    set +e
    stop_if_running "$guest"
    stop_if_running "$provider" true
    rm -f -- "$provider_public_tmp" "$client_public_tmp"
    exit "$rc"
}
trap cleanup EXIT

copy_to_vm() {
    "$harness/nftfw-r2-scp.sh" "$1" "$2" "$3"
}

run_vm() {
    local vm=$1
    shift
    "$harness/nftfw-r2-ssh.sh" "$vm" "$@"
}

run_vm_qga() {
    local vm=$1
    shift
    local ready=false
    for _ in $(seq 1 120); do
        if "$harness/nftfw-r2-qga.py" "$overlays/$vm.qga" ping >/dev/null 2>&1; then
            ready=true
            break
        fi
        sleep 1
    done
    [[ $ready == true ]] || {
        echo "FAIL: disposable guest agent did not become ready"
        return 1
    }
    timeout 1200 "$harness/nftfw-r2-qga.py" "$overlays/$vm.qga" exec "$@"
}

assert_overlay() {
    runuser -u nftfw-r2 -- qemu-img check "$overlays/$1.qcow2" >/dev/null
}

[[ $(pgrep -u nftfw-r2 -fc qemu-system-x86_64 2>/dev/null || true) -eq 0 ]]

"$harness/nftfw-r2-vm-create-overlay.sh" "$provider" >"$raw/$provider-create.log" 2>&1
"$harness/nftfw-r2-vm-start-provider-v1.sh" "$provider" >"$raw/$provider-start.log" 2>&1
copy_to_vm "$provider" "$harness/r2-managed-provider-guest-v1.sh" "$provider_script"
copy_to_vm "$provider" "$harness/r2-managed-provider-server-v1.py" "$provider_server"
run_vm "$provider" chmod 0700 "$provider_script" "$provider_server"
run_vm "$provider" "$provider_script" prepare >"$raw/$provider-prepare.log" 2>&1
run_vm "$provider" cat /run/nftfw-r2-managed-provider/public.key >"$provider_public_tmp"
[[ $(stat -c %s "$provider_public_tmp") -ge 40 && $(stat -c %s "$provider_public_tmp") -le 64 ]]
provider_port=$(<"$overlays/$provider.provider-udp-port")
[[ $provider_port =~ ^[0-9]+$ && $provider_port -ge 1024 && $provider_port -le 65535 ]]

"$harness/nftfw-r2-vm-create-overlay.sh" "$guest" >"$raw/$guest-create.log" 2>&1
"$harness/nftfw-r2-vm-start.sh" "$guest" >"$raw/$guest-start.log" 2>&1
copy_to_vm "$guest" "$private_deb" /root/private-2.1.0.deb
copy_to_vm "$guest" "$harness/managed_retry_disposable.sh" "$guest_script"
copy_to_vm "$guest" "$harness/r2-guest-prerequisites-v1.sh" "$prerequisite_script"
copy_to_vm "$guest" "$provider_public_tmp" /root/provider-public.key
run_vm "$guest" chmod 0700 "$guest_script" "$prerequisite_script"
run_vm "$guest" "$prerequisite_script" >"$raw/$guest-prerequisite.log" 2>&1
run_vm "$guest" "$guest_script" prepare /root/private-2.1.0.deb >"$raw/$guest-prepare.log" 2>&1
run_vm "$guest" cat /opt/nftfw-amendment-w/client-public.key >"$client_public_tmp"
[[ $(stat -c %s "$client_public_tmp") -ge 40 && $(stat -c %s "$client_public_tmp") -le 64 ]]
copy_to_vm "$provider" "$client_public_tmp" /run/nftfw-r2-managed-provider/client-public.key
run_vm "$provider" "$provider_script" configure \
    /run/nftfw-r2-managed-provider/client-public.key >"$raw/$provider-configure.log" 2>&1

run_vm "$guest" "$guest_script" configure-unreachable /root/private-2.1.0.deb \
    >"$raw/$guest-configure-unreachable.log" 2>&1
run_vm "$guest" "$guest_script" dry-run /root/private-2.1.0.deb \
    >"$raw/$guest-dry-initial.log" 2>&1
run_vm_qga "$guest" "$guest_script" process-death /root/private-2.1.0.deb unused unused 1 \
    >"$raw/$guest-process-death-1.log" 2>&1
run_vm "$guest" "$guest_script" dry-run /root/private-2.1.0.deb \
    >"$raw/$guest-dry-after-1.log" 2>&1
run_vm_qga "$guest" "$guest_script" process-death /root/private-2.1.0.deb unused unused 2 \
    >"$raw/$guest-process-death-2.log" 2>&1
run_vm "$guest" "$guest_script" dry-run /root/private-2.1.0.deb \
    >"$raw/$guest-dry-after-2.log" 2>&1
run_vm "$guest" "$guest_script" configure /root/private-2.1.0.deb \
    /root/provider-public.key "$provider_port" >"$raw/$guest-configure-reachable.log" 2>&1
run_vm_qga "$guest" "$guest_script" success /root/private-2.1.0.deb \
    >"$raw/$guest-success.log" 2>&1
run_vm "$guest" "$guest_script" idempotent /root/private-2.1.0.deb \
    >"$raw/$guest-idempotent.log" 2>&1
run_vm "$guest" "$guest_script" tunnel-loss /root/private-2.1.0.deb \
    >"$raw/$guest-tunnel-loss.log" 2>&1
for reboot_index in 1 2; do
    "$harness/nftfw-r2-vm-stop.sh" "$guest" graceful \
        >"$raw/$guest-reboot-$reboot_index-stop.log" 2>&1
    "$harness/nftfw-r2-vm-start.sh" "$guest" \
        >"$raw/$guest-reboot-$reboot_index-start.log" 2>&1
    run_vm "$guest" "$guest_script" verify-boot /root/private-2.1.0.deb \
        >"$raw/$guest-reboot-$reboot_index-verify.log" 2>&1
done
run_vm "$provider" "$provider_script" status >"$raw/$provider-status.log" 2>&1

"$harness/nftfw-r2-vm-stop.sh" "$guest" graceful >"$raw/$guest-stop.log" 2>&1
assert_overlay "$guest"
run_vm "$provider" "$provider_script" cleanup >"$raw/$provider-cleanup.log" 2>&1
"$harness/nftfw-r2-vm-stop-provider-v1.sh" "$provider" graceful >"$raw/$provider-stop.log" 2>&1
assert_overlay "$provider"

qemu_count=$(pgrep -u nftfw-r2 -fc qemu-system-x86_64 2>/dev/null || true)
listener_count=$(ss -Hlnptu 2>/dev/null | awk '/qemu-system-x86_64/ {count++} END {print count+0}')
[[ $qemu_count -eq 0 && $listener_count -eq 0 ]]

record=$sanitized/STAGE_ER_AMENDMENT_W_MANAGED_RETRY_$run_id.json
[[ ! -e $record && ! -L $record ]]
jq -n --arg package "$private_deb_sha" --arg run "$run_id" '{
    schema:"nftfw.stage-er-amendment-w-managed-retry.v1",status:"PASS",target_version:"2.1.0",
    run_id:$run,private_package_sha256:$package,provider:"synthetic-disposable-wireguard",
    coherent_docker_baseline:true,docker_firewall_ownership:false,
    docker_restart_trigger:"userland-proxy",dry_run_nonmutating:true,
    process_death_phase:"validate",failed_retries:2,exact_operator_rollback:true,
    retained_audit_state_monotonic:true,stable_provenance_reused:true,
    durable_terminal_history:true,eventual_success_generation:3,
    unrelated_nftables_unchanged:true,complete_managed_transaction:true,
    host_and_container_vpn_dataplane:true,idempotent_no_docker_restart:true,
    tunnel_loss_physical_payload_packets:0,docker_restart_during_tunnel_loss_leak:false,
    tunnel_recovery:true,consecutive_managed_boots:2,
    qemu_processes_after:0,qemu_listeners_after:0,
    live_host_product_state_changed:false,stage:"E-R_SOURCE_ONLY",r2_authorized:false,
    publication_authorized:false,deployment_authorized:false
}' >"$record"
chmod 0600 "$record"
echo "STAGE_ER_AMENDMENT_W_MANAGED_RETRY_CONTROLLER_PASS"
