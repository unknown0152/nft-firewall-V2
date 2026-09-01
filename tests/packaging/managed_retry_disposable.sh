#!/usr/bin/env bash
set -Eeuo pipefail
umask 0077

# This script is copied only into a disposable Debian guest by the protected
# Stage E-R harness. It deliberately exercises real Docker, nftables, systemd,
# routing, and WireGuard state without touching the build host.

readonly action=${1:?action required}
readonly private_deb=${2:-}
readonly provider_public_input=${3:-}
readonly provider_port=${4:-}
readonly expected_generation=${5:-}
readonly work_root=/opt/nftfw-amendment-w
readonly profile=/run/nftfw-amendment-w-provider.conf
readonly client_private=$work_root/client-private.key
readonly client_public=$work_root/client-public.key
readonly network_a=amendmentw-a
readonly network_b=amendmentw-b
readonly unrelated_table=amendment_w_unrelated

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    echo "BLOCKED: Amendment W disposable suite requires guest root"
    exit 77
}

require_tools() {
    local tool
    for tool in busybox curl docker dpkg find ip ip6tables iptables jq ldd nft \
        sha256sum sqlite3 stat sysctl systemctl tar tcpdump timeout wg; do
        command -v "$tool" >/dev/null || {
            echo "BLOCKED: missing Amendment W disposable prerequisite"
            exit 77
        }
    done
}

ensure_test_image() {
    docker image inspect alpine:3.22 >/dev/null 2>&1 && return 0
    local rootfs=$work_root/local-image-rootfs
    local archive=$work_root/local-image-rootfs.tar
    local busybox target library
    busybox=$(command -v busybox)
    [[ -x $busybox ]]
    install -d -o root -g root -m 0700 "$rootfs/usr/bin"
    install -o root -g root -m 0755 "$busybox" "$rootfs/usr/bin/busybox"
    while IFS= read -r applet; do
        [[ $applet != /* && $applet != *..* ]] || continue
        target="$rootfs/$applet"
        [[ -e $target || -L $target ]] && continue
        install -d -o root -g root -m 0755 "${target%/*}"
        ln -s /usr/bin/busybox "$target"
    done < <("$busybox" --list-full)
    while IFS= read -r library; do
        [[ -f $library ]]
        install -D -o root -g root -m 0755 "$library" "$rootfs$library"
    done < <(ldd "$busybox" | awk '/=> \// {print $3} $1 ~ /^\// {print $1}')
    tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
        -C "$rootfs" -cf "$archive" .
    docker import "$archive" alpine:3.22 >/dev/null
    docker image inspect alpine:3.22 >/dev/null
}

delete_legacy_tables() {
    local family table
    for family in ip ip6; do
        for table in filter nat mangle raw security; do
            if [[ $family == ip ]]; then
                iptables -t "$table" -F 2>/dev/null || true
                iptables -t "$table" -X 2>/dev/null || true
            else
                ip6tables -t "$table" -F 2>/dev/null || true
                ip6tables -t "$table" -X 2>/dev/null || true
            fi
            nft delete table "$family" "$table" >/dev/null 2>&1 || true
        done
    done
    for table in nftfw_filter nftfw_nat nftfw_filter6 nftfw_setup_guard; do
        nft delete table inet "$table" >/dev/null 2>&1 || true
        nft delete table ip "$table" >/dev/null 2>&1 || true
        nft delete table ip6 "$table" >/dev/null 2>&1 || true
    done
}

file_record() {
    local path=$1
    if [[ -f $path && ! -L $path ]]; then
        printf 'FILE %s %s %s\n' "$path" "$(stat -c '%a:%U:%G:%s:%h' "$path")" \
            "$(sha256sum "$path" | awk '{print $1}')"
    elif [[ -d $path && ! -L $path ]]; then
        printf 'DIR %s %s\n' "$path" "$(stat -c '%a:%U:%G:%h' "$path")"
    elif [[ -L $path ]]; then
        printf 'LINK %s %s\n' "$path" "$(readlink "$path")"
    else
        printf 'ABSENT %s\n' "$path"
    fi
}

structural_nft() {
    nft -j list ruleset | jq -S '
        walk(if type == "object" then del(.handle, .packets, .bytes) else . end)
        | .nftables | map(select(.metainfo? | not))
    ' | sha256sum | awk '{print $1}'
}

unrelated_nft() {
    if ! nft -j list table inet "$unrelated_table" >/dev/null 2>&1; then
        echo ABSENT
        return
    fi
    nft -j list table inet "$unrelated_table" | jq -S '
        walk(if type == "object" then del(.handle, .packets, .bytes) else . end)
        | .nftables | map(select(.metainfo? | not))
    ' | sha256sum | awk '{print $1}'
}

create_unrelated_nft() {
    nft -f - <<EOF
table inet $unrelated_table {
    chain sentinel {
        type filter hook input priority 250; policy accept;
    }
}
EOF
}

operator_snapshot() {
    local path physical unit
    local -a docker_network_ids
    physical=$(ip -j -4 route show default | jq -er '.[0].dev')
    [[ $physical =~ ^[A-Za-z0-9_.-]{1,15}$ ]]
    printf 'NFT %s\n' "$(structural_nft)"
    printf 'UNRELATED %s\n' "$(unrelated_nft)"
    printf 'ROUTES %s\n' "$(ip -j -4 route show table all | jq -S \
        'sort_by([.table // 0, .dst // "", .dev // "", .gateway // "", .metric // 0])' | \
        sha256sum | awk '{print $1}')"
    printf 'RULES %s\n' "$(ip -j -4 rule show | jq -S \
        'sort_by([.priority // 0, .table // 0, .from // "", .to // ""])' | \
        sha256sum | awk '{print $1}')"
    for path in \
        /etc/nftfw/intent.toml /etc/nftfw/nftfw.toml \
        /etc/nftfw/initramfs-managed-disabled-v1 \
        /etc/nftfw/initramfs-source-owner-v1 \
        /etc/wireguard/nftfw0.conf /etc/sysctl.d/90-nftfw-managed.conf \
        /etc/docker/daemon.json \
        /etc/initramfs-tools/scripts/init-top/nftfw-ipv6-early \
        /etc/initramfs-tools/scripts/init-top/udev \
        /etc/systemd/system/nftfwd.service.d/docker-access.conf \
        /etc/systemd/system/nftfwd.service.d/50-nftfw-final-early.conf \
        /etc/systemd/system/nftfw-rollback.service.d/50-nftfw-final-early.conf \
        /var/lib/nftfw/enforcement-enabled; do
        file_record "$path"
    done
    for unit in docker.service docker.socket containerd.service nftfw-vpn.service \
        nftfwd.service nftfw-web.service nftfw-early.service \
        nftfw-enforcement-ready.service nftfw-rollback.timer \
        nftfw-setup-rollback.timer nftfw-managed-rollback.timer; do
        printf 'UNIT %s %s %s\n' "$unit" \
            "$(systemctl is-active "$unit" 2>/dev/null || true)" \
            "$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    done
    printf 'SYSCTL ip_forward=%s all_forwarding=%s default_disable=%s lo_disable=%s physical_disable=%s\n' \
        "$(sysctl -n net.ipv4.ip_forward)" \
        "$(sysctl -n net.ipv6.conf.all.forwarding)" \
        "$(sysctl -n net.ipv6.conf.default.disable_ipv6)" \
        "$(sysctl -n net.ipv6.conf.lo.disable_ipv6)" \
        "$(sysctl -n "net.ipv6.conf.$physical.disable_ipv6")"
    mapfile -t docker_network_ids < <(docker network ls -q)
    docker network inspect "${docker_network_ids[@]}" |
        # Docker may replace its opaque generated network ID across a daemon
        # restart. NFTFW adopts the stable name/interface/subnet tuple, so the
        # exact rollback contract compares that complete semantic topology and
        # excludes only the ID plus volatile creation/member fields.
        jq -S 'map(del(.Id, .Created, .Peers, .Containers)) | sort_by(.Name)' |
        sha256sum | awk '{print "DOCKER_NETWORKS "$1}'
}

retained_snapshot() {
    local root=/var/lib/nftfw path
    if [[ ! -e $root ]]; then
        echo ABSENT
        return
    fi
    while IFS= read -r -d '' path; do
        case $(stat -c %F "$path") in
            directory)
                printf 'DIR %s %s\n' "${path#"$root"}" "$(stat -c '%a:%U:%G' "$path")"
                ;;
            'regular file')
                printf 'FILE %s %s %s\n' "${path#"$root"}" \
                    "$(stat -c '%a:%U:%G:%s' "$path")" \
                    "$(sha256sum "$path" | awk '{print $1}')"
                ;;
            'symbolic link')
                printf 'LINK %s %s\n' "${path#"$root"}" "$(readlink "$path")"
                ;;
            *)
                printf 'UNSAFE %s %s\n' "${path#"$root"}" "$(stat -c %F "$path")"
                ;;
        esac
    done < <(find "$root" -xdev -print0 | sort -z)
}

write_profile() {
    local peer_file=$1 port=$2
    [[ -f $peer_file && ! -L $peer_file && $port =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]]
    install -o root -g root -m 0600 /dev/null "$profile"
    {
        printf '[Interface]\nAddress = 10.240.0.2/32\nPrivateKey = %s\n\n' "$(<"$client_private")"
        printf '[Peer]\nPublicKey = %s\nEndpoint = 10.0.2.2:%s\n' "$(<"$peer_file")" "$port"
        printf 'AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 5\n'
    } >"$profile"
    chmod 0600 "$profile"
}

assert_output_redacted() {
    local output=$1 secret
    for secret in "$(<"$client_private")" "$(<"$client_public")"; do
        if grep -Fq -- "$secret" "$output"; then
            echo "FAIL: setup output disclosed key material"
            exit 1
        fi
    done
    if grep -Eq '10\.0\.2\.2:[0-9]+' "$output"; then
        echo "FAIL: setup output disclosed endpoint"
        exit 1
    fi
}

verify_history() {
    local expected=$1 entry digest embedded
    local -a entries=()
    if (( expected == 0 )); then
        [[ ! -e /var/lib/nftfw/setup/history ]]
        return
    fi
    [[ $(stat -c '%a:%U:%G' /var/lib/nftfw/setup/history) == 700:root:root ]]
    mapfile -t entries < <(find /var/lib/nftfw/setup/history -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)
    [[ ${#entries[@]} -eq expected ]]
    for entry in "${entries[@]}"; do
        [[ $entry =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.([0-9a-f]{64})\.json$ ]]
        digest=$(sha256sum "/var/lib/nftfw/setup/history/$entry" | awk '{print $1}')
        embedded=${BASH_REMATCH[1]}
        [[ $digest == "$embedded" ]]
        jq -e '.schema=="nftfw.setup-journal.v1" and .phase=="failed" and
            .status=="rolled_back" and .committed!=true' "/var/lib/nftfw/setup/history/$entry" >/dev/null
    done
}

provenance_identity() {
    sqlite3 -readonly /var/lib/nftfw/provenance-ledger.db \
        'SELECT interface_name || "|" || provenance_id || "|" || retired FROM allocations ORDER BY provenance_id,interface_name;'
}

verify_terminal_generation() {
    local generation=$1 index snapshot
    [[ $generation =~ ^[1-9][0-9]*$ ]]
    [[ $(sqlite3 -readonly /var/lib/nftfw/generation-state/state.db 'PRAGMA quick_check;') == ok ]]
    [[ $(sqlite3 -readonly /var/lib/nftfw/provenance-ledger.db 'PRAGMA quick_check;') == ok ]]
    [[ $(sqlite3 -readonly /var/lib/nftfw/generation-state/state.db \
        'SELECT COUNT(*) FROM generations;') -eq generation ]]
    [[ $(sqlite3 -readonly /var/lib/nftfw/generation-state/state.db \
        'SELECT COUNT(*) FROM generations WHERE status="rolled_back" AND previous_id IS NULL AND commit_prepared_at IS NULL;') -eq generation ]]
    [[ $(jq -r '.generation' /var/lib/nftfw/setup/journal.json) -eq generation ]]
    jq -e '.schema=="nftfw.setup-journal.v1" and .phase=="failed" and
        .status=="rolled_back" and .committed!=true and (.backup_dir|length)>0' \
        /var/lib/nftfw/setup/journal.json >/dev/null
    verify_history "$((generation - 1))"
    [[ $(find /var/lib/nftfw/setup/backups -mindepth 1 -maxdepth 1 -type d | wc -l) -eq generation ]]
    [[ $(sqlite3 -readonly /var/lib/nftfw/provenance-ledger.db \
        'SELECT COUNT(*) FROM allocations WHERE retired<>0;') -eq 0 ]]
    [[ $(sqlite3 -readonly /var/lib/nftfw/provenance-ledger.db \
        'SELECT COUNT(*) FROM allocations;') -gt 0 ]]
    provenance_identity >"$work_root/provenance-$generation.identity"
    if (( generation > 1 )); then
        cmp -s "$work_root/provenance-1.identity" "$work_root/provenance-$generation.identity"
    fi
    for index in $(seq 1 "$generation"); do
        printf -v snapshot '/var/lib/nftfw/generations/%020d.snapshot.json' "$index"
        jq -e --argjson id "$index" '.schema=="nftfw.generation-snapshot.v1" and
            .generation==$id and .previous==null and (.provenance|length)>0 and
            ([.provenance[].retired]|all(.==false))' "$snapshot" >/dev/null
        jq -Sc '.provenance|sort_by(.id)|map({name,id,retired})' "$snapshot" \
            >"$work_root/snapshot-$index.provenance"
        cmp -s "$work_root/snapshot-1.provenance" "$work_root/snapshot-$index.provenance"
    done
}

assert_exact_operator_rollback() {
    operator_snapshot >"$work_root/operator-after.snapshot"
    cmp -s "$work_root/operator-baseline.snapshot" "$work_root/operator-after.snapshot" || {
        diff -u "$work_root/operator-baseline.snapshot" "$work_root/operator-after.snapshot" || true
        echo "FAIL: operator/runtime state was not restored exactly"
        exit 1
    }
}

assert_managed_healthy() {
    local physical recent
    physical=$(ip -j -4 route show default table main | jq -er '.[0].dev')
    /usr/sbin/nftfw setup status --json >"$work_root/status.json"
    jq -e '.status=="complete" and .summary.docker_mode=="enabled"' "$work_root/status.json" >/dev/null
    [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]]
    [[ $(sysctl -n net.ipv6.conf.default.disable_ipv6) == 1 ]]
    [[ $(sysctl -n "net.ipv6.conf.$physical.disable_ipv6") == 1 ]]
    jq -e '.iptables==false and .ip6tables==false and ."ip-forward"==false and
        ."ip-masq"==false and ."userland-proxy"==false and ."log-driver"=="json-file"' \
        /etc/docker/daemon.json >/dev/null
    ip -j -4 route get 1.1.1.1 | jq -e '.[0].dev=="nftfw0"' >/dev/null
    for _ in $(seq 1 40); do
        recent=$(wg show nftfw0 latest-handshakes | awk -v now="$(date +%s)" \
            '$2 > 0 && now-$2 < 30 {n++} END {print n+0}')
        if [[ $recent -eq 1 ]] &&
            curl -4fsS --max-time 2 http://1.1.1.1:443/ 2>/dev/null | grep -Fxq R2OK; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

case "$action" in
    prepare)
        require_tools
        [[ -f $private_deb && ! -L $private_deb ]]
        [[ $(dpkg-deb -f "$private_deb" Package) == nft-firewall-v2 ]]
        [[ $(dpkg-deb -f "$private_deb" Version) == 2.1.0 ]]
        [[ $(dpkg-deb -f "$private_deb" X-NFTFW-Build-Disposition) == release ]]
        [[ ! -e $work_root && ! -e $profile ]]
        install -d -o root -g root -m 0700 "$work_root"
        systemctl disable --now nftfw-r2-outer.service >/dev/null 2>&1 || true
        nft delete table inet r2_outer >/dev/null 2>&1 || true
        systemctl stop docker.socket docker.service containerd.service >/dev/null 2>&1 || true
        delete_legacy_tables
        install -d -o root -g root -m 0700 /etc/docker
        install -o root -g root -m 0600 /dev/null /etc/docker/daemon.json
        printf '%s\n' '{"iptables":false,"ip6tables":false,"ip-forward":false,"ip-masq":false,"userland-proxy":true,"log-driver":"json-file"}' \
            >/etc/docker/daemon.json
        systemctl start containerd.service docker.service
        systemctl is-active --quiet docker.service
        docker network create --driver bridge --opt com.docker.network.bridge.name=br-amwa \
            --subnet 172.30.0.0/16 --gateway 172.30.0.1 "$network_a" >/dev/null
        docker network create --driver bridge --opt com.docker.network.bridge.name=br-amwb \
            --subnet 172.31.0.0/16 --gateway 172.31.0.1 "$network_b" >/dev/null
        ensure_test_image
        [[ -z $(docker ps -aq --no-trunc) ]]
        delete_legacy_tables
        [[ -z $(nft list tables) ]]
        dpkg --install "$private_deb" >/dev/null
        for unit in nftfwd.service nftfw-web.service nftfw-rollback.timer; do
            if systemctl is-active --quiet "$unit"; then
                echo "FAIL: package installation activated $unit"
                exit 1
            fi
        done
        wg genkey >"$client_private"
        wg pubkey <"$client_private" >"$client_public"
        chmod 0600 "$client_private" "$client_public"
        echo "AMENDMENT_W_PREPARE_COHERENT_DOCKER_PASS"
        ;;
    configure-unreachable)
        wg genkey | wg pubkey >"$work_root/unreachable-public.key"
        chmod 0600 "$work_root/unreachable-public.key"
        write_profile "$work_root/unreachable-public.key" 9
        operator_snapshot >"$work_root/operator-baseline.snapshot"
        echo "AMENDMENT_W_UNREACHABLE_PROFILE_PASS"
        ;;
    configure)
        [[ -f $provider_public_input && ! -L $provider_public_input ]]
        write_profile "$provider_public_input" "$provider_port"
        echo "AMENDMENT_W_REACHABLE_PROFILE_PASS"
        ;;
    dry-run)
        operator_snapshot >"$work_root/dry-operator-before.snapshot"
        retained_snapshot >"$work_root/dry-retained-before.snapshot"
        /usr/sbin/nftfw setup --vpn "$profile" --dry-run --json >"$work_root/dry-run.json"
        operator_snapshot >"$work_root/dry-operator-after.snapshot"
        retained_snapshot >"$work_root/dry-retained-after.snapshot"
        cmp -s "$work_root/dry-operator-before.snapshot" "$work_root/dry-operator-after.snapshot"
        cmp -s "$work_root/dry-retained-before.snapshot" "$work_root/dry-retained-after.snapshot"
        jq -e '.schema=="nftfw.setup-plan.v1" and .docker_mode=="enabled" and
            .docker_restart_required==true and (.docker_networks|length)==3 and
            (.public_tcp // [])==[] and (.public_udp // [])==[] and .ipv6_mode=="disabled"' \
            "$work_root/dry-run.json" >/dev/null
        assert_output_redacted "$work_root/dry-run.json"
        echo "AMENDMENT_W_DRY_RUN_NONMUTATING_PASS"
        ;;
    process-death)
        [[ $expected_generation =~ ^[1-9][0-9]*$ ]]
        /usr/sbin/nftfw setup --vpn "$profile" --yes --json \
            >"$work_root/process-death-$expected_generation.log" 2>&1 &
        setup_pid=$!
        reached=false
        for _ in $(seq 1 1200); do
            phase=$(jq -r '.phase // empty' /var/lib/nftfw/setup/journal.json 2>/dev/null || true)
            if [[ $phase == validate ]]; then reached=true; break; fi
            if ! kill -0 "$setup_pid" 2>/dev/null; then break; fi
            sleep 0.05
        done
        [[ $reached == true ]]
        create_unrelated_nft
        unrelated_nft >"$work_root/unrelated-$expected_generation.sha256"
        kill -9 "$setup_pid"
        wait "$setup_pid" 2>/dev/null || true
        [[ $(jq -r '.status' /var/lib/nftfw/setup/journal.json) == running ]]
        /usr/sbin/nftfw setup rollback
        [[ $(unrelated_nft) == "$(<"$work_root/unrelated-$expected_generation.sha256")" ]]
        nft delete table inet "$unrelated_table"
        assert_exact_operator_rollback
        verify_terminal_generation "$expected_generation"
        echo "AMENDMENT_W_PROCESS_DEATH_EXACT_ROLLBACK_PASS generation=$expected_generation"
        ;;
    success)
        /usr/sbin/nftfw setup --vpn "$profile" --yes --json >"$work_root/setup-success.json"
        jq -e '.status=="PROTECTED" and .plan.schema=="nftfw.setup-plan.v1" and
            .plan.docker_mode=="enabled"' "$work_root/setup-success.json" >/dev/null
        assert_output_redacted "$work_root/setup-success.json"
        assert_managed_healthy
        [[ $(sqlite3 -readonly /var/lib/nftfw/generation-state/state.db \
            'SELECT group_concat(id || ":" || status,",") FROM (SELECT id,status FROM generations ORDER BY id);') == \
            '1:rolled_back,2:rolled_back,3:committed' ]]
        [[ $(jq -r '.generation' /var/lib/nftfw/enforcement-enabled) -eq 3 ]]
        [[ $(jq -r '.generation' /var/lib/nftfw/setup/journal.json) -eq 3 ]]
        jq -e '.phase=="complete" and .status=="complete" and .committed==true' \
            /var/lib/nftfw/setup/journal.json >/dev/null
        verify_history 2
        provenance_identity >"$work_root/provenance-3.identity"
        cmp -s "$work_root/provenance-1.identity" "$work_root/provenance-3.identity"
        [[ $(sqlite3 -readonly /var/lib/nftfw/provenance-ledger.db \
            'SELECT COUNT(*) FROM allocations WHERE retired<>0;') -eq 0 ]]
        [[ $(unrelated_nft) == ABSENT ]]
        [[ $(find /var/lib/nftfw/setup/backups -mindepth 1 -maxdepth 1 -type d | wc -l) -eq 3 ]]
        for network in bridge "$network_a" "$network_b"; do
            docker run --rm --network "$network" alpine:3.22 \
                wget -qO- -T 8 http://1.1.1.1:443/ | grep -Fxq R2OK
        done
        echo "AMENDMENT_W_EVENTUAL_SUCCESS_GENERATION_3_PASS"
        ;;
    idempotent)
        before=$(systemctl show docker.service -p ExecMainStartTimestampMonotonic -p NRestarts)
        /usr/sbin/nftfw setup --vpn "$profile" --yes --json >"$work_root/setup-idempotent.json"
        after=$(systemctl show docker.service -p ExecMainStartTimestampMonotonic -p NRestarts)
        [[ $before == "$after" ]]
        assert_managed_healthy
        echo "AMENDMENT_W_IDEMPOTENT_NO_DOCKER_RESTART_PASS"
        ;;
    tunnel-loss)
        uplink=$(ip -j -4 route show default | jq -r '.[0].dev')
        [[ $uplink =~ ^[A-Za-z0-9_.-]{1,15}$ ]]
        capture=$work_root/tunnel-loss.pcap
        tcpdump -ni "$uplink" -w "$capture" host 1.1.1.1 >/dev/null 2>&1 &
        capture_pid=$!
        sleep 0.5
        systemctl stop nftfw-vpn.service
        if curl -4fsS --max-time 3 http://1.1.1.1:443/ >/dev/null 2>&1; then
            echo "FAIL: host leaked after managed tunnel loss"
            exit 1
        fi
        if docker run --rm --network "$network_a" alpine:3.22 \
            wget -qO- -T 3 http://1.1.1.1:443/ >/dev/null 2>&1; then
            echo "FAIL: container leaked after managed tunnel loss"
            exit 1
        fi
        systemctl restart docker.service
        if docker run --rm --network "$network_b" alpine:3.22 \
            wget -qO- -T 3 http://1.1.1.1:443/ >/dev/null 2>&1; then
            echo "FAIL: Docker restart restored direct egress"
            exit 1
        fi
        sleep 0.5
        kill "$capture_pid"
        wait "$capture_pid" 2>/dev/null || true
        [[ $(tcpdump -nnr "$capture" 2>/dev/null | wc -l) -eq 0 ]]
        systemctl start nftfw-vpn.service
        for _ in $(seq 1 40); do
            if curl -4fsS --max-time 2 http://1.1.1.1:443/ 2>/dev/null | grep -Fxq R2OK; then
                echo "AMENDMENT_W_TUNNEL_LOSS_DOCKER_RESTART_ZERO_LEAK_RECOVERY_PASS"
                exit 0
            fi
            sleep 0.5
        done
        echo "FAIL: managed tunnel did not recover"
        exit 1
        ;;
    verify-boot)
        assert_managed_healthy
        systemctl is-enabled --quiet nftfw-early.service nftfw-enforcement-ready.service \
            nftfwd.service nftfw-rollback.timer nftfw-web.service nftfw-vpn.service
        echo "AMENDMENT_W_MANAGED_BOOT_PASS"
        ;;
    *)
        echo "usage: managed_retry_disposable.sh ACTION [private.deb] [provider-public] [provider-port] [generation]"
        exit 64
        ;;
esac
