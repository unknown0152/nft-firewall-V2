#!/usr/bin/env bash
set -Eeuo pipefail
umask 0077

# This fixture is copied only into a disposable Debian 13 guest. It exercises
# the managed GRUB reboot boundary with real systemd, nftables, Docker,
# WireGuard, routing, sysctls, and initramfs state. It must never run on the
# build or production host.

readonly action=${1:?action required}
readonly private_deb=${2:-}
readonly provider_public=${3:-}
readonly provider_port=${4:-}
readonly work_root=/opt/nftfw-amendment-x
readonly profile=$work_root/provider.conf
readonly client_private=$work_root/client-private.key
readonly client_public=$work_root/client-public.key
readonly before_docker=$work_root/before-docker.sha256
readonly before_forwarding=$work_root/before-forwarding
readonly before_ruleset=$work_root/before-ruleset.sha256
readonly before_grub=$work_root/before-grub.sha256
readonly update_grub_backup=$work_root/update-grub.original
readonly setup_output=$work_root/setup.json
readonly resume_output=$work_root/resume.json
readonly fragment=/etc/default/grub.d/90-nftfw-ipv6-disabled.cfg
readonly boot_marker=/etc/nftfw/setup-boot-hold-v1
readonly journal=/var/lib/nftfw/setup/journal.json
readonly resume_table=nftfw_setup_resume_guard

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    echo "BLOCKED: Amendment X disposable fixture requires guest root"
    exit 77
}

require_tools() {
    local tool
    for tool in busybox curl docker dpkg dpkg-deb grep ip ip6tables iptables jq ldd nft \
        sha256sum stat sysctl systemctl tar update-grub wg; do
        command -v "$tool" >/dev/null || {
            echo "BLOCKED: missing Amendment X guest prerequisite: $tool"
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

prepare_clean_docker() {
    local family table
    systemctl disable --now nftfw-r2-outer.service >/dev/null 2>&1 || true
    nft delete table inet r2_outer >/dev/null 2>&1 || true
    systemctl stop docker.socket docker.service containerd.service >/dev/null 2>&1 || true
    if [[ -e /etc/docker/daemon.json || -L /etc/docker/daemon.json ]]; then
        [[ -f /etc/docker/daemon.json && ! -L /etc/docker/daemon.json ]]
    fi
    install -d -o root -g root -m 0700 /etc/docker
    install -o root -g root -m 0600 /dev/null /etc/docker/daemon.json
    printf '%s\n' \
        '{"iptables":false,"ip6tables":false,"ip-forward":false,"ip-masq":false,"userland-proxy":false,"log-driver":"json-file"}' \
        >/etc/docker/daemon.json
    chmod 0600 /etc/docker/daemon.json
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
    systemctl start containerd.service docker.service
    systemctl is-active --quiet docker.service
    [[ -z $(docker ps -aq --no-trunc) ]]
    [[ -z $(nft list tables) ]]
}

backup_update_grub() {
    [[ -f /usr/sbin/update-grub && ! -L /usr/sbin/update-grub ]]
    [[ $(stat -c '%u:%g:%h' /usr/sbin/update-grub) == 0:0:1 ]]
    cp --preserve=all -- /usr/sbin/update-grub "$update_grub_backup"
    chmod 0700 "$update_grub_backup"
}

restore_update_grub() {
    [[ -f $update_grub_backup && ! -L $update_grub_backup ]]
    cp --preserve=all -- "$update_grub_backup" /usr/sbin/update-grub
    dpkg --verify grub2-common
}

assert_preboot_rollback_exact() {
    jq -e '.status == "rolled_back" and .phase == "failed" and
        (.committed // false) == false and (.generation // 0) == 0' "$journal" >/dev/null
    [[ $(sha256sum /boot/grub/grub.cfg | awk '{print $1}') == "$(<"$before_grub")" ]]
    [[ ! -e $fragment && ! -L $fragment && ! -e $boot_marker && ! -L $boot_marker ]]
    /usr/lib/nftfw/initramfs/nftfw-initramfs-manage verify-disabled
    assert_no_managed_runtime_mutation
    echo "AMENDMENT_X_DISPOSABLE_PREBOOT_ROLLBACK_EXACT_PASS"
}

one_cmdline_disable() {
    local count
    count=$(tr ' ' '\n' </proc/cmdline | grep -Fxc 'ipv6.disable=1' || true)
    [[ $count -eq 1 ]]
}

kernel_ipv6_disabled() {
    local value
    value=$(tr '[:lower:]' '[:upper:]' </sys/module/ipv6/parameters/disable)
    [[ $value == Y || $value == 1 ]]
}

assert_no_managed_runtime_mutation() {
    [[ $(sha256sum /etc/docker/daemon.json | awk '{print $1}') == "$(<"$before_docker")" ]]
    [[ $(sysctl -n net.ipv4.ip_forward) == "$(<"$before_forwarding")" ]]
    [[ $(nft -j list ruleset | jq -S . | sha256sum | awk '{print $1}') == "$(<"$before_ruleset")" ]]
    for path in /etc/nftfw/intent.toml /etc/wireguard/nftfw0.conf \
        /etc/sysctl.d/90-nftfw-managed.conf \
        /etc/systemd/system/nftfwd.service.d/docker-access.conf \
        /var/lib/nftfw/enforcement-enabled; do
        [[ ! -e $path && ! -L $path ]]
    done
    for unit in nftfw-vpn.service nftfwd.service nftfw-web.service; do
        if systemctl is-active --quiet "$unit"; then
            echo "FAIL: pre-reboot managed unit is active: $unit"
            exit 1
        fi
    done
}

assert_managed_healthy() {
    jq -e '.status == "complete" and .phase == "complete"' "$journal" >/dev/null
    one_cmdline_disable
    kernel_ipv6_disabled
    [[ ! -s /proc/net/if_inet6 ]]
    [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]]
    [[ ! -e /proc/sys/net/ipv6 && ! -L /proc/sys/net/ipv6 ]]
    systemctl is-active --quiet docker.service nftfw-vpn.service nftfwd.service nftfw-web.service
    local attempt
    for attempt in $(seq 1 90); do
        /usr/sbin/nftfw health >/dev/null 2>&1 && break
        sleep 1
    done
    [[ $attempt -lt 90 ]] || /usr/sbin/nftfw health >/dev/null
    ip -j -4 route get 1.1.1.1 | jq -e '.[0].dev == "nftfw0"' >/dev/null
    curl -4fsS --max-time 8 http://1.1.1.1:443/ | grep -Fxq R2OK
}

case "$action" in
    prepare)
        require_tools
        [[ -f $private_deb && ! -L $private_deb ]]
        [[ $(dpkg-deb -f "$private_deb" Package) == nft-firewall-v2 ]]
        [[ $(dpkg-deb -f "$private_deb" Version) == 2.1.0 ]]
        [[ $(dpkg-deb -f "$private_deb" Architecture) == amd64 ]]
        [[ $(dpkg-deb -f "$private_deb" X-NFTFW-Build-Disposition) == release ]]
        [[ ! -e $work_root && ! -e /var/lib/nftfw ]]
        install -d -o root -g root -m 0700 "$work_root"
        prepare_clean_docker
        dpkg --install "$private_deb" >/dev/null
        for unit in nftfw-vpn.service nftfwd.service nftfw-web.service; do
            if systemctl is-active --quiet "$unit"; then
                echo "FAIL: package installation activated $unit"
                exit 1
            fi
        done
        wg genkey >"$client_private"
        wg pubkey <"$client_private" >"$client_public"
        chmod 0600 "$client_private" "$client_public"
        sha256sum /etc/docker/daemon.json | awk '{print $1}' >"$before_docker"
        sysctl -n net.ipv4.ip_forward >"$before_forwarding"
        nft -j list ruleset | jq -S . | sha256sum | awk '{print $1}' >"$before_ruleset"
        sha256sum /boot/grub/grub.cfg | awk '{print $1}' >"$before_grub"
        echo "AMENDMENT_X_DISPOSABLE_PREPARE_PASS"
        ;;
    configure)
        [[ -f $provider_public && ! -L $provider_public ]]
        [[ $provider_port =~ ^[0-9]+$ && $provider_port -ge 1 && $provider_port -le 65535 ]]
        [[ -f $client_private && ! -L $client_private ]]
        install -o root -g root -m 0600 /dev/null "$profile"
        {
            printf '[Interface]\nAddress = 10.240.0.2/32\nPrivateKey = %s\n\n' "$(<"$client_private")"
            printf '[Peer]\nPublicKey = %s\nEndpoint = 10.0.2.2:%s\n' "$(<"$provider_public")" "$provider_port"
            printf 'AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 5\n'
        } >"$profile"
        chmod 0600 "$profile"
        echo "AMENDMENT_X_DISPOSABLE_CONFIGURE_PASS"
        ;;
    first-pass)
        assert_no_managed_runtime_mutation
        /usr/sbin/nftfw setup --vpn "$profile" --yes --json >"$setup_output"
        jq -e '.status == "reboot_required" and .automatic_reboot == false and
            .plan.boot_policy == "debian-grub-ipv6-disabled-v1" and
            .plan.docker_mode == "enabled"' "$setup_output" >/dev/null
        jq -e '.status == "reboot_required" and .phase == "boot_prepare" and
            (.committed // false) == false and (.generation // 0) == 0' "$journal" >/dev/null
        [[ $(stat -c '%a:%U:%G:%h' "$fragment") == 600:root:root:1 ]]
        [[ $(stat -c '%a:%U:%G:%h' "$boot_marker") == 600:root:root:1 ]]
        # The expression below is the exact literal fragment contract.
        # shellcheck disable=SC2016
        grep -Fxq 'GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX:+$GRUB_CMDLINE_LINUX }ipv6.disable=1"' "$fragment"
        /usr/lib/nftfw/initramfs/nftfw-initramfs-manage verify-enabled
        ! one_cmdline_disable
        assert_no_managed_runtime_mutation
        /usr/sbin/nftfw setup status --json | jq -e '.status == "reboot_required"' >/dev/null
        echo "AMENDMENT_X_DISPOSABLE_REBOOT_REQUIRED_PASS"
        ;;
    resume-ready)
        one_cmdline_disable
        kernel_ipv6_disabled
        [[ ! -s /proc/net/if_inet6 ]]
        /usr/sbin/nftfw setup status --json | jq -e '.status == "resume_ready"' >/dev/null
        nft list table inet "$resume_table" >/dev/null
        ! nft list table inet nftfw_initramfs_guard >/dev/null 2>&1
        [[ $(systemctl show docker.service -p ActiveState --value) == inactive ]]
        [[ $(systemctl show docker.socket -p ActiveState --value) == active ]]
        [[ $(systemctl show nftfw-setup-docker-hold.service -p ActiveState --value) == activating ]]
        [[ -f /run/nftfw/setup-docker-hold-ready && ! -L /run/nftfw/setup-docker-hold-ready ]]
        echo "AMENDMENT_X_DISPOSABLE_RESUME_READY_PASS"
        ;;
    resume)
        /usr/sbin/nftfw setup --vpn "$profile" --yes --json >"$resume_output"
        jq -e '.status == "PROTECTED" and
            .plan.boot_policy == "debian-grub-ipv6-disabled-v1" and
            .plan.docker_mode == "enabled"' "$resume_output" >/dev/null
        assert_managed_healthy
        [[ ! -e $boot_marker && ! -L $boot_marker ]]
        [[ ! -e /run/nftfw/setup-docker-hold-ready &&
            ! -e /run/nftfw/setup-docker-release ]]
        ensure_test_image
        docker run --rm --network bridge alpine:3.22 \
            wget -qO- -T 8 http://1.1.1.1:443/ | grep -Fxq R2OK
        echo "AMENDMENT_X_DISPOSABLE_RESUME_PROTECTED_PASS"
        ;;
    idempotent)
        assert_managed_healthy
        before=$(systemctl show docker.service -p ExecMainStartTimestampMonotonic -p NRestarts)
        /usr/sbin/nftfw setup --vpn "$profile" --yes --json >"$work_root/idempotent.json"
        after=$(systemctl show docker.service -p ExecMainStartTimestampMonotonic -p NRestarts)
        [[ $before == "$after" ]]
        jq -e '.status == "PROTECTED" and .idempotent == true' "$work_root/idempotent.json" >/dev/null
        assert_managed_healthy
        echo "AMENDMENT_X_DISPOSABLE_IDEMPOTENT_PASS"
        ;;
    failed-update)
        backup_update_grub
        install -o root -g root -m 0755 /dev/null /usr/sbin/update-grub
        printf '%s\n' '#!/bin/sh' 'exit 42' >/usr/sbin/update-grub
        if /usr/sbin/nftfw setup --vpn "$profile" --yes --json >"$work_root/failed-update.out" 2>&1; then
            echo "FAIL: injected GRUB update failure was accepted"
            exit 1
        fi
        grep -Fq 'SETUP_BOOT_UPDATE_FAILED' "$work_root/failed-update.out"
        restore_update_grub
        assert_preboot_rollback_exact
        echo "AMENDMENT_X_DISPOSABLE_FAILED_UPDATE_PASS"
        ;;
    pre-reboot-death)
        backup_update_grub
        install -o root -g root -m 0755 /dev/null /usr/sbin/update-grub
        cat >/usr/sbin/update-grub <<EOF
#!/bin/sh
set -eu
"$update_grub_backup" "\$@"
: >"$work_root/update-blocked"
while :; do sleep 60; done
EOF
        chmod 0755 /usr/sbin/update-grub
        setsid /usr/sbin/nftfw setup --vpn "$profile" --yes --json \
            >"$work_root/pre-reboot-death.out" 2>&1 &
        setup_pid=$!
        for _ in $(seq 1 120); do
            [[ -f $work_root/update-blocked ]] && break
            sleep 0.25
        done
        [[ -f $work_root/update-blocked ]]
        jq -e '.status == "running" and .phase == "boot_prepare"' "$journal" >/dev/null
        kill -KILL -- "-$setup_pid"
        wait "$setup_pid" 2>/dev/null || true
        restore_update_grub
        /usr/sbin/nftfw setup rollback
        assert_preboot_rollback_exact
        echo "AMENDMENT_X_DISPOSABLE_PRE_REBOOT_DEATH_PASS"
        ;;
    post-reboot-death)
        one_cmdline_disable
        kernel_ipv6_disabled
        /usr/sbin/nftfw setup status --json | jq -e '.status == "resume_ready"' >/dev/null
        install -d -o root -g root -m 0700 "$work_root/bin"
        cat >"$work_root/bin/systemctl" <<EOF
#!/bin/sh
set -eu
if [ "\$*" = 'restart docker.service' ]; then
    /usr/bin/systemctl "\$@"
    : >"$work_root/docker-restart-blocked"
    while :; do sleep 60; done
fi
exec /usr/bin/systemctl "\$@"
EOF
        chmod 0700 "$work_root/bin/systemctl"
        setsid env PATH="$work_root/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
            /usr/sbin/nftfw setup --vpn "$profile" --yes --json \
            >"$work_root/post-reboot-death.out" 2>&1 &
        setup_pid=$!
        for _ in $(seq 1 240); do
            [[ -f $work_root/docker-restart-blocked ]] && break
            sleep 0.25
        done
        [[ -f $work_root/docker-restart-blocked ]]
        jq -e '.status == "running" and .phase == "docker"' "$journal" >/dev/null
        kill -KILL -- "-$setup_pid"
        wait "$setup_pid" 2>/dev/null || true
        rm -f -- "$work_root/bin/systemctl"
        /usr/sbin/nftfw setup rollback
        jq -e '.status == "rollback_reboot_required" and .phase == "failed" and
            (.committed // false) == false' "$journal" >/dev/null
        [[ $(sha256sum /boot/grub/grub.cfg | awk '{print $1}') == "$(<"$before_grub")" ]]
        [[ ! -e $fragment && ! -L $fragment && ! -e $boot_marker && ! -L $boot_marker ]]
        [[ $(sha256sum /etc/docker/daemon.json | awk '{print $1}') == "$(<"$before_docker")" ]]
        [[ $(sysctl -n net.ipv4.ip_forward) == "$(<"$before_forwarding")" ]]
        [[ ! -e /etc/sysctl.d/90-nftfw-managed.conf && ! -L /etc/sysctl.d/90-nftfw-managed.conf ]]
        /usr/lib/nftfw/initramfs/nftfw-initramfs-manage verify-disabled
        ! nft list table inet nftfw_setup_guard >/dev/null 2>&1
        ! nft list table inet "$resume_table" >/dev/null 2>&1
        echo "AMENDMENT_X_DISPOSABLE_POST_REBOOT_DEATH_ROLLBACK_PASS"
        ;;
    rollback-finalize)
        ! one_cmdline_disable
        /usr/sbin/nftfw setup rollback
        jq -e '.status == "rolled_back" and .phase == "failed" and
            (.committed // false) == false and (.generation // 0) == 0' "$journal" >/dev/null
        assert_preboot_rollback_exact
        echo "AMENDMENT_X_DISPOSABLE_ROLLBACK_FINALIZE_PASS"
        ;;
    verify-boot)
        assert_managed_healthy
        systemctl is-enabled --quiet nftfw-early.service nftfw-enforcement-ready.service \
            nftfwd.service nftfw-rollback.timer nftfw-web.service nftfw-vpn.service
        echo "AMENDMENT_X_DISPOSABLE_MANAGED_BOOT_PASS"
        ;;
    *)
        echo "usage: managed_boot_disposable.sh <prepare|configure|first-pass|resume-ready|resume|idempotent|failed-update|pre-reboot-death|post-reboot-death|rollback-finalize|verify-boot> [private.deb] [provider-public] [provider-port]"
        exit 64
        ;;
esac
