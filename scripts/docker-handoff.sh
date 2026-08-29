#!/bin/sh

nftfw_remove_managed_docker_dropin() {
    nftfw_root=${1:-}
    case "$nftfw_root" in
        ""|/*) ;;
        *)
            echo "NFTFW handoff root must be empty or absolute" >&2
            return 2
            ;;
    esac

    nftfw_dropin="$nftfw_root/etc/systemd/system/nftfwd.service.d/docker-access.conf"
    nftfw_daemon="$nftfw_root/etc/docker/daemon.json"
    nftfw_sysctl="$nftfw_root/etc/sysctl.d/90-nftfw-managed.conf"
    nftfw_handoff_dir="$nftfw_root/var/lib/nftfw/setup"
    nftfw_handoff="$nftfw_handoff_dir/UNINSTALL_HANDOFF"

    if [ -L "$nftfw_dropin" ]; then
        echo "Preserving unsafe Docker socket drop-in symlink for manual review: $nftfw_dropin" >&2
    elif [ -f "$nftfw_dropin" ]; then
        if printf '[Service]\nInaccessiblePaths=\n' | cmp -s - "$nftfw_dropin"; then
            rm -f -- "$nftfw_dropin"
            rmdir -- "$(dirname "$nftfw_dropin")" 2>/dev/null || true
        else
            echo "Preserving modified Docker socket drop-in for manual review: $nftfw_dropin" >&2
        fi
    fi

    if [ -e "$nftfw_daemon" ] || [ -e "$nftfw_sysctl" ]; then
        mkdir -p -- "$nftfw_handoff_dir"
        chmod 0700 "$nftfw_handoff_dir"
        nftfw_handoff_tmp="$nftfw_handoff.tmp.$$"
        umask 077
        {
            printf '%s\n' \
                'schema=nftfw.docker-uninstall-handoff.v1' \
                'status=preserved-fail-closed' \
                'docker_daemon=/etc/docker/daemon.json' \
                'sysctl=/etc/sysctl.d/90-nftfw-managed.conf' \
                'backup_journal=/var/lib/nftfw/setup/journal.json'
        } > "$nftfw_handoff_tmp"
        chmod 0600 "$nftfw_handoff_tmp"
        mv -f -- "$nftfw_handoff_tmp" "$nftfw_handoff"
    fi
}
