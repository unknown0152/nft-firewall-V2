#!/usr/bin/env bash
set -u

if [[ $# -ne 3 ]]; then
    echo "usage: emergency_rollback.sh <commit-marker> <owned-backup> <result-file>" >&2
    exit 2
fi

marker=$1
backup=$2
result=$3
nft_bin=/usr/sbin/nft

for path in "$marker" "$backup" "$result"; do
    [[ "$path" == /* ]] || { echo "all paths must be absolute" >&2; exit 2; }
done
[[ ! -L "$marker" && ! -L "$backup" && ! -L "$result" ]] || { echo "symlinked safety path rejected" >&2; exit 2; }
[[ -x "$nft_bin" ]] || { echo "nft executable is unavailable" >&2; exit 1; }
[[ -f "$backup" ]] || { echo "owned-table backup is unavailable" >&2; exit 1; }

umask 077
touch "$result" || exit 1
exec >>"$result" 2>&1

if [[ -e "$marker" ]]; then
    echo "EMERGENCY ROLLBACK: DISARMED"
    exit 0
fi

failed=0
while read -r family table; do
    if "$nft_bin" list table "$family" "$table" >/dev/null 2>&1; then
        if ! "$nft_bin" delete table "$family" "$table"; then
            failed=1
        fi
    fi
done <<'TABLES'
inet nftfw_filter
ip nftfw_nat
ip6 nftfw_filter6
TABLES

if [[ -s "$backup" ]]; then
    if ! "$nft_bin" --check --file "$backup" || ! "$nft_bin" --file "$backup"; then
        failed=1
    fi
fi

if (( failed != 0 )); then
    echo "EMERGENCY ROLLBACK: FAIL"
    exit 1
fi
echo "EMERGENCY ROLLBACK: PASS"

