#!/usr/bin/env bash
set -Eeuo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
arch=${1:-amd64}
real_systemd_analyze=$(command -v systemd-analyze)
wrapper_dir=$(mktemp -d /tmp/nftfw-systemd-wrapper.XXXXXX)
cleanup() {
    find "$wrapper_dir" -depth -delete
}
trap cleanup EXIT

cat > "$wrapper_dir/systemd-analyze" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
for argument in "$@"; do
    case "$argument" in
        *.service|*.timer)
            [[ "$argument" == /tmp/nftfw-systemd-verify.*/units/* ]] || {
                echo "systemd unit was not verified from the isolated stage: $argument" >&2
                exit 1
            }
            if grep -F '/usr/lib/nftfw/' "$argument" >/dev/null; then
                echo "systemd unit retained a final-path executable during preflight: $argument" >&2
                exit 1
            fi
            ;;
    esac
done
exec "$REAL_SYSTEMD_ANALYZE" "$@"
WRAPPER
chmod 0755 "$wrapper_dir/systemd-analyze"

REAL_SYSTEMD_ANALYZE=$real_systemd_analyze \
PATH="$wrapper_dir:$PATH" \
    bash "$root_dir/scripts/verify-systemd-units.sh" "$root_dir" "$arch"
echo "STAGED SYSTEMD PREFLIGHT: PASS"
