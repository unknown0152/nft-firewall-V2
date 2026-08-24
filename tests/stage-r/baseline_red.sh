#!/usr/bin/env bash
set -Eeuo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
baseline_tag=v2.0.1
baseline_commit=cf8451b679c734adada6d34e99765004f223f0f7

for command_name in find git grep mktemp python3 tar; do
    command -v "$command_name" >/dev/null || {
        echo "BLOCKED: Stage R baseline-red proof is missing $command_name" >&2
        exit 77
    }
done

cd "$root_dir"
resolved=$(git rev-parse --verify "$baseline_tag^{commit}" 2>/dev/null || true)
if [[ "$resolved" != "$baseline_commit" ]]; then
    echo "BLOCKED: $baseline_tag must resolve to immutable commit $baseline_commit (found ${resolved:-ABSENT})" >&2
    exit 77
fi

temporary=$(mktemp -d /tmp/nftfw-stage-r-baseline.XXXXXX)
cleanup() { find "$temporary" -depth -delete; }
trap cleanup EXIT
git archive --format=tar "$baseline_commit" | tar -xf - -C "$temporary"

baseline_postinst="$temporary/packaging/deb/postinst"
baseline_daemon="$temporary/packaging/systemd/nftfwd.service"
baseline_timer="$temporary/packaging/systemd/nftfw-rollback.timer"
grep -Eq '^[[:space:]]*systemctl[[:space:]]+enable([[:space:]]|$)' "$baseline_postinst" || {
    echo "FAIL: v2.0.1 lifecycle red proof no longer contains package auto-enable" >&2
    exit 1
}
grep -Eq '^[[:space:]]*systemctl[[:space:]]+restart([[:space:]]|$)' "$baseline_postinst" || {
    echo "FAIL: v2.0.1 lifecycle red proof no longer contains package auto-restart" >&2
    exit 1
}
echo "V2.0.1 PACKAGE LIFECYCLE BASELINE: EXPECTED RED"

grep -Fq 'Requires=nftfw-early.service' "$baseline_daemon" || {
    echo "FAIL: v2.0.1 graph red proof no longer contains daemon-to-early activation" >&2
    exit 1
}
grep -Fq 'After=nftfwd.service' "$baseline_timer" || {
    echo "FAIL: v2.0.1 graph red proof no longer contains timer-to-daemon ordering" >&2
    exit 1
}
echo "V2.0.1 SYSTEMD GRAPH BASELINE: EXPECTED RED"

set +e
baseline_output=$(python3 "$root_dir/tests/stage-r/provenance_source_contract.py" --source-root "$temporary" 2>&1)
baseline_rc=$?
set -e
if (( baseline_rc != 1 )); then
    printf '%s\n' "$baseline_output" >&2
    echo "FAIL: unchanged v2.0.1 must fail the Stage R provenance source contract with rc=1 (found rc=$baseline_rc)" >&2
    exit 1
fi
for expected in CONFIG_PROVENANCE_ID_MISSING PROVENANCE_MASK_MISSING WRITE_ONCE_ORIGINAL_DIRECTION_TAG_MISSING UNPROVEN_UPLINK_REPLY_STILL_PRESENT; do
    grep -Fq "$expected" <<<"$baseline_output" || {
        printf '%s\n' "$baseline_output" >&2
        echo "FAIL: v2.0.1 red proof did not expose expected defect marker $expected" >&2
        exit 1
    }
done
echo "V2.0.1 PROVENANCE BASELINE: EXPECTED RED"

python3 "$root_dir/tests/stage-r/provenance_source_contract.py" --source-root "$root_dir"
echo "V2.0.2 PROVENANCE SOURCE SHAPE: PASS (NOT PACKET PROOF)"
