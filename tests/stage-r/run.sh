#!/usr/bin/env bash
set -Eeuo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)

contract_status=0
release_guard_status=0
baseline_status=0
comparison_status=0
secret_scan_status=0
boot_pcap_status=0
python3 "$root_dir/tests/stage-r/source_contracts.py" || contract_status=$?
python3 "$root_dir/tests/stage-r/release_guard_contract.py" || release_guard_status=$?
bash "$root_dir/tests/stage-r/baseline_red.sh" || baseline_status=$?
python3 "$root_dir/tests/stage-r/candidate_comparison_test.py" || comparison_status=$?
python3 "$root_dir/tests/stage-r/secret_scan_test.py" || secret_scan_status=$?
python3 "$root_dir/tests/packaging/managed_boot_pcap_test.py" || boot_pcap_status=$?

if (( contract_status != 0 || release_guard_status != 0 || baseline_status != 0 || comparison_status != 0 || secret_scan_status != 0 || boot_pcap_status != 0 )); then
    printf 'STAGE R UNPRIVILEGED SOURCE CONTRACTS: FAIL (contracts=%d release_guard=%d baseline=%d comparison=%d secret_scan=%d boot_pcap=%d)\n' \
        "$contract_status" "$release_guard_status" "$baseline_status" "$comparison_status" "$secret_scan_status" "$boot_pcap_status" >&2
    echo "R2 PRIVILEGED PACKAGE/BOOT/NETWORK/DOCKER/OVPN EVIDENCE: NOT EXECUTED" >&2
    if (( contract_status != 0 )); then
        exit "$contract_status"
    fi
    if (( release_guard_status != 0 )); then
        exit "$release_guard_status"
    fi
    if (( baseline_status != 0 )); then
        exit "$baseline_status"
    fi
    if (( comparison_status != 0 )); then
        exit "$comparison_status"
    fi
    if (( secret_scan_status != 0 )); then
        exit "$secret_scan_status"
    fi
    exit "$boot_pcap_status"
fi

echo "STAGE R UNPRIVILEGED SOURCE CONTRACTS: PASS"
echo "R2 PRIVILEGED PACKAGE/BOOT/NETWORK/DOCKER/OVPN EVIDENCE: NOT EXECUTED"
