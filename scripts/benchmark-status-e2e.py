#!/usr/bin/env python3
"""Measure installed NFTFW status without exposing protected state."""

from __future__ import annotations

import argparse
import http.client
import json
import math
import os
import re
import socket
import statistics
import subprocess
import time
from typing import Any, Callable


MAX_STATUS_BYTES = 4 << 20
MAX_DOCKER_LIST_BYTES = 128 << 10
CLI_BUDGET_MS = 75.0
DASHBOARD_BUDGET_MS = 50.0
NFTFWD_RSS_BUDGET_KIB = 40 * 1024
NFTFWD_CGROUP_BUDGET_BYTES = 64 << 20
WEB_RSS_BUDGET_KIB = 16 * 1024
IDLE_CPU_BUDGET_PERCENT = 0.2
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
STATUS_SOCKET = "/run/nftfw/status.sock"
GENERATION_DATABASE = "/var/lib/nftfw/generation-state/state.db"
PROVENANCE_DATABASE = "/var/lib/nftfw/provenance-ledger.db"


def bounded_output(command: list[str], limit: int, timeout: float = 15.0) -> bytes:
    completed = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
    )
    if len(completed.stdout) > limit:
        raise RuntimeError("bounded command output exceeded its limit")
    return completed.stdout


def json_command(command: list[str]) -> dict[str, Any]:
    value = json.loads(bounded_output(command, MAX_STATUS_BYTES))
    if not isinstance(value, dict):
        raise RuntimeError("status command did not return a JSON object")
    return value


def unix_status() -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(12.0)
        connection.connect(STATUS_SOCKET)
        connection.sendall(b'{"op":"status"}\n')
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = connection.recv(min(64 << 10, MAX_STATUS_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_STATUS_BYTES:
                raise RuntimeError("Unix status response exceeded its safety limit")
    response = json.loads(b"".join(chunks))
    if not isinstance(response, dict) or response.get("ok") is not True:
        raise RuntimeError("Unix status response is not successful")
    value = response.get("data")
    if not isinstance(value, dict) or not protected_contract(value):
        raise RuntimeError("Unix status is not the healthy protected contract")
    return value


def percentile(values: list[float], fraction: float) -> float:
    return values[max(0, math.ceil(fraction * len(values)) - 1)]


def summarize(values: list[float]) -> dict[str, float]:
    values.sort()
    return {
        "median_ms": round(statistics.median(values), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "max_ms": round(values[-1], 3),
    }


def measure(operation: Callable[[], None], warmups: int, samples: int) -> dict[str, float]:
    for _ in range(warmups):
        operation()
    values: list[float] = []
    for _ in range(samples):
        started = time.monotonic_ns()
        operation()
        values.append((time.monotonic_ns() - started) / 1_000_000)
    return summarize(values)


def measure_command(command: list[str], samples: int) -> dict[str, float]:
    def invoke() -> None:
        subprocess.run(
            command,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )

    return measure(invoke, min(3, samples), samples)


def service_pid(name: str) -> int:
    value = bounded_output(
        ["systemctl", "show", name, "-p", "MainPID", "--value"], 128
    ).decode("ascii").strip()
    pid = int(value)
    if pid <= 1:
        raise RuntimeError("required managed service has no main process")
    return pid


def rss_kib(pid: int) -> int:
    with open(f"/proc/{pid}/status", encoding="ascii") as stream:
        for line in stream:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    raise RuntimeError("service RSS is unavailable")


def process_ticks(pid: int) -> int:
    with open(f"/proc/{pid}/stat", encoding="ascii") as stream:
        fields = stream.read().split()
    return int(fields[13]) + int(fields[14])


def component_profile(status: dict[str, Any], samples: int) -> dict[str, Any]:
    commands: dict[str, list[str]] = {
        "config_load_compile_cli": [
            "/usr/sbin/nftfw", "config", "validate", "/etc/nftfw/nftfw.toml"
        ],
        "nft_whole_ruleset_read": ["nft", "-j", "list", "ruleset"],
    }
    docker_prefix = ["docker", "--host", "unix:///var/run/docker.sock"]
    network_list = docker_prefix + [
        "network", "ls", "--no-trunc", "--format",
        "{{.ID}}\t{{.Name}}\t{{.Driver}}",
    ]
    raw_networks = bounded_output(network_list, MAX_DOCKER_LIST_BYTES).decode("utf-8")
    bridge_ids: list[str] = []
    for line in raw_networks.splitlines():
        fields = line.split("\t")
        if len(fields) == 3 and fields[2] == "bridge":
            bridge_ids.append(fields[0])
    if not bridge_ids or len(bridge_ids) > 62:
        raise RuntimeError("component profile found an unsupported Docker bridge count")
    commands["docker_network_list"] = network_list
    commands["docker_network_inspect_batched"] = docker_prefix + [
        "network", "inspect", "--", *bridge_ids,
    ]
    wireguard = status.get("wireguard")
    interface = wireguard.get("interface") if isinstance(wireguard, dict) else None
    if isinstance(interface, str) and interface:
        commands["wireguard_latest_handshakes"] = [
            "wg", "show", interface, "latest-handshakes"
        ]
        commands["wireguard_endpoints"] = ["wg", "show", interface, "endpoints"]
    sqlite_commands = {
        "generation_database_quick_check": [
            "sqlite3", "-readonly", GENERATION_DATABASE, "PRAGMA quick_check;"
        ],
        "provenance_database_quick_check": [
            "sqlite3", "-readonly", PROVENANCE_DATABASE, "PRAGMA quick_check;"
        ],
    }
    for name, command in sqlite_commands.items():
        if bounded_output(command, 128).decode("ascii").strip() != "ok":
            raise RuntimeError(f"{name} did not return ok")
        commands[name] = command

    timings: dict[str, Any] = {
        "daemon_status_unix": measure(
            lambda: unix_status(), min(3, samples), samples
        )
    }
    for name, command in commands.items():
        timings[name] = measure_command(command, samples)
    return {
        "samples_each": samples,
        "docker_bridge_count": len(bridge_ids),
        "timings": timings,
        "sensitive_output_emitted": False,
    }


def protected_contract(value: dict[str, Any]) -> bool:
    checksum = value.get("policy_checksum")
    primary = value.get("policy_hash")
    return (
        value.get("schema") == "nftfw.status.v2"
        and value.get("status") == "HEALTHY"
        and value.get("active") is True
        and value.get("policy_match") is True
        and value.get("kill_switch_enforced") is True
        and isinstance(primary, str)
        and SHA256_PATTERN.fullmatch(primary) is not None
        and primary == checksum
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--disposable-vm", action="store_true", required=True)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--warmups", type=int, default=10)
    parser.add_argument("--component-samples", type=int, default=20)
    parser.add_argument("--idle-seconds", type=int, default=60)
    parser.add_argument("--baseline-cli-p95-ms", type=float)
    parser.add_argument("--baseline-dashboard-p95-ms", type=float)
    args = parser.parse_args()
    if not 20 <= args.samples <= 1000:
        parser.error("--samples must be 20..1000")
    if not 1 <= args.warmups <= 100:
        parser.error("--warmups must be 1..100")
    if not 5 <= args.component_samples <= 100:
        parser.error("--component-samples must be 5..100")
    if not 10 <= args.idle_seconds <= 300:
        parser.error("--idle-seconds must be 10..300")
    for value in (args.baseline_cli_p95_ms, args.baseline_dashboard_p95_ms):
        if value is not None and value <= 0:
            parser.error("baseline p95 values must be positive")
    return args


def main() -> int:
    args = parse_args()
    if os.geteuid() != 0:
        raise SystemExit("benchmark requires guest root")
    virtualization = bounded_output(
        ["systemd-detect-virt", "--vm"], 128, timeout=5
    ).decode("ascii").strip()
    if virtualization in {"", "none"}:
        raise SystemExit("benchmark refuses a non-virtual-machine host")
    setup = json_command(["/usr/sbin/nftfw", "setup", "status", "--json"])
    if setup.get("status") != "complete" or setup.get("phase") != "complete":
        raise SystemExit("managed setup is not complete")
    identity = json_command(["/usr/sbin/nftfw", "version", "--json"])
    nftfwd_pid = service_pid("nftfwd.service")
    web_pid = service_pid("nftfw-web.service")

    latest_cli: dict[str, Any] = {}

    def cli_status() -> None:
        nonlocal latest_cli
        latest_cli = json_command(["/usr/sbin/nftfw", "status", "--json"])
        if (
            latest_cli.get("schema") != "nftfw.status.v2"
            or latest_cli.get("managed") is not True
            or latest_cli.get("docker_enabled") is not True
            or not isinstance(latest_cli.get("docker_network_count"), int)
            or latest_cli.get("docker_network_count", 0) <= 0
            or latest_cli.get("ipv4_forwarding") is not True
            or not protected_contract(latest_cli)
        ):
            raise RuntimeError(
                "CLI status is not the healthy protected managed-Docker contract"
            )

    connection = http.client.HTTPConnection("127.0.0.1", 8787, timeout=2)

    def dashboard_status() -> None:
        connection.request("GET", "/api/status", headers={"Accept": "application/json"})
        response = connection.getresponse()
        payload = response.read(MAX_STATUS_BYTES + 1)
        if response.status != 200 or len(payload) > MAX_STATUS_BYTES:
            raise RuntimeError("dashboard status response failed its bound")
        value = json.loads(payload)
        if not isinstance(value, dict) or value.get("schema") != "nftfw.status.v2":
            raise RuntimeError("dashboard status schema changed")
        if value.get("protected") is not True or not protected_contract(value):
            raise RuntimeError("dashboard is not a healthy protected projection")

    cli = measure(cli_status, args.warmups, args.samples)
    time.sleep(2)
    dashboard = measure(dashboard_status, args.warmups, args.samples)
    connection.close()
    components = component_profile(latest_cli, args.component_samples)
    unix_median = components["timings"]["daemon_status_unix"]["median_ms"]
    components["derived_median_ms"] = {
        "cli_minus_unix": round(cli["median_ms"] - unix_median, 3),
        "dashboard_minus_unix": round(dashboard["median_ms"] - unix_median, 3),
    }

    time.sleep(5)
    ticks_before = process_ticks(nftfwd_pid)
    idle_started = time.monotonic()
    time.sleep(args.idle_seconds)
    idle_elapsed = time.monotonic() - idle_started
    ticks_after = process_ticks(nftfwd_pid)
    idle_cpu = ((ticks_after - ticks_before) / os.sysconf("SC_CLK_TCK")) / idle_elapsed * 100
    with open(
        "/sys/fs/cgroup/system.slice/nftfwd.service/memory.current",
        encoding="ascii",
    ) as stream:
        cgroup_memory = int(stream.read())
    resources = {
        "nftfwd_rss_kib": rss_kib(nftfwd_pid),
        "nftfwd_cgroup_memory_bytes": cgroup_memory,
        "nftfw_web_rss_kib": rss_kib(web_pid),
        "nftfwd_idle_cpu_percent": round(idle_cpu, 4),
    }
    passed = (
        cli["p95_ms"] < CLI_BUDGET_MS
        and dashboard["p95_ms"] < DASHBOARD_BUDGET_MS
        and resources["nftfwd_rss_kib"] <= NFTFWD_RSS_BUDGET_KIB
        and resources["nftfwd_cgroup_memory_bytes"] <= NFTFWD_CGROUP_BUDGET_BYTES
        and resources["nftfw_web_rss_kib"] <= WEB_RSS_BUDGET_KIB
        and resources["nftfwd_idle_cpu_percent"] < IDLE_CPU_BUDGET_PERCENT
    )
    baseline: dict[str, Any] = {}
    if args.baseline_cli_p95_ms is not None:
        baseline["cli_p95_ms"] = args.baseline_cli_p95_ms
        baseline["cli_p95_improvement_percent"] = round(
            (args.baseline_cli_p95_ms - cli["p95_ms"])
            / args.baseline_cli_p95_ms
            * 100,
            2,
        )
    if args.baseline_dashboard_p95_ms is not None:
        baseline["dashboard_p95_ms"] = args.baseline_dashboard_p95_ms
        baseline["dashboard_p95_improvement_percent"] = round(
            (args.baseline_dashboard_p95_ms - dashboard["p95_ms"])
            / args.baseline_dashboard_p95_ms
            * 100,
            2,
        )
    result = {
        "schema": "nftfw.status-performance.v2",
        "status": "PASS" if passed else "FAIL",
        "environment": "disposable-virtual-machine",
        "virtualization": virtualization,
        "version": identity.get("version"),
        "commit": identity.get("commit"),
        "samples": args.samples,
        "warmups_each": args.warmups,
        "measurement_order": "separate-cli-then-persistent-http-batches",
        "cli_status": cli,
        "dashboard_status": dashboard,
        "component_profile": components,
        "resources": resources,
        "baseline": baseline,
        "budgets": {
            "cli_p95_ms_exclusive": CLI_BUDGET_MS,
            "dashboard_p95_ms_exclusive": DASHBOARD_BUDGET_MS,
            "nftfwd_rss_kib_inclusive": NFTFWD_RSS_BUDGET_KIB,
            "nftfwd_cgroup_memory_bytes_inclusive": NFTFWD_CGROUP_BUDGET_BYTES,
            "nftfw_web_rss_kib_inclusive": WEB_RSS_BUDGET_KIB,
            "nftfwd_idle_cpu_percent_exclusive": IDLE_CPU_BUDGET_PERCENT,
        },
        "sensitive_output_emitted": False,
        "live_host_changes_authorized": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
