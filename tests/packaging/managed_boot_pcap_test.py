#!/usr/bin/env python3
"""Unprivileged regressions for the Amendment X pcap boundary validator."""

from __future__ import annotations

import json
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("managed_boot_pcap.py")
GUEST = bytes.fromhex("525400123456")


def frame(source: bytes = GUEST) -> bytes:
    return bytes.fromhex("525400abcdef") + source + bytes.fromhex("0800") + b"payload"


def pcap(records: list[tuple[int, int, bytes]]) -> bytes:
    result = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for seconds, microseconds, packet in records:
        result.extend(struct.pack("<IIII", seconds, microseconds, len(packet), len(packet)))
        result.extend(packet)
    return bytes(result)


class ManagedBootPcapTests(unittest.TestCase):
    def run_case(self, raw: bytes, marker: str = "4000000000.000000000") -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "boot.pcap"
            marker_path = root / "marker"
            capture.write_bytes(raw)
            marker_path.write_text(marker + "\n", encoding="ascii")
            return subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(capture),
                    str(marker_path),
                    "--clock-offset-seconds",
                    "3600",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

    def run_zero_case(self, raw: bytes) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            capture = pathlib.Path(directory) / "boot.pcap"
            capture.write_bytes(raw)
            return subprocess.run(
                [sys.executable, str(SCRIPT), str(capture), "--expect-zero-guest"],
                check=False,
                capture_output=True,
                text=True,
            )

    def test_first_guest_frame_after_marker_passes(self) -> None:
        result = self.run_case(
            pcap([(3_999_996_400, 500_000, frame()), (3_999_996_401, 0, frame())])
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual(record["status"], "PASS")
        self.assertEqual(record["first_guest_delta_seconds"], 0.5)

    def test_first_guest_frame_before_marker_fails(self) -> None:
        result = self.run_case(pcap([(3_999_996_399, 999_999, frame())]))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("preceded NFTFW initramfs readiness", result.stderr)

    def test_no_guest_and_truncated_capture_fail(self) -> None:
        no_guest = self.run_case(
            pcap([(3_999_996_401, 0, frame(bytes.fromhex("525400654321")))])
        )
        self.assertNotEqual(no_guest.returncode, 0)
        self.assertIn("no guest frame", no_guest.stderr)
        truncated = self.run_case(pcap([(3_999_996_401, 0, frame())])[:-1])
        self.assertNotEqual(truncated.returncode, 0)
        self.assertIn("invalid pcap record", truncated.stderr)

    def test_failed_identity_zero_guest_mode(self) -> None:
        result = self.run_zero_case(
            pcap([(4_000_000_000, 0, frame(bytes.fromhex("525400654321")))])
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual(record["expected_guest_frames"], 0)
        self.assertEqual(record["guest_frames"], 0)
        emitted = self.run_zero_case(pcap([(4_000_000_000, 0, frame())]))
        self.assertNotEqual(emitted.returncode, 0)
        self.assertIn("failed boot identity emitted a guest frame", emitted.stderr)

    def test_zero_guest_mode_rejects_marker_argument(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            capture = root / "boot.pcap"
            marker = root / "marker"
            capture.write_bytes(pcap([]))
            marker.write_text("4000000000.000000000\n", encoding="ascii")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(capture),
                    str(marker),
                    "--expect-zero-guest",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not accept a readiness marker", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
