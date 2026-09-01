#!/usr/bin/env python3
"""Validate that a disposable guest emits no frame before NFTFW readiness."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import struct


MAX_CAPTURE = 64 << 20
MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
FORMATS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def read_regular(path: str, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > limit:
            raise ValueError("unsafe or empty evidence file")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1 << 20, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(data) != before.st_size or len(data) > limit or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("evidence file changed during read")
        return data
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture")
    parser.add_argument("marker_epoch", nargs="?")
    parser.add_argument("--guest-mac", default="52:54:00:12:34:56")
    parser.add_argument("--clock-offset-seconds", type=int, default=0)
    parser.add_argument("--expect-zero-guest", action="store_true")
    arguments = parser.parse_args()
    mac_text = arguments.guest_mac.lower()
    if not MAC.fullmatch(mac_text) or abs(arguments.clock_offset_seconds) > 86_400:
        raise SystemExit("invalid capture identity")
    if arguments.expect_zero_guest:
        if arguments.marker_epoch is not None:
            raise SystemExit("zero-frame validation does not accept a readiness marker")
        marker_raw = ""
        marker = 0.0
    else:
        if arguments.marker_epoch is None:
            raise SystemExit("successful boot validation requires a readiness marker")
        marker_raw = read_regular(arguments.marker_epoch, 128).decode("ascii").strip()
        if not re.fullmatch(r"[0-9]{10,20}\.[0-9]{1,9}", marker_raw):
            raise SystemExit("invalid readiness marker")
        marker = float(marker_raw)
    data = read_regular(arguments.capture, MAX_CAPTURE)
    if len(data) < 24 or data[:4] not in FORMATS:
        raise SystemExit("invalid pcap header")
    endian, scale = FORMATS[data[:4]]
    guest_mac = bytes.fromhex(mac_text.replace(":", ""))
    offset = 24
    total_frames = 0
    guest_times: list[float] = []
    while offset < len(data):
        if offset + 16 > len(data):
            raise SystemExit("truncated pcap record")
        seconds, fraction, included, original = struct.unpack_from(
            endian + "IIII", data, offset
        )
        offset += 16
        if included > original or included > 1 << 20 or offset + included > len(data):
            raise SystemExit("invalid pcap record")
        packet = data[offset : offset + included]
        offset += included
        total_frames += 1
        if len(packet) >= 14 and packet[6:12] == guest_mac:
            guest_times.append(
                seconds + fraction / scale + arguments.clock_offset_seconds
            )
    if arguments.expect_zero_guest:
        if guest_times:
            raise SystemExit("failed boot identity emitted a guest frame")
        print(
            json.dumps(
                {
                    "schema": "nftfw.amendment-x-boot-pcap.v1",
                    "status": "PASS",
                    "expected_guest_frames": 0,
                    "guest_frames": 0,
                    "total_frames": total_frames,
                },
                sort_keys=True,
            )
        )
        return 0
    if not guest_times:
        raise SystemExit("successful boot emitted no guest frame")
    first = guest_times[0]
    if first <= marker:
        raise SystemExit("guest frame preceded NFTFW initramfs readiness")
    print(
        json.dumps(
            {
                "schema": "nftfw.amendment-x-boot-pcap.v1",
                "status": "PASS",
                "clock_offset_seconds": arguments.clock_offset_seconds,
                "marker_epoch": marker_raw,
                "first_guest_epoch": f"{first:.9f}",
                "first_guest_delta_seconds": round(first - marker, 6),
                "guest_frames": len(guest_times),
                "total_frames": total_frames,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
