#!/usr/bin/env python3
"""Boot a disposable GRUB guest with a contradictory disabled-IPv6 identity."""

from __future__ import annotations

import json
import os
import selectors
import socket
import stat
import sys
import time


def safe_socket(path: str) -> None:
    information = os.lstat(path)
    if not stat.S_ISSOCK(information.st_mode):
        raise SystemExit("unsafe disposable control socket")


def receive_line(connection: socket.socket) -> dict[str, object]:
    data = b""
    while not data.endswith(b"\n"):
        chunk = connection.recv(65536)
        if not chunk:
            raise RuntimeError("QMP connection closed")
        data += chunk
        if len(data) > 1 << 20:
            raise RuntimeError("oversized QMP response")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise RuntimeError("invalid QMP response")
    return result


def qmp_command(connection: socket.socket, command: str) -> None:
    request = json.dumps(
        {"execute": command}, separators=(",", ":"), sort_keys=True
    ).encode("ascii") + b"\n"
    connection.sendall(request)
    while "return" not in receive_line(connection):
        pass


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: managed_boot_grub_conflict.py SERIAL_SOCKET QMP_SOCKET OUTPUT"
        )
    serial_path, qmp_path, output_path = sys.argv[1:]
    for path in (serial_path, qmp_path, output_path):
        if not os.path.isabs(path) or os.path.normpath(path) != path:
            raise SystemExit("disposable evidence paths must be absolute and canonical")
    safe_socket(serial_path)
    safe_socket(qmp_path)

    output_descriptor = os.open(
        output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as serial_connection, \
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as qmp_connection:
            serial_connection.connect(serial_path)
            serial_connection.setblocking(False)
            qmp_connection.settimeout(5)
            qmp_connection.connect(qmp_path)
            if "QMP" not in receive_line(qmp_connection):
                raise RuntimeError("invalid QMP greeting")
            qmp_command(qmp_connection, "qmp_capabilities")
            qmp_command(qmp_connection, "system_reset")
            qmp_command(qmp_connection, "cont")

            selector = selectors.DefaultSelector()
            selector.register(serial_connection, selectors.EVENT_READ)
            observed = b""
            menu_selected = False
            conflicting_boot = False
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                for key, _ in selector.select(timeout=0.05):
                    data = key.fileobj.recv(65536)
                    if not data:
                        raise RuntimeError("serial console closed")
                    os.write(output_descriptor, data)
                    observed = (observed + data)[-65536:]
                if not menu_selected and b"automatically in 5s" in observed:
                    serial_connection.sendall(b"e")
                    menu_selected = True
                    observed = b""
                if (
                    menu_selected
                    and not conflicting_boot
                    and b"Minimum Emacs-like" in observed
                ):
                    time.sleep(3)
                    # The Debian entry has nine logical lines before its Linux
                    # command. Preserve a final disable while deliberately
                    # making the identity contradictory; the native verifier
                    # must block and the pre-driver kernel state must emit no
                    # frame. The serial console token is diagnostic-only.
                    edit = (
                        (b"\x0e" * 9)
                        + b"\x05 ipv6.disable=0 ipv6.disable=1 console=ttyS0"
                    )
                    for key_byte in edit:
                        serial_connection.sendall(bytes((key_byte,)))
                        time.sleep(0.2)
                    time.sleep(2)
                    serial_connection.sendall(b"\x18")
                    conflicting_boot = True
                    deadline = time.monotonic() + 35
            if not menu_selected:
                raise RuntimeError("GRUB menu was not observed")
            if not conflicting_boot:
                raise RuntimeError("GRUB editor was not observed")
        os.fsync(output_descriptor)
    finally:
        os.close(output_descriptor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
