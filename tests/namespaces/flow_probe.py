#!/usr/bin/env python3
"""Synthetic active-flow probe used only by the isolated namespace lab."""

import argparse
import pathlib
import socket
import sys
import time


def wait_for(path: pathlib.Path, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {path}")


def server(args: argparse.Namespace) -> int:
    kind = socket.SOCK_STREAM if args.protocol == "tcp" else socket.SOCK_DGRAM
    family = socket.AF_INET6 if ":" in args.address else socket.AF_INET
    sock = socket.socket(family, kind)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.address, args.port))
    peers: list[socket.socket] = []
    if args.protocol == "tcp":
        sock.listen(args.count)
    args.bound.touch()
    if args.protocol == "tcp":
        for _ in range(args.count):
            peer, _ = sock.accept()
            peers.append(peer)
            if peer.recv(64) != b"before":
                return 2
    else:
        for _ in range(args.count):
            data, _ = sock.recvfrom(64)
            if data != b"before":
                return 2
    args.ready.touch()
    wait_for(args.trigger)
    sock.settimeout(2.0)
    try:
        if args.protocol == "tcp":
            for peer in peers:
                peer.settimeout(2.0)
                if peer.recv(64) == b"after":
                    print("active TCP payload reached the physical endpoint", file=sys.stderr)
                    return 1
        else:
            data, _ = sock.recvfrom(64)
            if data == b"after":
                print("active UDP payload reached the physical endpoint", file=sys.stderr)
                return 1
    except TimeoutError:
        pass
    finally:
        for peer in peers:
            peer.close()
        sock.close()
    return 0


def client(args: argparse.Namespace) -> int:
    kind = socket.SOCK_STREAM if args.protocol == "tcp" else socket.SOCK_DGRAM
    family = socket.AF_INET6 if ":" in args.address else socket.AF_INET
    sock = socket.socket(family, kind)
    sock.settimeout(4.0)
    sock.connect((args.address, args.port))
    sock.sendall(b"before")
    args.ready.touch()
    wait_for(args.trigger)
    try:
        sock.sendall(b"after")
    except OSError:
        pass
    time.sleep(1.0)
    sock.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("protocol", choices=("tcp", "udp"))
    parser.add_argument("address")
    parser.add_argument("port", type=int)
    parser.add_argument("ready", type=pathlib.Path)
    parser.add_argument("trigger", type=pathlib.Path)
    parser.add_argument("--bound", type=pathlib.Path, default=pathlib.Path("/tmp/nftfw-flow-bound"))
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()
    try:
        return server(args) if args.mode == "server" else client(args)
    except (OSError, TimeoutError) as exc:
        print(f"flow probe failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
