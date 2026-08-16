#!/usr/bin/env python3
"""Minimal direct-socket probe for the namespace DNAT acceptance test."""

import argparse
import pathlib
import socket


def server(address: str, port: int, ready: pathlib.Path) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, port))
        listener.listen(1)
        ready.touch()
        listener.settimeout(5)
        peer, _ = listener.accept()
        with peer:
            peer.settimeout(5)
            if peer.recv(32) != b"nftfw-dnat-probe":
                raise RuntimeError("unexpected DNAT probe payload")
            peer.sendall(b"nftfw-dnat-ok")


def client(address: str, port: int) -> None:
    with socket.create_connection((address, port), timeout=5) as connection:
        connection.sendall(b"nftfw-dnat-probe")
        if connection.recv(32) != b"nftfw-dnat-ok":
            raise RuntimeError("DNAT reply was not received")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("address")
    parser.add_argument("port", type=int)
    parser.add_argument("ready", type=pathlib.Path, nargs="?")
    args = parser.parse_args()
    if args.mode == "server":
        if args.ready is None:
            parser.error("server mode requires a ready marker")
        server(args.address, args.port, args.ready)
    else:
        client(args.address, args.port)


if __name__ == "__main__":
    main()
