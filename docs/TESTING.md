# Testing

`go test ./...`, race detection, and vet are unprivileged gates. Tests cover
strict configuration, default-deny/compiler invariants, nft ownership, socket
protocol, SQLite migration/corruption, claim provenance, explanation, and
feed parsing.

`sudo tests/namespaces/run.sh` creates four isolated namespaces and a real
WireGuard tunnel. It proves host/container reachability while healthy, removes
the tunnel, captures the physical test link, and requires the result
`LEAKED INTERNET PACKETS: 0`. Exit code `77` means the host lacks a required
capability/tool and is reported as `BLOCKED`, never `PASS`.

Real external WireGuard acceptance requires
`../test-data/wg-test.conf`. Private key material must remain mode `0600` and
is never printed or archived.
