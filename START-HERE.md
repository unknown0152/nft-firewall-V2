# Start Here

1. Read `SECURITY.md` and `docs/THREAT-MODEL.md`.
2. Build with `make release VERSION=2.0.0`.
3. Run `sudo ./scripts/install.sh`.
4. Edit `/etc/nftfw/nftfw.toml`; replace every example address/interface.
5. Run `sudo nftfw config validate` and inspect `sudo nftfw plan`.
6. Ensure `nftfw-rollback.timer` is active before the first apply.
7. Run `sudo nftfw apply --safe`, perform management-path checks, then commit
   the returned generation with `sudo nftfw commit <generation>`.

Do not use the example policy unchanged on a real host. It uses documentation
addresses and cannot establish a production tunnel.
