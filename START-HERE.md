# Start Here

NFT Firewall V2 2.1.0 adds the supported clean-server path:

```bash
sudo apt install "./nft-firewall-v2_2.1.0_$(dpkg --print-architecture).deb"
sudo nftfw setup --vpn /path/to/working-vpn.conf
```

Read these in order:

1. `SUPPORTED-PLATFORMS.md`
2. `VPN-PROFILES.md`
3. `QUICKSTART.md`
4. `docs/RECOVERY.md`

The package is nonactivating. Setup defaults to VPN-only IPv4, disabled IPv6,
preserved private-LAN SSH management, and no public inbound exposure.

The current source is still within Stage E-R until disposable privileged R2,
tagging, and publication gates pass. Candidate artifacts labeled
`RELEASE-CANDIDATE-NOT-DEPLOYABLE` cannot run or install.

Existing NFTFW, Docker, Cosmos, and application hosts must use the upgrade or
adoption workflow. Do not erase state or disable another firewall owner to
force the clean-host path.
