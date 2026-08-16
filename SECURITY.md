# Security Policy and Operational Guarantees

Report vulnerabilities privately to the repository owner. Do not include live
keys, credentials, public IP inventories, or packet captures with user data.

Core guarantees are enforced in code and tests:

- input and forwarding are default deny;
- strict output permits Internet egress only on the declared WireGuard device;
- physical bootstrap is constrained by interface, mark, endpoint set, UDP port;
- container-to-physical forwarding is dropped before conntrack acceptance;
- IPv6 mode is explicit and disabled mode drops at priority `-300`;
- only named NFT Firewall tables are replaced;
- safe apply persists rollback intent before kernel mutation;
- claims retain independent provenance and expiry;
- privileged requests use root peer credentials, not JSON identity fields;
- external feeds are HTTPS-only, bounded, and strictly parsed;
- no code invokes a shell string for firewall/runtime operations.

The current implementation cannot protect against kernel compromise, a root
attacker, malicious firmware, or an operator who disables/stops both rollback
paths. Docker socket access is intentionally absent from the dashboard.
