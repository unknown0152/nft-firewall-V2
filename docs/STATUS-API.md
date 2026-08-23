# Status API contract

`nftfw status --json`, the read-only status socket, and `/api/status` expose
the versioned `nftfw.status.v1` schema. Security decisions must use the typed
fields in this contract; string truthiness and missing-field defaults are not
valid interpretations.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Exactly `nftfw.status.v1` for this contract |
| `version` | string | Build-injected NFT Firewall release version |
| `status` | string | Overall `HEALTHY` or `DEGRADED`, including integrations and WireGuard |
| `active` | boolean | An applied/committed generation exists and every owned table is structurally intact |
| `policy_match` | boolean | The canonical owned-kernel fingerprint matches the expected generation |
| `kill_switch_enforced` | boolean | Conservative machine-readable enforcement result; false on missing, damaged, or mismatched policy |
| `kill_switch` | string | Human-readable compatibility value, `enforced` or `degraded` |
| `policy_hash` | string | SHA-256 identity of the expected policy generation |
| `policy_checksum` | string | Compatibility alias of `policy_hash` |
| `claims_desired_revision` | non-negative integer | Durable revision of the latest intended runtime claim set |
| `claims_applied_revision` | non-negative integer | Last runtime claim revision confirmed in the kernel; health is degraded unless it equals `claims_desired_revision` |
| `protected` | boolean | Built-in `/api/status` proxy only: independently derived fail-closed display decision |

An external dashboard may display **Protected** only when all of these checks
pass:

```text
schema == "nftfw.status.v1"
status == "HEALTHY"
active == true
policy_match == true
kill_switch_enforced == true
policy_hash and policy_checksum are both present, each is a 64-character
lowercase hexadecimal SHA-256 value, and they are identical
```

Unknown schemas, absent fields, type mismatches, CLI errors, timeouts, and
malformed JSON are `Unavailable` or `Degraded`; they never fall back to a
protected state. Desired/static flow descriptions are not observations and
must not be substituted for live counters or flow data.

The built-in web proxy computes and overwrites `protected`; it never trusts a
value supplied by the daemon. Its browser code requires that boolean as well
as independently checking the typed fields and hash identities above.

`status` may be `DEGRADED` while the three policy booleans remain true, for
example when a threat feed is temporarily unavailable but its last known-good
claims and the verified kernel policy remain installed. This distinction lets
operators diagnose the subsystem without weakening the overall health gate.
