#!/usr/bin/env bash
set -Eeuo pipefail

for tool in sqlite3 truncate; do command -v "$tool" >/dev/null || { echo "BLOCKED: missing $tool"; exit 77; }; done
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
case "$(uname -m)" in
    x86_64) build_arch=amd64 ;;
    aarch64|arm64) build_arch=arm64 ;;
    *) echo "BLOCKED: unsupported architecture"; exit 77 ;;
esac
nftfw="$root_dir/dist/nftfw-linux-$build_arch"
[[ -x "$nftfw" ]] || { echo "BLOCKED: release CLI binary missing"; exit 77; }

lab_tmp=$(mktemp -d /tmp/nftfw-database.XXXXXX)
chmod 0700 "$lab_tmp"
cleanup() { if [[ "$lab_tmp" == /tmp/nftfw-database.* ]]; then rm -rf "$lab_tmp"; fi; }
trap cleanup EXIT

database="$lab_tmp/state.db"
backup="$lab_tmp/backup/state.db"
restored="$lab_tmp/restored.db"
"$nftfw" state verify --database "$database" >/dev/null
sqlite3 "$database" "INSERT INTO claims(address,family,source,reason,actor,created_at) VALUES('203.0.113.9/32','ipv4','manual','backup-test','acceptance',datetime('now'))"
"$nftfw" state backup "$backup" --database "$database" >/dev/null
[[ $(sqlite3 "$backup" 'SELECT COUNT(*) FROM claims') == 1 ]] || { echo "FAIL: consistent backup omitted state"; exit 1; }
install -o root -g root -m 0600 "$backup" "$restored"
"$nftfw" state verify --database "$restored" >/dev/null
[[ $(sqlite3 "$restored" 'SELECT COUNT(*) FROM claims') == 1 ]] || { echo "FAIL: restored copy omitted state"; exit 1; }
echo "DATABASE CREATE/BACKUP/OFFLINE RESTORE: PASS"

corrupt="$lab_tmp/corrupt.db"
install -o root -g root -m 0600 "$backup" "$corrupt"
truncate -s 128 "$corrupt"
if "$nftfw" state verify --database "$corrupt" >/dev/null 2>&1; then echo "FAIL: truncated database accepted"; exit 1; fi
if "$nftfw" state verify --database /proc/nftfw-state.db >/dev/null 2>&1; then echo "FAIL: unavailable database path accepted"; exit 1; fi
echo "DATABASE CORRUPT/UNAVAILABLE HANDLING: PASS"

legacy="$lab_tmp/legacy.db"
sqlite3 "$legacy" <<'SQL'
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE generations (
 id INTEGER PRIMARY KEY, checksum TEXT NOT NULL, script_path TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','applied','committed','rolled_back')),
 created_at TEXT NOT NULL, rollback_deadline TEXT,
 previous_id INTEGER REFERENCES generations(id)
);
CREATE INDEX generations_status_idx ON generations(status);
CREATE TABLE claims (
 id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL,
 family TEXT NOT NULL CHECK(family IN ('ipv4','ipv6')), source TEXT NOT NULL,
 reason TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT
);
CREATE INDEX claims_address_idx ON claims(address, family);
CREATE TABLE audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
 actor TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL
);
INSERT INTO schema_migrations VALUES(1, datetime('now'));
SQL
chmod 0600 "$legacy"
"$nftfw" state verify --database "$legacy" >/dev/null
[[ $(sqlite3 "$legacy" 'SELECT MAX(version) FROM schema_migrations') == 3 ]] || { echo "FAIL: legacy migration did not reach v3"; exit 1; }
[[ $(sqlite3 "$legacy" "SELECT COUNT(*) FROM pragma_table_info('generations') WHERE name='observed_hash'") == 1 ]] || { echo "FAIL: v3 fingerprint column missing"; exit 1; }
if sqlite3 "$legacy" "INSERT INTO claims(address,family,source,reason,actor,created_at) VALUES('bad','invalid','x','x','x','x')" >/dev/null 2>&1; then echo "FAIL: invalid claim family bypassed schema constraint"; exit 1; fi
echo "DATABASE V1-TO-V3 MIGRATION/CONSTRAINTS: PASS"
echo "DATABASE ACCEPTANCE: PASS"
