-- Documentation copy of the migration embedded in internal/state/store.go.
-- The binary executes the embedded form transactionally at startup.
CREATE TABLE generations (
  id INTEGER PRIMARY KEY,
  checksum TEXT NOT NULL,
  script_path TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','applied','committed','rolled_back')),
  created_at TEXT NOT NULL,
  rollback_deadline TEXT,
  previous_id INTEGER REFERENCES generations(id)
);
CREATE TABLE claims (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  address TEXT NOT NULL,
  family TEXT NOT NULL CHECK(family IN ('ipv4','ipv6')),
  source TEXT NOT NULL,
  reason TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT
);
CREATE TABLE audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  actor TEXT NOT NULL,
  event TEXT NOT NULL,
  detail TEXT NOT NULL
);
