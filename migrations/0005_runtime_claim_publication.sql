-- Documentation copy; internal/state embeds and executes this transactionally.
CREATE TABLE runtime_claim_publication (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  desired_revision INTEGER NOT NULL CHECK(desired_revision >= 0),
  applied_revision INTEGER NOT NULL CHECK(applied_revision >= 0),
  updated_at TEXT NOT NULL
);

INSERT INTO runtime_claim_publication(singleton, desired_revision, applied_revision, updated_at)
VALUES(1, 1, 0, datetime('now'));

INSERT INTO integration_state(name, status, entry_count, last_success, updated_at)
VALUES(
  'runtime/claims',
  'degraded',
  (SELECT COUNT(*) FROM claims
   WHERE expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  NULL,
  datetime('now')
)
ON CONFLICT(name) DO UPDATE SET
  status = 'degraded',
  entry_count = excluded.entry_count,
  updated_at = excluded.updated_at;
