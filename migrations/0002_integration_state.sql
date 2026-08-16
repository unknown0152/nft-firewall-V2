-- Documentation copy; internal/state embeds and executes this transactionally.
CREATE TABLE integration_state (
  name TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  entry_count INTEGER NOT NULL CHECK(entry_count >= 0),
  last_success TEXT,
  updated_at TEXT NOT NULL
);
