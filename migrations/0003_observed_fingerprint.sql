-- Documentation copy; internal/state embeds and executes this transactionally.
ALTER TABLE generations ADD COLUMN observed_hash TEXT NOT NULL DEFAULT '';
