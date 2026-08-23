-- Documentation copy; internal/state embeds and executes this transactionally.
DELETE FROM audit
WHERE id < COALESCE((SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET 9999), 0);

CREATE TRIGGER audit_prune_after_insert
AFTER INSERT ON audit
BEGIN
  DELETE FROM audit WHERE id <= NEW.id - 10000;
END;
