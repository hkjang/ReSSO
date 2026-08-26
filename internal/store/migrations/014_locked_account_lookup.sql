-- The dashboard counts locked accounts on every load, and the users screen
-- lists them when an administrator follows that number. Both ask for accounts
-- whose lock has not yet run out, which almost none of them are, and nothing
-- indexed it: fifty thousand rows read to count three.
--
-- Partial on the column being set at all, because "still locked" is a
-- comparison against the clock and cannot live in an index predicate. Locking
-- is rare and temporary, so the index stays a handful of rows however many
-- accounts the realm holds.
CREATE INDEX IF NOT EXISTS idx_users_locked ON users(realm_id, locked_until)
    WHERE locked_until IS NOT NULL;
