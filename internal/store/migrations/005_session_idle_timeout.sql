-- Sessions expired only on their absolute lifetime, so one left open on a
-- shared machine stayed valid for the whole Realm TTL regardless of activity.
-- Zero keeps the previous behaviour, so an upgrade changes nothing until an
-- administrator sets a value.
ALTER TABLE realms ADD COLUMN IF NOT EXISTS idle_timeout_seconds integer NOT NULL DEFAULT 0;

ALTER TABLE realms DROP CONSTRAINT IF EXISTS realms_idle_timeout_seconds_check;
ALTER TABLE realms ADD CONSTRAINT realms_idle_timeout_seconds_check
    CHECK (idle_timeout_seconds = 0 OR idle_timeout_seconds BETWEEN 300 AND 2592000);

-- Idle checks read last_access for a session that is otherwise live.
CREATE INDEX IF NOT EXISTS idx_sessions_last_access ON sso_sessions(last_access) WHERE revoked_at IS NULL;
