-- Back-channel logout resolves the clients that participated in a session.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session ON refresh_tokens(session_id) WHERE session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_authorization_codes_session ON authorization_codes(session_id);

-- Expired refresh tokens whose session is still alive were never collected.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);

-- The optional trigram indexes for user search are not created here. They
-- depend on the pg_trgm extension, which only a database owner can install and
-- which must not be installed into an application schema by a migration. They
-- are created at startup instead, so enabling the extension later takes effect
-- on the next restart rather than requiring a new migration. See
-- Store.EnsureSearchIndexes.
