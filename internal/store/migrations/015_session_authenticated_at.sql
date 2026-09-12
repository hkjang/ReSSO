-- When this session last proved who the user is, as opposed to when it began.
--
-- The two were the same fact until now, because the only way to prove who you
-- are was to start a session. Both the OIDC auth_time claim and a relying
-- party's max_age were therefore answered from created_at, which is correct
-- right up to the moment a session can re-prove itself without being replaced
-- — which is what confirming a password before a protected administrative
-- action is. Keeping a second timestamp beside created_at would leave the same
-- fact recorded twice and let the two drift, so there is one column and
-- everything that asks "how long ago did this person prove who they are" reads
-- it.
--
-- Backfilled from created_at rather than from now(): an upgrade must not hand
-- every session that happens to be open a fresh proof it never gave.
ALTER TABLE sso_sessions ADD COLUMN IF NOT EXISTS authenticated_at timestamptz;
UPDATE sso_sessions SET authenticated_at = created_at WHERE authenticated_at IS NULL;
ALTER TABLE sso_sessions ALTER COLUMN authenticated_at SET DEFAULT now();
ALTER TABLE sso_sessions ALTER COLUMN authenticated_at SET NOT NULL;
