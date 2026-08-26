-- The console's session screen asks for a Realm's sessions, newest use first,
-- and takes the first five hundred. Nothing indexed that pair, so answering it
-- meant reading every session in the Realm and sorting them to keep five
-- hundred: fifty thousand rows read to return five hundred, and the wait grows
-- with the Realm rather than with the answer.
--
-- That screen is where an administrator goes during an incident — to see who
-- is signed in and to end a session — so it is the one that must not get
-- slower as the deployment gets busier.
CREATE INDEX IF NOT EXISTS idx_sessions_realm_recent ON sso_sessions(realm_id, last_access DESC);
