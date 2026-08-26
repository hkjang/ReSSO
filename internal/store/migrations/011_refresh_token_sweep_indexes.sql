-- Ending someone's sessions everywhere reads every refresh token in the
-- deployment. The sweep selects by user_id, which nothing indexed: with sixty
-- thousand tokens spread over two hundred accounts, finding one account's
-- three hundred meant reading the other fifty-nine thousand seven hundred and
-- taking a lock along the way.
--
-- That sweep is the emergency stop. It runs when an administrator disables an
-- account, when a password changes because someone believes it is known, and
-- once per account when a directory sync deactivates a batch of them — the
-- moments where it has to be quick and certain, and the table it walks is the
-- one that grows with every token ever issued.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);

-- And the rollback after a failed refresh asks whether the token it is about
-- to restore has a successor. Every one of those questions read the whole
-- table to answer "no". Partial because only a rotated successor carries a
-- parent, so the index stays a fraction of the rows.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_parent ON refresh_tokens(parent_id)
    WHERE parent_id IS NOT NULL;
