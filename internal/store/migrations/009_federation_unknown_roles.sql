-- A group is mapped to a Role by typing its name. A name this Realm does not
-- have — a typo, or a Role deleted after the mapping was made — resolves to
-- nothing: the rule stays in the configuration, the people in that group never
-- receive the Role, and every run reports success. The run knows which names
-- failed to resolve; keeping them on the provider puts that where the console
-- sends an administrator to see what a run did, and a scheduled run has no
-- caller to hand its summary to.
ALTER TABLE user_federations
    ADD COLUMN IF NOT EXISTS last_sync_unknown_roles text[] NOT NULL DEFAULT '{}';
