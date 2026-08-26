-- Which of a person's Roles came from the directory is asked by user and role,
-- without naming the provider — there is only one answer either way, and the
-- caller has the person in hand, not the provider. The only index on this
-- table is its primary key, which leads with the provider, so neither question
-- could use it.
--
-- Both run on the screen where an administrator edits somebody's roles: once
-- per Role listed to mark the ones the directory grants, and once per Role
-- again on save to decide which locally-granted rows may be removed. With ten
-- thousand federated accounts holding three Roles each, every one of those
-- questions read thirty thousand rows, and the ones that answer "no" had to
-- read all of them to say so.
CREATE INDEX IF NOT EXISTS idx_federation_assignment_user_role
    ON federation_role_assignments(user_id, role_id);
