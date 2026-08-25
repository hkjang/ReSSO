-- Group mappings can name Roles this Realm really has and still grant nothing,
-- because the directory returned no group membership at all: the memberOf
-- attribute is named wrong, or the overlay that produces it is not enabled —
-- it is not on by default in OpenLDAP. The run succeeds, the mappings look
-- correct, and nobody receives a Role. Counting how many of the users read
-- carried any membership is what separates "the mapping is wrong" from
-- "nothing to map against".
ALTER TABLE user_federations
    ADD COLUMN IF NOT EXISTS last_sync_group_memberships integer NOT NULL DEFAULT 0;
