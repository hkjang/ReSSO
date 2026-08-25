-- A sync under the DISABLE policy deactivates the accounts that vanished from
-- the directory and ends their sessions. That is the consequential number of a
-- run, and it was recorded only in the audit trail: the provider row kept
-- added, updated and failed, and the console sends the administrator to those
-- fields to find out what a run did. So the one outcome worth checking after a
-- sync was the one the screen could not show.
ALTER TABLE user_federations ADD COLUMN IF NOT EXISTS last_sync_disabled integer NOT NULL DEFAULT 0;
