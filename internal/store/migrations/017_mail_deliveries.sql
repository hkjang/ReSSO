-- Every notification mail this service tries to send, one row per attempt at
-- one recipient. The record is what answers "it never arrived": without the
-- successes an administrator can only see what failed, and without the
-- failures they can only see what was accepted.
--
-- The body is not kept. Subject and recipient say what left the building;
-- the body would make this table a copy of every notification, readable by
-- anyone who can read the table.
CREATE TABLE IF NOT EXISTS mail_deliveries (
    id uuid PRIMARY KEY,
    event text NOT NULL,
    recipient text NOT NULL,
    subject text NOT NULL,
    -- What the mail was about, as an identifier the event owns: the approval
    -- request, the API key. Free text because the events differ in what they
    -- point at, and no foreign key because the record should outlive it.
    reference text NOT NULL DEFAULT '',
    actor_id uuid,
    status text NOT NULL,
    attempts int NOT NULL DEFAULT 0,
    error_message text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mail_deliveries_created ON mail_deliveries(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mail_deliveries_status ON mail_deliveries(status, created_at DESC);

-- When the owner of a personal API key was told it is about to expire. The
-- sweep that sends that warning runs every hour, and without this it would
-- send the same warning every hour for a week.
ALTER TABLE personal_api_keys ADD COLUMN IF NOT EXISTS expiry_notice_sent_at timestamptz;
