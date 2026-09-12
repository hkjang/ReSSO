-- Settings that belong to the installation rather than to a Realm. The first
-- is the visitor tracking snippet: which collector the console reports to and
-- what the content security policy has to allow for it. It is a table rather
-- than an environment variable because the collector's address differs per
-- installation and changes while the service runs, and a setting that needs a
-- redeploy to change stays off.
--
-- One row per key, the value as a document, so a new setting is a new key and
-- not a new migration. No row means the default — for tracking, off — so an
-- upgrade changes nothing until an administrator saves the screen.
CREATE TABLE IF NOT EXISTS platform_settings (
    key text PRIMARY KEY,
    value jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL
);
