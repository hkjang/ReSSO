ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified boolean NOT NULL DEFAULT false;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_realm_id_email_key;
DROP INDEX IF EXISTS idx_users_realm_email_ci;
CREATE UNIQUE INDEX idx_users_realm_email_ci ON users(realm_id, lower(email)) WHERE email <> '';

ALTER TABLE clients ALTER COLUMN default_scopes SET DEFAULT '{openid,profile,email,roles}';
UPDATE clients SET default_scopes=array_append(default_scopes,'roles')
WHERE NOT ('roles'=ANY(default_scopes));

CREATE TABLE IF NOT EXISTS login_rate_limits (
    bucket_hash bytea PRIMARY KEY,
    window_started_at timestamptz NOT NULL,
    attempts integer NOT NULL CHECK (attempts > 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_login_rate_limits_updated ON login_rate_limits(updated_at);

CREATE INDEX IF NOT EXISTS idx_user_roles_role_user ON user_roles(role_id, user_id);
CREATE INDEX IF NOT EXISTS idx_user_client_roles_role_user ON user_client_roles(client_role_id, user_id);
