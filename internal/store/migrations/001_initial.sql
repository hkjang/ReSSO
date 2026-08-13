CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS realms (
    id uuid PRIMARY KEY,
    name varchar(63) NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    display_name varchar(120) NOT NULL,
    issuer_url varchar(512) NOT NULL UNIQUE,
    enabled boolean NOT NULL DEFAULT true,
    approval_enabled boolean NOT NULL DEFAULT false,
    access_token_ttl_seconds integer NOT NULL DEFAULT 300 CHECK (access_token_ttl_seconds BETWEEN 60 AND 3600),
    refresh_token_ttl_seconds integer NOT NULL DEFAULT 1800 CHECK (refresh_token_ttl_seconds BETWEEN 300 AND 2592000),
    session_ttl_seconds integer NOT NULL DEFAULT 28800 CHECK (session_ttl_seconds BETWEEN 300 AND 2592000),
    password_min_length integer NOT NULL DEFAULT 12 CHECK (password_min_length BETWEEN 8 AND 128),
    max_login_attempts integer NOT NULL DEFAULT 5 CHECK (max_login_attempts BETWEEN 3 AND 50),
    lockout_seconds integer NOT NULL DEFAULT 900 CHECK (lockout_seconds BETWEEN 30 AND 86400),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY,
    realm_id uuid NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    username varchar(128) NOT NULL,
    email varchar(320) NOT NULL DEFAULT '',
    display_name varchar(160) NOT NULL DEFAULT '',
    password_hash text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    platform_admin boolean NOT NULL DEFAULT false,
    manager_id uuid REFERENCES users(id) ON DELETE SET NULL,
    failed_attempts integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(realm_id, username),
    UNIQUE(realm_id, email)
);
CREATE INDEX IF NOT EXISTS idx_users_realm_search ON users(realm_id, lower(username), lower(email));

CREATE TABLE IF NOT EXISTS roles (
    id uuid PRIMARY KEY,
    realm_id uuid NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name varchar(128) NOT NULL,
    description varchar(512) NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(realm_id, name)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(user_id, role_id)
);

CREATE TABLE IF NOT EXISTS clients (
    id uuid PRIMARY KEY,
    realm_id uuid NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id varchar(255) NOT NULL,
    name varchar(160) NOT NULL,
    type varchar(20) NOT NULL CHECK (type IN ('public', 'confidential')),
    secret_hash text,
    redirect_uris text[] NOT NULL DEFAULT '{}',
    post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
    web_origins text[] NOT NULL DEFAULT '{}',
    grant_types text[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
    default_scopes text[] NOT NULL DEFAULT '{openid,profile,email}',
    require_pkce boolean NOT NULL DEFAULT true,
    enabled boolean NOT NULL DEFAULT true,
    access_token_ttl_seconds integer NOT NULL DEFAULT 300 CHECK (access_token_ttl_seconds BETWEEN 60 AND 3600),
    refresh_token_ttl_seconds integer NOT NULL DEFAULT 1800 CHECK (refresh_token_ttl_seconds BETWEEN 300 AND 2592000),
    backchannel_logout_uri varchar(1024) NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(realm_id, client_id)
);

CREATE TABLE IF NOT EXISTS client_roles (
    id uuid PRIMARY KEY,
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name varchar(128) NOT NULL,
    description varchar(512) NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(client_id, name)
);

CREATE TABLE IF NOT EXISTS user_client_roles (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_role_id uuid NOT NULL REFERENCES client_roles(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(user_id, client_role_id)
);

CREATE TABLE IF NOT EXISTS signing_keys (
    id uuid PRIMARY KEY,
    realm_id uuid NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    kid varchar(128) NOT NULL,
    algorithm varchar(16) NOT NULL DEFAULT 'RS256',
    status varchar(16) NOT NULL CHECK (status IN ('ACTIVE', 'PASSIVE', 'RETIRED')),
    private_key_cipher bytea NOT NULL,
    public_jwk jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    retire_at timestamptz,
    UNIQUE(realm_id, kid)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_signing_keys_one_active ON signing_keys(realm_id) WHERE status = 'ACTIVE';

CREATE TABLE IF NOT EXISTS sso_sessions (
    id uuid PRIMARY KEY,
    realm_id uuid NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    csrf_hash bytea NOT NULL,
    ip_address varchar(64) NOT NULL DEFAULT '',
    user_agent varchar(1024) NOT NULL DEFAULT '',
    auth_method varchar(64) NOT NULL DEFAULT 'password',
    created_at timestamptz NOT NULL DEFAULT now(),
    last_access timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sso_sessions(user_id, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON sso_sessions(expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS authorization_requests (
    id uuid PRIMARY KEY,
    token_hash bytea NOT NULL UNIQUE,
    realm_id uuid NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    redirect_uri varchar(2048) NOT NULL,
    response_type varchar(32) NOT NULL,
    scope text[] NOT NULL,
    state text NOT NULL DEFAULT '',
    nonce text NOT NULL DEFAULT '',
    code_challenge varchar(128) NOT NULL DEFAULT '',
    code_challenge_method varchar(16) NOT NULL DEFAULT '',
    prompt varchar(64) NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

CREATE TABLE IF NOT EXISTS authorization_codes (
    id uuid PRIMARY KEY,
    code_hash bytea NOT NULL UNIQUE,
    realm_id uuid NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id uuid NOT NULL REFERENCES sso_sessions(id) ON DELETE CASCADE,
    redirect_uri varchar(2048) NOT NULL,
    scope text[] NOT NULL,
    nonce text NOT NULL DEFAULT '',
    code_challenge varchar(128) NOT NULL DEFAULT '',
    code_challenge_method varchar(16) NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id uuid PRIMARY KEY,
    token_hash bytea NOT NULL UNIQUE,
    family_id uuid NOT NULL,
    parent_id uuid REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    realm_id uuid NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    session_id uuid REFERENCES sso_sessions(id) ON DELETE CASCADE,
    scope text[] NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    rotated_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);

CREATE TABLE IF NOT EXISTS revoked_access_tokens (
    jti uuid PRIMARY KEY,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS personal_api_keys (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name varchar(120) NOT NULL,
    prefix varchar(24) NOT NULL UNIQUE,
    secret_hash bytea NOT NULL,
    scopes text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz,
    rotated_from uuid REFERENCES personal_api_keys(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON personal_api_keys(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
    id bigserial PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    realm_id uuid REFERENCES realms(id) ON DELETE SET NULL,
    actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
    actor_name varchar(128) NOT NULL DEFAULT '',
    event_type varchar(80) NOT NULL,
    result varchar(24) NOT NULL,
    target_type varchar(80) NOT NULL DEFAULT '',
    target_id varchar(160) NOT NULL DEFAULT '',
    ip_address varchar(64) NOT NULL DEFAULT '',
    user_agent varchar(1024) NOT NULL DEFAULT '',
    trace_id varchar(64) NOT NULL DEFAULT '',
    detail jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_occurred ON audit_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_realm_event ON audit_events(realm_id, event_type, occurred_at DESC);

CREATE TABLE IF NOT EXISTS system_logs (
    id bigserial PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    level varchar(16) NOT NULL,
    component varchar(80) NOT NULL,
    message text NOT NULL,
    trace_id varchar(64) NOT NULL DEFAULT '',
    attributes jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_system_logs_occurred ON system_logs(occurred_at DESC);

CREATE TABLE IF NOT EXISTS approval_requests (
    id uuid PRIMARY KEY,
    realm_id uuid NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    requester_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reviewer_id uuid REFERENCES users(id) ON DELETE SET NULL,
    kind varchar(64) NOT NULL CHECK (kind IN ('ROLE_ASSIGNMENT', 'CLIENT_REGISTRATION', 'API_KEY_SCOPE')),
    payload jsonb NOT NULL,
    reason varchar(1000) NOT NULL DEFAULT '',
    status varchar(24) NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED')),
    decision_note varchar(1000) NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    decided_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_approvals_realm_status ON approval_requests(realm_id, status, created_at DESC);
