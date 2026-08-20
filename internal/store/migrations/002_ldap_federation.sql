CREATE TABLE IF NOT EXISTS user_federations (
    id uuid PRIMARY KEY,
    realm_id uuid NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name varchar(120) NOT NULL,
    vendor varchar(24) NOT NULL CHECK (vendor IN ('OTHER', 'AD')),
    priority integer NOT NULL DEFAULT 0 CHECK (priority BETWEEN 0 AND 1000),
    enabled boolean NOT NULL DEFAULT true,
    connection_url varchar(1024) NOT NULL,
    start_tls boolean NOT NULL DEFAULT false,
    ca_certificate text NOT NULL DEFAULT '',
    bind_dn varchar(1024) NOT NULL DEFAULT '',
    bind_credential_cipher bytea,
    users_dn varchar(1024) NOT NULL,
    username_ldap_attribute varchar(128) NOT NULL,
    rdn_ldap_attribute varchar(128) NOT NULL,
    uuid_ldap_attribute varchar(128) NOT NULL,
    user_object_classes text[] NOT NULL,
    user_ldap_filter varchar(2048) NOT NULL DEFAULT '',
    search_scope varchar(24) NOT NULL DEFAULT 'SUBTREE' CHECK (search_scope IN ('ONE_LEVEL', 'SUBTREE')),
    email_ldap_attribute varchar(128) NOT NULL DEFAULT 'mail',
    first_name_ldap_attribute varchar(128) NOT NULL DEFAULT 'givenName',
    last_name_ldap_attribute varchar(128) NOT NULL DEFAULT 'sn',
    display_name_ldap_attribute varchar(128) NOT NULL DEFAULT 'displayName',
    member_of_ldap_attribute varchar(128) NOT NULL DEFAULT 'memberOf',
    group_role_mappings jsonb NOT NULL DEFAULT '{}',
    import_enabled boolean NOT NULL DEFAULT true,
    sync_registrations boolean NOT NULL DEFAULT true,
    missing_user_action varchar(24) NOT NULL DEFAULT 'KEEP' CHECK (missing_user_action IN ('KEEP', 'DISABLE')),
    edit_mode varchar(24) NOT NULL DEFAULT 'READ_ONLY' CHECK (edit_mode IN ('READ_ONLY', 'WRITABLE', 'UNSYNCED')),
    batch_size integer NOT NULL DEFAULT 500 CHECK (batch_size BETWEEN 50 AND 5000),
    sync_period_seconds integer NOT NULL DEFAULT 0 CHECK (sync_period_seconds = 0 OR sync_period_seconds BETWEEN 300 AND 604800),
    next_sync_at timestamptz,
    last_sync_at timestamptz,
    last_sync_status varchar(24) NOT NULL DEFAULT 'NEVER' CHECK (last_sync_status IN ('NEVER', 'RUNNING', 'SUCCESS', 'FAILURE')),
    last_sync_error varchar(1000) NOT NULL DEFAULT '',
    last_sync_added integer NOT NULL DEFAULT 0,
    last_sync_updated integer NOT NULL DEFAULT 0,
    last_sync_failed integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(realm_id, name)
);
CREATE INDEX IF NOT EXISTS idx_user_federations_realm_priority
    ON user_federations(realm_id, enabled, priority, name);
CREATE INDEX IF NOT EXISTS idx_user_federations_due
    ON user_federations(next_sync_at) WHERE enabled AND sync_period_seconds > 0;

ALTER TABLE users ADD COLUMN IF NOT EXISTS federation_id uuid REFERENCES user_federations(id) ON DELETE RESTRICT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_id varchar(1024);
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_dn varchar(2048);
ALTER TABLE users ADD COLUMN IF NOT EXISTS federation_synced_at timestamptz;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_federation_external
    ON users(federation_id, external_id) WHERE federation_id IS NOT NULL AND external_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_realm_username_ci ON users(realm_id, lower(username));
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_realm_email_ci ON users(realm_id, lower(email));

CREATE TABLE IF NOT EXISTS federation_role_assignments (
    federation_id uuid NOT NULL REFERENCES user_federations(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(federation_id, user_id, role_id)
);
