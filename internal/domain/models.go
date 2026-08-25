// Package domain holds the entities shared by the storage, OIDC and HTTP
// layers: Realms, users, clients, roles, sessions and signing keys.
package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type Realm struct {
	ID                     uuid.UUID `json:"id"`
	Name                   string    `json:"name"`
	DisplayName            string    `json:"display_name"`
	IssuerURL              string    `json:"issuer_url"`
	Enabled                bool      `json:"enabled"`
	ApprovalEnabled        bool      `json:"approval_enabled"`
	AccessTokenTTLSeconds  int       `json:"access_token_ttl_seconds"`
	RefreshTokenTTLSeconds int       `json:"refresh_token_ttl_seconds"`
	SessionTTLSeconds      int       `json:"session_ttl_seconds"`
	// IdleTimeoutSeconds ends a session that has gone unused for this long.
	// Zero disables the check and keeps only the absolute lifetime.
	IdleTimeoutSeconds int       `json:"idle_timeout_seconds"`
	PasswordMinLength  int       `json:"password_min_length"`
	MaxLoginAttempts   int       `json:"max_login_attempts"`
	LockoutSeconds     int       `json:"lockout_seconds"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type User struct {
	ID                 uuid.UUID  `json:"id"`
	RealmID            uuid.UUID  `json:"realm_id"`
	Username           string     `json:"username"`
	Email              string     `json:"email"`
	EmailVerified      bool       `json:"email_verified"`
	DisplayName        string     `json:"display_name"`
	Enabled            bool       `json:"enabled"`
	PlatformAdmin      bool       `json:"platform_admin"`
	ManagerID          *uuid.UUID `json:"manager_id,omitempty"`
	FederationID       *uuid.UUID `json:"federation_id,omitempty"`
	ExternalID         *string    `json:"external_id,omitempty"`
	ExternalDN         *string    `json:"external_dn,omitempty"`
	FederationSyncedAt *time.Time `json:"federation_synced_at,omitempty"`
	FailedAttempts     int        `json:"failed_attempts"`
	LockedUntil        *time.Time `json:"locked_until,omitempty"`
	PasswordChanged    time.Time  `json:"password_changed_at"`
	// Locked is whether the lockout is in force now, decided by the same
	// clock that wrote locked_until. The console used to compare that
	// timestamp against the browser's clock, and it is what decides whether
	// the unlock action is offered at all — so an administrator whose machine
	// ran fast saw a locked account as normal, with no way to release it.
	Locked    bool      `json:"locked"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type LDAPFederation struct {
	ID                       uuid.UUID         `json:"id"`
	RealmID                  uuid.UUID         `json:"realm_id"`
	Name                     string            `json:"name"`
	Vendor                   string            `json:"vendor"`
	Priority                 int               `json:"priority"`
	Enabled                  bool              `json:"enabled"`
	ConnectionURL            string            `json:"connection_url"`
	StartTLS                 bool              `json:"start_tls"`
	CACertificate            string            `json:"ca_certificate,omitempty"`
	BindDN                   string            `json:"bind_dn"`
	BindCredentialSet        bool              `json:"bind_credential_set"`
	UsersDN                  string            `json:"users_dn"`
	UsernameLDAPAttribute    string            `json:"username_ldap_attribute"`
	RDNLDAPAttribute         string            `json:"rdn_ldap_attribute"`
	UUIDLDAPAttribute        string            `json:"uuid_ldap_attribute"`
	UserObjectClasses        []string          `json:"user_object_classes"`
	UserLDAPFilter           string            `json:"user_ldap_filter"`
	SearchScope              string            `json:"search_scope"`
	EmailLDAPAttribute       string            `json:"email_ldap_attribute"`
	FirstNameLDAPAttribute   string            `json:"first_name_ldap_attribute"`
	LastNameLDAPAttribute    string            `json:"last_name_ldap_attribute"`
	DisplayNameLDAPAttribute string            `json:"display_name_ldap_attribute"`
	MemberOfLDAPAttribute    string            `json:"member_of_ldap_attribute"`
	GroupRoleMappings        map[string]string `json:"group_role_mappings"`
	ImportEnabled            bool              `json:"import_enabled"`
	SyncRegistrations        bool              `json:"sync_registrations"`
	MissingUserAction        string            `json:"missing_user_action"`
	EditMode                 string            `json:"edit_mode"`
	BatchSize                int               `json:"batch_size"`
	SyncPeriodSeconds        int               `json:"sync_period_seconds"`
	NextSyncAt               *time.Time        `json:"next_sync_at,omitempty"`
	LastSyncAt               *time.Time        `json:"last_sync_at,omitempty"`
	LastSyncStatus           string            `json:"last_sync_status"`
	LastSyncError            string            `json:"last_sync_error,omitempty"`
	LastSyncAdded            int               `json:"last_sync_added"`
	LastSyncUpdated          int               `json:"last_sync_updated"`
	LastSyncFailed           int               `json:"last_sync_failed"`
	// LastSyncDisabled is how many accounts the run deactivated because they
	// were gone from the directory. Under the DISABLE policy that is the
	// consequential outcome of a sync — it ends those people's sessions — and
	// the console sends an administrator to these fields to find out what a run
	// did, so leaving it to the audit trail alone hid it where they were told
	// to look.
	LastSyncDisabled int `json:"last_sync_disabled"`
	// LastSyncUnknownRoles names the Roles a group mapping points at that this
	// Realm does not have. They are configuration faults rather than run
	// failures: the sync succeeds and grants nothing, so without naming them
	// there is nothing to act on.
	LastSyncUnknownRoles []string `json:"last_sync_unknown_roles,omitempty"`
	// LastSyncGroupMemberships is how many of the users the last run read
	// carried any group. Zero, with mappings configured, means the mappings had
	// nothing to match against rather than that they name the wrong Role.
	LastSyncGroupMemberships int `json:"last_sync_group_memberships"`
	// SyncRunning is the reconciled answer to "is a run happening now", not
	// the raw status column. A run whose process died leaves that column
	// saying RUNNING for ever, and the console used to believe it: the sync
	// button stayed disabled and the page polled every few seconds, with no
	// way back, while the server would have accepted a new run.
	SyncRunning bool      `json:"sync_running"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Client struct {
	ID                     uuid.UUID `json:"id"`
	RealmID                uuid.UUID `json:"realm_id"`
	ClientID               string    `json:"client_id"`
	Name                   string    `json:"name"`
	Type                   string    `json:"type"`
	RedirectURIs           []string  `json:"redirect_uris"`
	PostLogoutRedirectURIs []string  `json:"post_logout_redirect_uris"`
	WebOrigins             []string  `json:"web_origins"`
	GrantTypes             []string  `json:"grant_types"`
	DefaultScopes          []string  `json:"default_scopes"`
	RequirePKCE            bool      `json:"require_pkce"`
	Enabled                bool      `json:"enabled"`
	AccessTokenTTLSeconds  int       `json:"access_token_ttl_seconds"`
	RefreshTokenTTLSeconds int       `json:"refresh_token_ttl_seconds"`
	BackchannelLogoutURI   string    `json:"backchannel_logout_uri,omitempty"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type Session struct {
	ID         uuid.UUID  `json:"id"`
	RealmID    uuid.UUID  `json:"realm_id"`
	UserID     uuid.UUID  `json:"user_id"`
	Username   string     `json:"username,omitempty"`
	IPAddress  string     `json:"ip_address"`
	UserAgent  string     `json:"user_agent"`
	AuthMethod string     `json:"auth_method"`
	CreatedAt  time.Time  `json:"created_at"`
	LastAccess time.Time  `json:"last_access"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	// Active is whether this session would still be accepted, which is not
	// something a reader can work out from the other fields: a Realm may
	// expire sessions that go unused, and such a session is refused long
	// before expires_at arrives. The console listed those as active because
	// that was all it could see.
	Active bool `json:"active"`
}

type SigningKey struct {
	ID        uuid.UUID       `json:"id"`
	RealmID   uuid.UUID       `json:"realm_id"`
	KID       string          `json:"kid"`
	Algorithm string          `json:"algorithm"`
	Status    string          `json:"status"`
	PublicJWK json.RawMessage `json:"public_jwk"`
	CreatedAt time.Time       `json:"created_at"`
	RetireAt  *time.Time      `json:"retire_at,omitempty"`
	// AgeDays is how old the key is according to the database, which is the
	// clock the dashboard counts aged keys with. The console worked it out
	// from the browser's clock, so the screen listing a key and the dashboard
	// counting it could reach different verdicts about the same key — the
	// disagreement the advisory threshold is already shared to avoid.
	AgeDays int `json:"age_days"`
}

type ApprovalRequest struct {
	ID           uuid.UUID       `json:"id"`
	RealmID      uuid.UUID       `json:"realm_id"`
	RequesterID  uuid.UUID       `json:"requester_id"`
	ReviewerID   *uuid.UUID      `json:"reviewer_id,omitempty"`
	Kind         string          `json:"kind"`
	Payload      json.RawMessage `json:"payload"`
	Reason       string          `json:"reason"`
	Status       string          `json:"status"`
	DecisionNote string          `json:"decision_note"`
	CreatedAt    time.Time       `json:"created_at"`
	DecidedAt    *time.Time      `json:"decided_at,omitempty"`
}

type Principal struct {
	UserID        uuid.UUID
	RealmID       uuid.UUID
	Username      string
	PlatformAdmin bool
	RealmAdmin    bool
	SessionID     *uuid.UUID
	Scopes        []string
}
