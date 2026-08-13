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
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type User struct {
	ID              uuid.UUID  `json:"id"`
	RealmID         uuid.UUID  `json:"realm_id"`
	Username        string     `json:"username"`
	Email           string     `json:"email"`
	DisplayName     string     `json:"display_name"`
	Enabled         bool       `json:"enabled"`
	PlatformAdmin   bool       `json:"platform_admin"`
	ManagerID       *uuid.UUID `json:"manager_id,omitempty"`
	FailedAttempts  int        `json:"failed_attempts"`
	LockedUntil     *time.Time `json:"locked_until,omitempty"`
	PasswordChanged time.Time  `json:"password_changed_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
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
	SessionID     *uuid.UUID
	Scopes        []string
}
