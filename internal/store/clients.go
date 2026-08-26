package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hkjang/ReSSO/internal/cryptoutil"
	"github.com/hkjang/ReSSO/internal/domain"
	"github.com/hkjang/ReSSO/internal/password"
)

const clientColumns = `id,realm_id,client_id,name,type,redirect_uris,post_logout_redirect_uris,
    web_origins,grant_types,default_scopes,require_pkce,enabled,access_token_ttl_seconds,
    refresh_token_ttl_seconds,backchannel_logout_uri,created_at,updated_at`

func scanClient(row pgx.Row) (domain.Client, error) {
	var client domain.Client
	err := row.Scan(&client.ID, &client.RealmID, &client.ClientID, &client.Name, &client.Type,
		&client.RedirectURIs, &client.PostLogoutRedirectURIs, &client.WebOrigins, &client.GrantTypes,
		&client.DefaultScopes, &client.RequirePKCE, &client.Enabled, &client.AccessTokenTTLSeconds,
		&client.RefreshTokenTTLSeconds, &client.BackchannelLogoutURI, &client.CreatedAt, &client.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Client{}, ErrNotFound
	}
	return client, err
}

func (s *Store) ClientByIdentifier(ctx context.Context, realmID uuid.UUID, identifier string) (domain.Client, error) {
	return scanClient(s.Pool.QueryRow(ctx, "SELECT "+clientColumns+" FROM clients WHERE realm_id=$1 AND client_id=$2", realmID, identifier))
}

func (s *Store) ClientByID(ctx context.Context, id uuid.UUID) (domain.Client, error) {
	return scanClient(s.Pool.QueryRow(ctx, "SELECT "+clientColumns+" FROM clients WHERE id=$1", id))
}

func (s *Store) ListClients(ctx context.Context, realmID uuid.UUID) ([]domain.Client, error) {
	rows, err := s.Pool.Query(ctx, "SELECT "+clientColumns+" FROM clients WHERE realm_id=$1 ORDER BY client_id", realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	clients := make([]domain.Client, 0)
	for rows.Next() {
		client, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

type CreateClientInput struct {
	ClientID               string   `json:"client_id"`
	Name                   string   `json:"name"`
	Type                   string   `json:"type"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	WebOrigins             []string `json:"web_origins"`
	GrantTypes             []string `json:"grant_types"`
	DefaultScopes          []string `json:"default_scopes"`
	RequirePKCE            bool     `json:"require_pkce"`
	BackchannelLogoutURI   string   `json:"backchannel_logout_uri"`
}

type CreatedClient struct {
	Client       domain.Client `json:"client"`
	ClientSecret string        `json:"client_secret,omitempty"`
}

type UpdateClientInput struct {
	Name                   string   `json:"name"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	WebOrigins             []string `json:"web_origins"`
	GrantTypes             []string `json:"grant_types"`
	DefaultScopes          []string `json:"default_scopes"`
	RequirePKCE            bool     `json:"require_pkce"`
	Enabled                bool     `json:"enabled"`
	AccessTokenTTLSeconds  int      `json:"access_token_ttl_seconds"`
	RefreshTokenTTLSeconds int      `json:"refresh_token_ttl_seconds"`
	BackchannelLogoutURI   string   `json:"backchannel_logout_uri"`
}

// validateBackchannelLogoutURI applies the same transport rules as redirect
// URIs. ReSSO now actually posts signed logout tokens to this address, so an
// unvalidated value would let an administrator direct signed tokens at an
// arbitrary plaintext endpoint.
func validateBackchannelLogoutURI(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}
	if err := validateURIs([]string{trimmed}, false); err != nil {
		return "", fmt.Errorf("backchannel_logout_uri: %w", err)
	}
	return trimmed, nil
}

func (s *Store) UpdateClient(ctx context.Context, id uuid.UUID, input UpdateClientInput) (domain.Client, error) {
	if strings.TrimSpace(input.Name) == "" {
		return domain.Client{}, invalidf("Client 표시 이름이 필요합니다.")
	}
	if err := requireOpenIDForLogins(input.GrantTypes, input.DefaultScopes); err != nil {
		return domain.Client{}, err
	}
	if err := requireRedirectURIForLogins(input.GrantTypes, input.RedirectURIs); err != nil {
		return domain.Client{}, err
	}
	if err := validateURIs(input.RedirectURIs, false); err != nil {
		return domain.Client{}, fmt.Errorf("redirect_uris: %w", err)
	}
	if err := validateURIs(input.PostLogoutRedirectURIs, false); err != nil {
		return domain.Client{}, fmt.Errorf("post_logout_redirect_uris: %w", err)
	}
	var err error
	input.WebOrigins, err = normalizeWebOrigins(input.WebOrigins)
	if err != nil {
		return domain.Client{}, fmt.Errorf("web_origins: %w", err)
	}
	input.RedirectURIs = nonNilStrings(input.RedirectURIs)
	input.PostLogoutRedirectURIs = nonNilStrings(input.PostLogoutRedirectURIs)
	input.GrantTypes = nonNilStrings(input.GrantTypes)
	input.DefaultScopes = nonNilStrings(input.DefaultScopes)
	backchannelURI, err := validateBackchannelLogoutURI(input.BackchannelLogoutURI)
	if err != nil {
		return domain.Client{}, err
	}
	// A public Client keeps PKCE whatever the request says, the same rule
	// CreateClient applies. Only creation enforced it, so an ordinary edit
	// could take it away — and for a Client with no secret, PKCE is the only
	// thing tying an authorization code to whoever asked for it. The type is
	// read from the row rather than taken from the caller because it cannot be
	// changed after creation and is not part of this input.
	command, err := s.Pool.Exec(ctx, `UPDATE clients SET name=$2,redirect_uris=$3,
        post_logout_redirect_uris=$4,web_origins=$5,grant_types=$6,default_scopes=$7,
        require_pkce=($8 OR type='public'),enabled=$9,access_token_ttl_seconds=$10,
        refresh_token_ttl_seconds=$11,
        backchannel_logout_uri=$12,updated_at=now() WHERE id=$1`, id, strings.TrimSpace(input.Name),
		input.RedirectURIs, input.PostLogoutRedirectURIs, input.WebOrigins, input.GrantTypes,
		input.DefaultScopes, input.RequirePKCE, input.Enabled, input.AccessTokenTTLSeconds,
		input.RefreshTokenTTLSeconds, backchannelURI)
	if err != nil {
		if conflict, taken := conflictFromUnique(err); taken {
			return domain.Client{}, conflict
		}
		return domain.Client{}, fmt.Errorf("update client: %w", err)
	}
	if command.RowsAffected() == 0 {
		return domain.Client{}, ErrNotFound
	}
	return s.ClientByID(ctx, id)
}

func (s *Store) CreateClient(ctx context.Context, realmID uuid.UUID, input CreateClientInput) (CreatedClient, error) {
	var nameErr error
	if input.ClientID, nameErr = displayableName("client_id", input.ClientID); nameErr != nil {
		return CreatedClient{}, nameErr
	}
	if input.Name, nameErr = displayableName("Client 이름", input.Name); nameErr != nil {
		return CreatedClient{}, nameErr
	}
	input.Type = strings.TrimSpace(input.Type)
	if input.ClientID == "" || input.Name == "" || !slices.Contains([]string{"public", "confidential"}, input.Type) {
		return CreatedClient{}, invalidf("client_id와 이름, 그리고 public 또는 confidential 유형이 필요합니다.")
	}
	if len(input.GrantTypes) == 0 {
		input.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(input.DefaultScopes) == 0 {
		input.DefaultScopes = []string{"openid", "profile", "email", "roles"}
	}
	if err := requireOpenIDForLogins(input.GrantTypes, input.DefaultScopes); err != nil {
		return CreatedClient{}, err
	}
	if err := requireRedirectURIForLogins(input.GrantTypes, input.RedirectURIs); err != nil {
		return CreatedClient{}, err
	}
	if err := validateURIs(input.RedirectURIs, false); err != nil {
		return CreatedClient{}, fmt.Errorf("redirect_uris: %w", err)
	}
	if err := validateURIs(input.PostLogoutRedirectURIs, false); err != nil {
		return CreatedClient{}, fmt.Errorf("post_logout_redirect_uris: %w", err)
	}
	normalizedOrigins, err := normalizeWebOrigins(input.WebOrigins)
	if err != nil {
		return CreatedClient{}, fmt.Errorf("web_origins: %w", err)
	}
	input.WebOrigins = normalizedOrigins
	input.RedirectURIs = nonNilStrings(input.RedirectURIs)
	input.PostLogoutRedirectURIs = nonNilStrings(input.PostLogoutRedirectURIs)
	backchannelURI, err := validateBackchannelLogoutURI(input.BackchannelLogoutURI)
	if err != nil {
		return CreatedClient{}, err
	}
	client := domain.Client{ID: uuid.New(), RealmID: realmID, ClientID: input.ClientID, Name: input.Name,
		Type: input.Type, RedirectURIs: input.RedirectURIs, PostLogoutRedirectURIs: input.PostLogoutRedirectURIs,
		WebOrigins: input.WebOrigins, GrantTypes: input.GrantTypes, DefaultScopes: input.DefaultScopes,
		RequirePKCE: input.RequirePKCE || input.Type == "public", Enabled: true, AccessTokenTTLSeconds: 300,
		RefreshTokenTTLSeconds: 1800, BackchannelLogoutURI: backchannelURI,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	var secret, secretHash string
	if client.Type == "confidential" {
		secret, err = cryptoutil.RandomToken(32)
		if err != nil {
			return CreatedClient{}, err
		}
		secretHash = s.clientSecretDigest(secret)
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO clients(id,realm_id,client_id,name,type,secret_hash,redirect_uris,
        post_logout_redirect_uris,web_origins,grant_types,default_scopes,require_pkce,enabled,
        access_token_ttl_seconds,refresh_token_ttl_seconds,backchannel_logout_uri,created_at,updated_at)
        VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10,$11,$12,true,$13,$14,$15,$16,$16)`,
		client.ID, realmID, client.ClientID, client.Name, client.Type, secretHash, client.RedirectURIs,
		client.PostLogoutRedirectURIs, client.WebOrigins, client.GrantTypes, client.DefaultScopes,
		client.RequirePKCE, client.AccessTokenTTLSeconds, client.RefreshTokenTTLSeconds,
		client.BackchannelLogoutURI, client.CreatedAt)
	if err != nil {
		if conflict, taken := conflictFromUnique(err); taken {
			return CreatedClient{}, conflict
		}
		return CreatedClient{}, fmt.Errorf("create client: %w", err)
	}
	return CreatedClient{Client: client, ClientSecret: secret}, nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// requireOpenIDForLogins refuses a Client that could never complete a login.
//
// The authorization endpoint requires openid among a Client's allowed scopes,
// so one configured without it is accepted, shown as configured, and then
// fails every authorization request with invalid_scope. The refusal belongs
// here, where somebody is looking at the field they just edited, rather than
// at a relying party that cannot say which setting is wrong. Clients that only
// use client_credentials never reach that endpoint and are left alone.
func requireOpenIDForLogins(grantTypes, scopes []string) error {
	if !slices.Contains(grantTypes, "authorization_code") {
		return nil
	}
	if slices.Contains(scopes, "openid") {
		return nil
	}
	return invalidf("로그인에 쓰이는 Client의 허용 Scope에는 openid가 있어야 합니다. 없으면 모든 인가 요청이 invalid_scope로 거절됩니다.")
}

// requireRedirectURIForLogins refuses a login Client with nowhere to send
// anyone back to.
//
// A registered redirect URI is what the authorization endpoint matches the
// request against, so with none registered nothing can match and every
// authorization request is refused as unregistered. Like the scope above, the
// Client saves cleanly and only the relying party ever sees the problem.
func requireRedirectURIForLogins(grantTypes, redirectURIs []string) error {
	if !slices.Contains(grantTypes, "authorization_code") {
		return nil
	}
	if len(redirectURIs) > 0 {
		return nil
	}
	return invalidf("로그인에 쓰이는 Client에는 Redirect URI가 최소 하나 필요합니다. 없으면 모든 인가 요청이 등록되지 않은 주소로 거절됩니다.")
}

func validateURIs(values []string, allowFragment bool) error {
	for _, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || (!allowFragment && parsed.Fragment != "") {
			return fmt.Errorf("%q is not an absolute URI without a fragment", value)
		}
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHostname(parsed.Hostname())) {
			return fmt.Errorf("%q must use HTTPS except for loopback development addresses", value)
		}
	}
	return nil
}

func normalizeWebOrigins(values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
			(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("%q must be an origin without path, query, userinfo or fragment", value)
		}
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHostname(parsed.Hostname())) {
			return nil, fmt.Errorf("%q must use HTTPS except for loopback development origins", value)
		}
		origin := strings.ToLower(parsed.Scheme) + "://" + canonicalOriginHost(parsed)
		if !seen[origin] {
			normalized = append(normalized, origin)
			seen[origin] = true
		}
	}
	return normalized, nil
}

// canonicalOriginHost drops a port that is the scheme's default, because that
// is the form a browser sends and therefore the only form that can ever match.
// Keeping it meant an origin registered as https://app.example.com:443 was
// accepted, displayed as saved, and never matched anything: the Origin header
// carries https://app.example.com, so every cross-origin request from the
// application it was registered for was refused with nothing to say why. The
// two spellings are the same origin, so collapsing them cannot widen what is
// allowed.
func canonicalOriginHost(parsed *url.URL) string {
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if port == "" ||
		(parsed.Scheme == "https" && port == "443") ||
		(parsed.Scheme == "http" && port == "80") {
		return host
	}
	return net.JoinHostPort(host, port)
}

func isLoopbackHostname(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// normalizedWebOrigin canonicalizes a single Origin header value. A malformed
// value is reported as not well formed rather than as an error: it can never
// match a registered origin, so the caller's answer is simply "not allowed".
func normalizedWebOrigin(origin string) (string, bool) {
	normalized, err := normalizeWebOrigins([]string{origin})
	if err != nil || len(normalized) != 1 {
		return "", false
	}
	return normalized[0], true
}

func (s *Store) WebOriginAllowed(ctx context.Context, realmID uuid.UUID, origin string) (bool, error) {
	normalized, wellFormed := normalizedWebOrigin(origin)
	if !wellFormed {
		return false, nil
	}
	var allowed bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM clients
		WHERE realm_id=$1 AND enabled=true AND $2=ANY(web_origins))`, realmID, normalized).Scan(&allowed)
	return allowed, err
}

func RedirectURIAllowed(client domain.Client, requested string) bool {
	return slices.Contains(client.RedirectURIs, requested)
}

func PostLogoutURIAllowed(client domain.Client, requested string) bool {
	return slices.Contains(client.PostLogoutRedirectURIs, requested)
}

// clientSecretDigestPrefix marks a keyed-HMAC client secret hash. Client
// secrets are 256-bit values generated by ReSSO, so they carry no guessable
// structure for a password-stretching function to defend. Verifying them with
// Argon2 instead let any unauthenticated caller of the token, introspection or
// revocation endpoint spend 64 MiB and a CPU core per attempt, so new secrets
// use the same keyed digest as personal API keys.
const clientSecretDigestPrefix = "hmac-sha256$"

func (s *Store) clientSecretDigest(secret string) string {
	return clientSecretDigestPrefix + base64.RawStdEncoding.EncodeToString(s.Sealer.Digest(secret))
}

// VerifyClientSecret accepts both the keyed digest and the v0.2 Argon2 hash.
// A surviving Argon2 hash is upgraded in place on the first successful
// verification so the expensive path disappears as clients authenticate.
func (s *Store) VerifyClientSecret(ctx context.Context, clientID uuid.UUID, secret string) (bool, error) {
	var hash *string
	if err := s.Pool.QueryRow(ctx, "SELECT secret_hash FROM clients WHERE id=$1", clientID).Scan(&hash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, err
	}
	if hash == nil || secret == "" {
		return false, nil
	}
	if encoded, ok := strings.CutPrefix(*hash, clientSecretDigestPrefix); ok {
		expected, err := base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return false, errors.New("stored client secret digest is malformed")
		}
		return s.Sealer.MatchDigest(secret, expected), nil
	}
	matched, err := password.VerifyContext(ctx, secret, *hash)
	if err != nil || !matched {
		return false, err
	}
	// Best effort: a failed upgrade only leaves the legacy hash in place.
	_, _ = s.Pool.Exec(ctx, `UPDATE clients SET secret_hash=$2 WHERE id=$1 AND secret_hash=$3`,
		clientID, s.clientSecretDigest(secret), *hash)
	return true, nil
}

func (s *Store) RotateClientSecret(ctx context.Context, clientID uuid.UUID) (string, error) {
	secret, err := cryptoutil.RandomToken(32)
	if err != nil {
		return "", err
	}
	command, err := s.Pool.Exec(ctx, `UPDATE clients SET secret_hash=$2,updated_at=now()
        WHERE id=$1 AND type='confidential'`, clientID, s.clientSecretDigest(secret))
	if err != nil {
		return "", err
	}
	if command.RowsAffected() == 0 {
		return "", ErrNotFound
	}
	return secret, nil
}
