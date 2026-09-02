// Package oidc issues and verifies ReSSO's OpenID Connect tokens: access,
// ID, refresh and back-channel logout tokens, with Keycloak-compatible claims.
package oidc

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/domain"
	"github.com/hkjang/ReSSO/internal/store"
)

type Service struct {
	Store *store.Store
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope"`
}

type keycloakClaims struct {
	Type              string              `json:"typ"`
	AuthorizedParty   string              `json:"azp"`
	Scope             string              `json:"scope,omitempty"`
	AuthTime          int64               `json:"auth_time,omitempty"`
	SessionID         string              `json:"sid,omitempty"`
	SessionState      string              `json:"session_state,omitempty"`
	PreferredUsername string              `json:"preferred_username,omitempty"`
	Email             string              `json:"email,omitempty"`
	EmailVerified     *bool               `json:"email_verified,omitempty"`
	Name              string              `json:"name,omitempty"`
	Nonce             string              `json:"nonce,omitempty"`
	AccessTokenHash   string              `json:"at_hash,omitempty"`
	RealmAccess       map[string][]string `json:"realm_access,omitempty"`
	ResourceAccess    map[string]any      `json:"resource_access,omitempty"`
}

type VerifiedToken struct {
	Claims jwt.Claims
	Extra  keycloakClaims
	Raw    string
}

func (s *Service) signer(ctx context.Context, realmID uuid.UUID) (jose.Signer, error) {
	privateKey, metadata, err := s.Store.ActivePrivateKey(ctx, realmID)
	if err != nil {
		return nil, err
	}
	return jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", metadata.KID))
}

func signClaims(signer jose.Signer, standard jwt.Claims, extra keycloakClaims) (string, error) {
	return jwt.Signed(signer).Claims(standard).Claims(extra).Serialize()
}

func (s *Service) IssueUserTokens(ctx context.Context, realm domain.Realm, client domain.Client, user domain.User,
	sessionID uuid.UUID, scopes []string, nonce string, includeRefresh bool) (TokenResponse, error) {
	signer, err := s.signer(ctx, realm.ID)
	if err != nil {
		return TokenResponse{}, err
	}
	now := time.Now().UTC()
	authTime, err := s.Store.SessionAuthTime(ctx, sessionID)
	if err != nil {
		return TokenResponse{}, err
	}
	ttl := client.AccessTokenTTLSeconds
	if ttl <= 0 {
		ttl = realm.AccessTokenTTLSeconds
	}
	accessJTI := uuid.New()
	accessStandard := jwt.Claims{Issuer: realm.IssuerURL, Subject: user.ID.String(), Audience: jwt.Audience{client.ClientID},
		Expiry: jwt.NewNumericDate(now.Add(time.Duration(ttl) * time.Second)), IssuedAt: jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)), ID: accessJTI.String()}
	extra := keycloakClaims{Type: "Bearer", AuthorizedParty: client.ClientID, Scope: strings.Join(scopes, " "),
		AuthTime: authTime.Unix(), SessionID: sessionID.String(), SessionState: sessionID.String()}
	if containsScope(scopes, "profile") {
		extra.PreferredUsername = user.Username
		extra.Name = user.DisplayName
	}
	if containsScope(scopes, "email") && user.Email != "" {
		extra.Email = user.Email
		verified := user.EmailVerified
		extra.EmailVerified = &verified
	}
	if containsScope(scopes, "roles") {
		roles, roleErr := s.Store.RealmRolesForUser(ctx, user.ID)
		if roleErr != nil {
			return TokenResponse{}, roleErr
		}
		clientRoles, roleErr := s.Store.ClientRolesForUser(ctx, user.ID)
		if roleErr != nil {
			return TokenResponse{}, roleErr
		}
		resources := make(map[string]any, len(clientRoles))
		for clientID, assigned := range clientRoles {
			resources[clientID] = map[string]any{"roles": assigned}
		}
		extra.RealmAccess = map[string][]string{"roles": roles}
		extra.ResourceAccess = resources
	}
	accessToken, err := signClaims(signer, accessStandard, extra)
	if err != nil {
		return TokenResponse{}, err
	}
	response := TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: ttl, Scope: strings.Join(scopes, " ")}
	if containsScope(scopes, "openid") {
		idStandard := jwt.Claims{Issuer: realm.IssuerURL, Subject: user.ID.String(), Audience: jwt.Audience{client.ClientID},
			Expiry: jwt.NewNumericDate(now.Add(time.Duration(ttl) * time.Second)), IssuedAt: jwt.NewNumericDate(now),
			ID: uuid.NewString()}
		idExtra := extra
		idExtra.Type = "ID"
		idExtra.Nonce = nonce
		idExtra.Scope = ""
		// at_hash lets a relying party bind the ID token to the access token
		// it was issued with. Strict OpenID Connect clients reject an ID token
		// without it when an access token is present.
		idExtra.AccessTokenHash = accessTokenHash(accessToken)
		response.IDToken, err = signClaims(signer, idStandard, idExtra)
		if err != nil {
			return TokenResponse{}, err
		}
	}
	if includeRefresh {
		refreshTTL := client.RefreshTokenTTLSeconds
		if refreshTTL <= 0 {
			refreshTTL = realm.RefreshTokenTTLSeconds
		}
		userID := user.ID
		sid := sessionID
		response.RefreshToken, err = s.Store.CreateRefreshToken(ctx, store.RefreshToken{RealmID: realm.ID,
			ClientID: client.ID, UserID: &userID, SessionID: &sid, Scope: scopes,
			ExpiresAt: now.Add(time.Duration(refreshTTL) * time.Second)})
		if err != nil {
			return TokenResponse{}, err
		}
	}
	return response, nil
}

func (s *Service) IssueRefreshedUserTokens(ctx context.Context, realm domain.Realm, client domain.Client,
	user domain.User, token store.RefreshToken, rawRefresh string) (TokenResponse, error) {
	if token.SessionID == nil {
		return TokenResponse{}, errors.New("refresh token is not bound to a user session")
	}
	response, err := s.IssueUserTokens(ctx, realm, client, user, *token.SessionID, token.Scope, "", false)
	if err != nil {
		return TokenResponse{}, err
	}
	response.RefreshToken = rawRefresh
	return response, nil
}

func (s *Service) IssueClientToken(ctx context.Context, realm domain.Realm, client domain.Client, scopes []string) (TokenResponse, error) {
	signer, err := s.signer(ctx, realm.ID)
	if err != nil {
		return TokenResponse{}, err
	}
	now := time.Now().UTC()
	ttl := client.AccessTokenTTLSeconds
	standard := jwt.Claims{Issuer: realm.IssuerURL, Subject: client.ClientID, Audience: jwt.Audience{client.ClientID},
		Expiry: jwt.NewNumericDate(now.Add(time.Duration(ttl) * time.Second)), IssuedAt: jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)), ID: uuid.NewString()}
	extra := keycloakClaims{Type: "Bearer", AuthorizedParty: client.ClientID, Scope: strings.Join(scopes, " "),
		PreferredUsername: "service-account-" + client.ClientID,
		ResourceAccess:    map[string]any{client.ClientID: map[string]any{"roles": []string{}}}}
	raw, err := signClaims(signer, standard, extra)
	return TokenResponse{AccessToken: raw, TokenType: "Bearer", ExpiresIn: ttl, Scope: strings.Join(scopes, " ")}, err
}

// logoutEvent is the event identifier every OpenID Connect Back-Channel
// Logout token must carry.
const logoutEvent = "http://schemas.openid.net/event/backchannel-logout"

type logoutClaims struct {
	Events    map[string]any `json:"events"`
	SessionID string         `json:"sid,omitempty"`
}

// IssueLogoutToken builds an OpenID Connect Back-Channel Logout 1.0 token for
// one relying party. The token deliberately carries no nonce, and both sub and
// sid so that a relying party can terminate either the specific session or all
// of the subject's sessions.
func (s *Service) IssueLogoutToken(ctx context.Context, realm domain.Realm, client domain.Client,
	sessionID, userID uuid.UUID) (string, error) {
	privateKey, metadata, err := s.Store.ActivePrivateKey(ctx, realm.ID)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("logout+jwt").WithHeader("kid", metadata.KID))
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	standard := jwt.Claims{Issuer: realm.IssuerURL, Subject: userID.String(),
		Audience: jwt.Audience{client.ClientID}, IssuedAt: jwt.NewNumericDate(now),
		Expiry: jwt.NewNumericDate(now.Add(2 * time.Minute)), ID: uuid.NewString()}
	extra := logoutClaims{Events: map[string]any{logoutEvent: map[string]any{}}, SessionID: sessionID.String()}
	return jwt.Signed(signer).Claims(standard).Claims(extra).Serialize()
}

// IDTokenHint reads the claims of an id_token_hint, for the two endpoints that
// take one: authorization and RP-initiated logout.
//
// Expiry is deliberately not checked. A hint is normally presented precisely
// because the token expired — that is what a relying party is trying to renew,
// and the state its stored token is in by the time somebody clicks log out — so
// rejecting expired ones would refuse the case the parameter exists for.
// RP-Initiated Logout 1.0 section 4 asks for exactly that. The signature and
// issuer still have to be ours, which is what makes the claims trustworthy
// enough to act on.
//
// The typ claim is checked because only an ID token is a hint. An access token
// carries the same issuer, azp and subject, so without this it passed for one.
func (s *Service) IDTokenHint(ctx context.Context, realm domain.Realm, raw string) (VerifiedToken, error) {
	standard, extra, err := s.parseSigned(ctx, realm, raw)
	if err != nil {
		return VerifiedToken{}, err
	}
	if standard.Issuer != realm.IssuerURL {
		return VerifiedToken{}, errors.New("id_token_hint was issued by another issuer")
	}
	if extra.Type != "ID" {
		return VerifiedToken{}, errors.New("id_token_hint is not an ID token")
	}
	return VerifiedToken{Claims: standard, Extra: extra, Raw: raw}, nil
}

// SubjectFromIDTokenHint reads the subject an id_token_hint asserts.
func (s *Service) SubjectFromIDTokenHint(ctx context.Context, realm domain.Realm, raw string) (string, error) {
	hint, err := s.IDTokenHint(ctx, realm, raw)
	if err != nil {
		return "", err
	}
	if hint.Claims.Subject == "" {
		return "", errors.New("id_token_hint has no subject")
	}
	return hint.Claims.Subject, nil
}

// parseSigned resolves the Realm signing key named by the token and returns
// its claims. No time-based validation is applied; callers add what they need.
func (s *Service) parseSigned(ctx context.Context, realm domain.Realm, raw string) (jwt.Claims, keycloakClaims, error) {
	var standard jwt.Claims
	var extra keycloakClaims
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return standard, extra, errors.New("token is not a signed RS256 JWT")
	}
	if len(parsed.Headers) != 1 {
		return standard, extra, errors.New("token has an invalid JOSE header count")
	}
	kid := parsed.Headers[0].KeyID
	if kid == "" {
		return standard, extra, errors.New("token has no kid header")
	}
	// Ask for the named key rather than scanning what happens to be cached: a
	// key rotated on another instance is unknown here until this instance
	// reloads, and rejecting the tokens that instance is issuing is not an
	// answer anyone can act on.
	metadata, err := s.Store.SigningKeyByKID(ctx, realm.ID, kid)
	if err != nil {
		return standard, extra, errors.New("token signing key is unavailable")
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(metadata.PublicJWK, &jwk); err != nil {
		return standard, extra, err
	}
	publicKey, _ := jwk.Key.(*rsa.PublicKey)
	if publicKey == nil {
		return standard, extra, errors.New("token signing key is unavailable")
	}
	if err := parsed.Claims(publicKey, &standard, &extra); err != nil {
		return standard, extra, errors.New("token signature validation failed")
	}
	return standard, extra, nil
}

// ErrTokenStateUnavailable reports that a token could not be judged because
// its revocation state could not be read. It is not a statement about the
// token, which may be entirely valid.
var ErrTokenStateUnavailable = errors.New("token revocation state is unavailable")

func (s *Service) Verify(ctx context.Context, realm domain.Realm, raw string, expectedAudience string) (VerifiedToken, error) {
	standard, extra, err := s.parseSigned(ctx, realm, raw)
	if err != nil {
		return VerifiedToken{}, err
	}
	expected := jwt.Expected{Issuer: realm.IssuerURL, Time: time.Now().UTC()}
	if expectedAudience != "" {
		expected.AnyAudience = jwt.Audience{expectedAudience}
	}
	if err := standard.Validate(expected); err != nil {
		return VerifiedToken{}, fmt.Errorf("token claims validation failed: %w", err)
	}
	jti, err := uuid.Parse(standard.ID)
	if err == nil {
		revoked, checkErr := s.Store.IsAccessJTIRevoked(ctx, jti)
		if checkErr != nil {
			// Distinguishable from an invalid token: the token may be
			// perfectly good and simply unjudgeable right now. Callers that
			// refuse are refusing safely; a caller that is being asked to
			// *change* the token's state must not read this as "nothing to do".
			return VerifiedToken{}, fmt.Errorf("%w: %v", ErrTokenStateUnavailable, checkErr)
		}
		if revoked {
			return VerifiedToken{}, errors.New("token has been revoked")
		}
	}
	return VerifiedToken{Claims: standard, Extra: extra, Raw: raw}, nil
}

// accessTokenHash is the base64url encoding of the left-most half of the
// SHA-256 digest of the access token, as required for RS256 by OpenID Connect
// Core 1.0 section 3.1.3.6.
func accessTokenHash(accessToken string) string {
	digest := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])
}

func containsScope(scopes []string, expected string) bool {
	for _, scope := range scopes {
		if scope == expected {
			return true
		}
	}
	return false
}
