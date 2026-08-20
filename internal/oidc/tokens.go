package oidc

import (
	"context"
	"crypto/rsa"
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
	if containsScope(scopes, "email") {
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

func (s *Service) Verify(ctx context.Context, realm domain.Realm, raw string, expectedAudience string) (VerifiedToken, error) {
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return VerifiedToken{}, errors.New("token is not a signed RS256 JWT")
	}
	if len(parsed.Headers) != 1 {
		return VerifiedToken{}, errors.New("token has an invalid JOSE header count")
	}
	kid := parsed.Headers[0].KeyID
	if kid == "" {
		return VerifiedToken{}, errors.New("token has no kid header")
	}
	keys, err := s.Store.ListSigningKeys(ctx, realm.ID)
	if err != nil {
		return VerifiedToken{}, err
	}
	var publicKey *rsa.PublicKey
	for _, metadata := range keys {
		if metadata.KID != kid {
			continue
		}
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(metadata.PublicJWK, &jwk); err != nil {
			return VerifiedToken{}, err
		}
		publicKey, _ = jwk.Key.(*rsa.PublicKey)
		break
	}
	if publicKey == nil {
		return VerifiedToken{}, errors.New("token signing key is unavailable")
	}
	var standard jwt.Claims
	var extra keycloakClaims
	if err := parsed.Claims(publicKey, &standard, &extra); err != nil {
		return VerifiedToken{}, errors.New("token signature validation failed")
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
			return VerifiedToken{}, checkErr
		}
		if revoked {
			return VerifiedToken{}, errors.New("token has been revoked")
		}
	}
	return VerifiedToken{Claims: standard, Extra: extra, Raw: raw}, nil
}

func containsScope(scopes []string, expected string) bool {
	for _, scope := range scopes {
		if scope == expected {
			return true
		}
	}
	return false
}
