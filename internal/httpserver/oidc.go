package httpserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/domain"
	ressooidc "github.com/hkjang/ReSSO/internal/oidc"
	"github.com/hkjang/ReSSO/internal/store"
)

func (s *Server) realmFromPath(r *http.Request) (domain.Realm, error) {
	return s.store.RealmByName(r.Context(), chi.URLParam(r, "realm"))
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	realm, err := s.realmFromPath(r)
	if err != nil || !realm.Enabled {
		writeError(w, r, http.StatusNotFound, "realm_not_found", "Realm을 찾을 수 없습니다.")
		return
	}
	issuer := strings.TrimRight(realm.IssuerURL, "/")
	protocol := issuer + "/protocol/openid-connect"
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                        issuer,
		"authorization_endpoint":                        protocol + "/auth",
		"token_endpoint":                                protocol + "/token",
		"userinfo_endpoint":                             protocol + "/userinfo",
		"jwks_uri":                                      protocol + "/certs",
		"end_session_endpoint":                          protocol + "/logout",
		"introspection_endpoint":                        protocol + "/token/introspect",
		"revocation_endpoint":                           protocol + "/revoke",
		"response_types_supported":                      []string{"code"},
		"response_modes_supported":                      []string{"query"},
		"grant_types_supported":                         []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"RS256"},
		"token_endpoint_auth_methods_supported":         []string{"client_secret_basic", "client_secret_post", "none"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":              []string{"S256"},
		"scopes_supported":                              []string{"openid", "profile", "email", "roles"},
		"claims_supported":                              []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "jti", "sid", "azp", "scope", "preferred_username", "email", "email_verified", "name", "realm_access", "resource_access"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	realm, err := s.realmFromPath(r)
	if err != nil || !realm.Enabled {
		writeError(w, r, http.StatusNotFound, "realm_not_found", "Realm을 찾을 수 없습니다.")
		return
	}
	keys, err := s.store.ListSigningKeys(r.Context(), realm.ID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	result := make([]json.RawMessage, 0, len(keys))
	for _, key := range keys {
		result = append(result, key.PublicJWK)
	}
	w.Header().Set("Cache-Control", "public, max-age=300, stale-while-revalidate=300")
	writeJSON(w, http.StatusOK, map[string]any{"keys": result})
}

func (s *Server) authorization(w http.ResponseWriter, r *http.Request) {
	realm, err := s.realmFromPath(r)
	if err != nil || !realm.Enabled {
		writeError(w, r, http.StatusNotFound, "realm_not_found", "Realm을 찾을 수 없습니다.")
		return
	}
	query := r.URL.Query()
	client, err := s.store.ClientByIdentifier(r.Context(), realm.ID, query.Get("client_id"))
	if err != nil || !client.Enabled {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "unknown client_id")
		return
	}
	redirectURI := query.Get("redirect_uri")
	if !store.RedirectURIAllowed(client, redirectURI) {
		// Never redirect an error to an untrusted URI.
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "redirect_uri is not registered")
		return
	}
	if query.Get("response_type") != "code" {
		redirectOAuthError(w, r, redirectURI, query.Get("state"), realm.IssuerURL, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	if mode := query.Get("response_mode"); mode != "" && mode != "query" {
		redirectOAuthError(w, r, redirectURI, query.Get("state"), realm.IssuerURL, "unsupported_response_mode", "only query response mode is supported")
		return
	}
	scopes, err := validatedScopes(query.Get("scope"), client.DefaultScopes, true)
	if err != nil {
		redirectOAuthError(w, r, redirectURI, query.Get("state"), realm.IssuerURL, "invalid_scope", err.Error())
		return
	}
	challenge, method := query.Get("code_challenge"), query.Get("code_challenge_method")
	if client.RequirePKCE || challenge != "" {
		if method != "S256" || len(challenge) < 43 || len(challenge) > 128 {
			redirectOAuthError(w, r, redirectURI, query.Get("state"), realm.IssuerURL, "invalid_request", "PKCE with code_challenge_method=S256 is required")
			return
		}
	}
	prompt := query.Get("prompt")
	if prompt != "login" {
		if authenticated, sessionErr := s.store.SessionByToken(r.Context(), sessionCookie(r)); sessionErr == nil && authenticated.User.RealmID == realm.ID {
			code, codeErr := s.store.CreateAuthorizationCode(r.Context(), store.AuthorizationCode{
				RealmID: realm.ID, ClientID: client.ID, UserID: authenticated.User.ID, SessionID: authenticated.Session.ID,
				RedirectURI: redirectURI, Scope: scopes, Nonce: query.Get("nonce"), CodeChallenge: challenge,
				CodeChallengeMethod: method,
			})
			if codeErr != nil {
				redirectOAuthError(w, r, redirectURI, query.Get("state"), realm.IssuerURL, "server_error", "authorization code could not be created")
				return
			}
			http.Redirect(w, r, authorizationRedirect(redirectURI, code, query.Get("state"), realm.IssuerURL, authenticated.Session.ID), http.StatusFound)
			return
		}
	}
	if prompt == "none" {
		redirectOAuthError(w, r, redirectURI, query.Get("state"), realm.IssuerURL, "login_required", "no active SSO session")
		return
	}
	pending := store.AuthorizationRequest{RealmID: realm.ID, ClientID: client.ID, RedirectURI: redirectURI,
		ResponseType: "code", Scope: scopes, State: query.Get("state"), Nonce: query.Get("nonce"),
		CodeChallenge: challenge, CodeChallengeMethod: method, Prompt: prompt}
	token, err := s.store.CreateAuthorizationRequest(r.Context(), pending)
	if err != nil {
		redirectOAuthError(w, r, redirectURI, query.Get("state"), realm.IssuerURL, "server_error", "authorization request could not be saved")
		return
	}
	http.Redirect(w, r, "/login?request="+url.QueryEscape(token), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Pragma", "no-cache")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	realm, err := s.realmFromPath(r)
	if err != nil || !realm.Enabled {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_grant", "realm is unavailable")
		return
	}
	client, authenticated, err := s.authenticateOIDCClient(r, realm)
	if err != nil || !authenticated || !client.Enabled {
		w.Header().Set("WWW-Authenticate", `Basic realm="ReSSO token endpoint"`)
		writeOAuthError(w, r, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	grant := r.Form.Get("grant_type")
	if !slices.Contains(client.GrantTypes, grant) {
		writeOAuthError(w, r, http.StatusBadRequest, "unsupported_grant_type", "grant is not enabled for this client")
		return
	}
	switch grant {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r, realm, client)
	case "refresh_token":
		s.handleRefreshGrant(w, r, realm, client)
	case "client_credentials":
		s.handleClientCredentialsGrant(w, r, realm, client)
	default:
		writeOAuthError(w, r, http.StatusBadRequest, "unsupported_grant_type", "grant is not supported")
	}
}

func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, realm domain.Realm, client domain.Client) {
	code, err := s.store.RedeemAuthorizationCode(r.Context(), r.Form.Get("code"), func(candidate store.AuthorizationCode) error {
		if candidate.RealmID != realm.ID || candidate.ClientID != client.ID || candidate.RedirectURI != r.Form.Get("redirect_uri") {
			return store.ErrNotFound
		}
		if candidate.CodeChallenge != "" || client.RequirePKCE {
			return ressooidc.ValidatePKCE(candidate.CodeChallenge, candidate.CodeChallengeMethod, r.Form.Get("code_verifier"))
		}
		return nil
	})
	if err != nil {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
		return
	}
	user, err := s.store.UserByID(r.Context(), code.UserID)
	if err != nil || !user.Enabled {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_grant", "user is unavailable")
		return
	}
	includeRefresh := slices.Contains(client.GrantTypes, "refresh_token")
	response, err := s.oidc.IssueUserTokens(r.Context(), realm, client, user, code.SessionID, code.Scope, code.Nonce, includeRefresh)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_grant", "authorization session is no longer active")
			return
		}
		s.logger.Error("token issue failed", "trace_id", traceIDFrom(r.Context()), "error", err)
		writeOAuthError(w, r, http.StatusInternalServerError, "server_error", "token could not be issued")
		return
	}
	s.audit(r, &realm.ID, &user.ID, user.Username, "TOKEN_ISSUED", "SUCCESS", "client", client.ClientID, map[string]any{"grant_type": "authorization_code"})
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleRefreshGrant(w http.ResponseWriter, r *http.Request, realm domain.Realm, client domain.Client) {
	raw := r.Form.Get("refresh_token")
	inspected, _, err := s.store.InspectRefreshToken(r.Context(), raw)
	if err != nil || inspected.RealmID != realm.ID || inspected.ClientID != client.ID || inspected.UserID == nil {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or expired")
		return
	}
	requestedScopes, err := validatedScopes(r.Form.Get("scope"), inspected.Scope, false)
	if err != nil {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}
	if r.Form.Get("scope") != "" {
		inspected.Scope = requestedScopes
	}
	var reducedScopes []string
	if r.Form.Get("scope") != "" {
		reducedScopes = inspected.Scope
	}
	rotated, rawNew, err := s.store.RotateRefreshToken(r.Context(), raw, reducedScopes)
	if err != nil {
		if errors.Is(err, store.ErrTokenReuse) {
			s.audit(r, &realm.ID, inspected.UserID, "", "REFRESH_TOKEN_REUSE", "FAILURE", "client", client.ClientID, nil)
		}
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or was already used")
		return
	}
	rotated.Scope = inspected.Scope
	user, err := s.store.UserByID(r.Context(), *rotated.UserID)
	if err != nil || !user.Enabled {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_grant", "user is unavailable")
		return
	}
	response, err := s.oidc.IssueRefreshedUserTokens(r.Context(), realm, client, user, rotated, rawNew)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_grant", "authorization session is no longer active")
			return
		}
		writeOAuthError(w, r, http.StatusInternalServerError, "server_error", "token could not be issued")
		return
	}
	s.audit(r, &realm.ID, &user.ID, user.Username, "TOKEN_REFRESH", "SUCCESS", "client", client.ClientID, nil)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, realm domain.Realm, client domain.Client) {
	if client.Type != "confidential" {
		writeOAuthError(w, r, http.StatusUnauthorized, "unauthorized_client", "client_credentials requires a confidential client")
		return
	}
	scopes, err := validatedScopes(r.Form.Get("scope"), client.DefaultScopes, false)
	if err != nil {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}
	response, err := s.oidc.IssueClientToken(r.Context(), realm, client, scopes)
	if err != nil {
		writeOAuthError(w, r, http.StatusInternalServerError, "server_error", "token could not be issued")
		return
	}
	s.audit(r, &realm.ID, nil, client.ClientID, "TOKEN_ISSUED", "SUCCESS", "client", client.ClientID, map[string]any{"grant_type": "client_credentials"})
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) authenticateOIDCClient(r *http.Request, realm domain.Realm) (domain.Client, bool, error) {
	clientID, secret, basic := r.BasicAuth()
	if !basic {
		clientID, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
	}
	client, err := s.store.ClientByIdentifier(r.Context(), realm.ID, clientID)
	if err != nil {
		return domain.Client{}, false, err
	}
	if client.Type == "public" {
		return client, secret == "", nil
	}
	ok, err := s.store.VerifyClientSecret(r.Context(), client.ID, secret)
	return client, ok, err
}

func (s *Server) userInfo(w http.ResponseWriter, r *http.Request) {
	realm, err := s.realmFromPath(r)
	if err != nil {
		writeBearerError(w, r, "invalid_token")
		return
	}
	raw := bearerToken(r)
	verified, err := s.oidc.Verify(r.Context(), realm, raw, "")
	if err != nil || verified.Extra.Type != "Bearer" {
		writeBearerError(w, r, "invalid_token")
		return
	}
	userID, err := uuid.Parse(verified.Claims.Subject)
	if err != nil {
		writeBearerError(w, r, "invalid_token")
		return
	}
	user, err := s.store.UserByID(r.Context(), userID)
	if err != nil || !user.Enabled {
		writeBearerError(w, r, "invalid_token")
		return
	}
	if sid, parseErr := uuid.Parse(verified.Extra.SessionID); parseErr != nil {
		writeBearerError(w, r, "invalid_token")
		return
	} else if _, sessionErr := s.store.SessionAuthTime(r.Context(), sid); sessionErr != nil {
		writeBearerError(w, r, "invalid_token")
		return
	}
	scopes := strings.Fields(verified.Extra.Scope)
	result := map[string]any{"sub": user.ID.String()}
	if slices.Contains(scopes, "profile") {
		result["preferred_username"] = user.Username
		result["name"] = user.DisplayName
	}
	if slices.Contains(scopes, "email") {
		result["email"] = user.Email
		result["email_verified"] = user.EmailVerified
	}
	if slices.Contains(scopes, "roles") {
		roles, _ := s.store.RealmRolesForUser(r.Context(), user.ID)
		result["realm_access"] = map[string]any{"roles": roles}
		clientRoles, _ := s.store.ClientRolesForUser(r.Context(), user.ID)
		resources := make(map[string]any, len(clientRoles))
		for clientID, assigned := range clientRoles {
			resources[clientID] = map[string]any{"roles": assigned}
		}
		result["resource_access"] = resources
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) introspect(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	realm, err := s.realmFromPath(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	client, ok, err := s.authenticateOIDCClient(r, realm)
	if err != nil || !ok || client.Type != "confidential" {
		writeOAuthError(w, r, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	raw := r.Form.Get("token")
	if verified, verifyErr := s.oidc.Verify(r.Context(), realm, raw, client.ClientID); verifyErr == nil && verified.Extra.AuthorizedParty == client.ClientID {
		if verified.Extra.SessionID != "" {
			sid, parseErr := uuid.Parse(verified.Extra.SessionID)
			if parseErr != nil {
				writeJSON(w, http.StatusOK, map[string]any{"active": false})
				return
			}
			if _, sessionErr := s.store.SessionAuthTime(r.Context(), sid); sessionErr != nil {
				writeJSON(w, http.StatusOK, map[string]any{"active": false})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"active": true, "scope": verified.Extra.Scope,
			"client_id": verified.Extra.AuthorizedParty, "username": verified.Extra.PreferredUsername,
			"token_type": "Bearer", "exp": verified.Claims.Expiry.Time().Unix(), "iat": verified.Claims.IssuedAt.Time().Unix(),
			"sub": verified.Claims.Subject, "aud": verified.Claims.Audience, "iss": verified.Claims.Issuer, "jti": verified.Claims.ID})
		return
	}
	if refresh, active, inspectErr := s.store.InspectRefreshToken(r.Context(), raw); inspectErr == nil && refresh.RealmID == realm.ID && refresh.ClientID == client.ID {
		writeJSON(w, http.StatusOK, map[string]any{"active": active, "client_id": client.ClientID,
			"scope": strings.Join(refresh.Scope, " "), "exp": refresh.ExpiresAt.Unix()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"active": false})
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	realm, err := s.realmFromPath(r)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	client, ok, err := s.authenticateOIDCClient(r, realm)
	if err != nil || !ok {
		writeOAuthError(w, r, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	raw := r.Form.Get("token")
	if refresh, _, inspectErr := s.store.InspectRefreshToken(r.Context(), raw); inspectErr == nil && refresh.ClientID == client.ID {
		_ = s.store.RevokeRefreshToken(r.Context(), raw)
	} else if verified, verifyErr := s.oidc.Verify(r.Context(), realm, raw, client.ClientID); verifyErr == nil {
		if jti, parseErr := uuid.Parse(verified.Claims.ID); parseErr == nil && verified.Claims.Expiry != nil {
			_ = s.store.RevokeAccessJTI(r.Context(), jti, verified.Claims.Expiry.Time())
		}
	}
	s.audit(r, &realm.ID, nil, client.ClientID, "TOKEN_REVOKED", "SUCCESS", "client", client.ClientID, nil)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) oidcLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		_ = r.ParseForm()
	}
	realm, err := s.realmFromPath(r)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "realm_not_found", "Realm을 찾을 수 없습니다.")
		return
	}
	values := r.URL.Query()
	if r.Method == http.MethodPost {
		values = r.Form
	}
	var client *domain.Client
	if hint := values.Get("id_token_hint"); hint != "" {
		if verified, verifyErr := s.oidc.Verify(r.Context(), realm, hint, ""); verifyErr == nil {
			if found, findErr := s.store.ClientByIdentifier(r.Context(), realm.ID, verified.Extra.AuthorizedParty); findErr == nil {
				client = &found
			}
		}
	}
	redirectTo := ""
	if requested := values.Get("post_logout_redirect_uri"); requested != "" && client != nil && store.PostLogoutURIAllowed(*client, requested) {
		redirectTo = requested
	}
	if session, sessionErr := s.store.SessionByToken(r.Context(), sessionCookie(r)); sessionErr == nil && session.Session.RealmID == realm.ID {
		_ = s.store.RevokeSession(r.Context(), session.Session.ID)
		s.audit(r, &realm.ID, &session.User.ID, session.User.Username, "LOGOUT", "SUCCESS", "session", session.Session.ID.String(), nil)
	}
	s.clearBrowserCookies(w, r)
	if redirectTo != "" {
		parsed, _ := url.Parse(redirectTo)
		query := parsed.Query()
		if state := values.Get("state"); state != "" {
			query.Set("state", state)
		}
		parsed.RawQuery = query.Encode()
		http.Redirect(w, r, parsed.String(), http.StatusFound)
		return
	}
	if r.Method == http.MethodPost {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/login?logged_out=1", http.StatusFound)
}

func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if len(value) < 8 || !strings.EqualFold(value[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(value[7:])
}

func validatedScopes(requested string, allowed []string, requireOpenID bool) ([]string, error) {
	values := allowed
	if strings.TrimSpace(requested) != "" {
		values = strings.Fields(requested)
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, scope := range values {
		if !slices.Contains(allowed, scope) {
			return nil, errors.New("one or more requested scopes are not allowed")
		}
		if !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}
	if requireOpenID && !seen["openid"] {
		return nil, errors.New("the openid scope is required")
	}
	return result, nil
}

func writeOAuthError(w http.ResponseWriter, r *http.Request, status int, code, description string) {
	writeJSON(w, status, map[string]any{"error": code, "error_description": description})
}

func redirectOAuthError(w http.ResponseWriter, r *http.Request, target, state, issuer, code, description string) {
	parsed, _ := url.Parse(target)
	query := parsed.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	query.Set("iss", issuer)
	if state != "" {
		query.Set("state", state)
	}
	parsed.RawQuery = query.Encode()
	http.Redirect(w, r, parsed.String(), http.StatusFound)
}

func writeBearerError(w http.ResponseWriter, r *http.Request, code string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`"`)
	writeOAuthError(w, r, http.StatusUnauthorized, code, "access token is invalid or expired")
}

var _ = time.Second
