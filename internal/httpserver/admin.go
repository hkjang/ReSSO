package httpserver

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/store"
)

func (s *Server) adminRoutes(r chi.Router) {
	r.Get("/dashboard", s.adminDashboard)
	r.Get("/quick-search", s.adminQuickSearch)
	r.Get("/realms", s.adminListRealms)
	r.With(s.requirePlatformAdmin).Post("/realms", s.adminCreateRealm)
	r.Route("/realms/{realmID}", func(r chi.Router) {
		r.Use(s.requireRealmAccess)
		r.Get("/", s.adminGetRealm)
		r.Put("/", s.adminUpdateRealm)
		r.Get("/users", s.adminListUsers)
		r.Post("/users", s.adminCreateUser)
		r.Put("/users/{userID}", s.adminUpdateUser)
		r.Put("/users/{userID}/password", s.adminResetPassword)
		r.Post("/users/{userID}/unlock", s.adminUnlockUser)
		r.Get("/users/{userID}/role-mappings", s.adminGetUserRoleMappings)
		r.Put("/users/{userID}/role-mappings", s.adminReplaceUserRoleMappings)
		r.Get("/user-federations", s.adminListLDAPFederations)
		r.Post("/user-federations", s.adminCreateLDAPFederation)
		r.Get("/user-federations/{federationID}", s.adminGetLDAPFederation)
		r.Put("/user-federations/{federationID}", s.adminUpdateLDAPFederation)
		r.Delete("/user-federations/{federationID}", s.adminDeleteLDAPFederation)
		r.Post("/user-federations/{federationID}/test-connection", s.adminTestLDAPConnection)
		r.Post("/user-federations/{federationID}/test-authentication", s.adminTestLDAPAuthentication)
		r.Post("/user-federations/{federationID}/sync", s.adminSyncLDAPFederation)
		r.Get("/clients", s.adminListClients)
		r.Post("/clients", s.adminCreateClient)
		r.Put("/clients/{clientID}", s.adminUpdateClient)
		r.Post("/clients/{clientID}/rotate-secret", s.adminRotateClientSecret)
		r.Get("/clients/{clientID}/roles", s.adminListClientRoles)
		r.Post("/clients/{clientID}/roles", s.adminCreateClientRole)
		r.Delete("/clients/{clientID}/roles/{roleID}", s.adminDeleteClientRole)
		r.Get("/roles", s.adminListRoles)
		r.Post("/roles", s.adminCreateRole)
		r.Put("/roles/{roleID}", s.adminUpdateRole)
		r.Delete("/roles/{roleID}", s.adminDeleteRole)
		r.Get("/sessions", s.adminListRealmSessions)
		r.Delete("/sessions/{sessionID}", s.adminRevokeSession)
		r.Get("/keys", s.adminListKeys)
		r.Post("/keys/rotate", s.adminRotateKey)
	})
	r.Get("/approvals", s.adminListApprovals)
	r.Post("/approvals/{requestID}/decision", s.adminDecideApproval)
	r.Get("/audit", s.adminListAudit)
	r.Get("/audit/event-types", s.adminListAuditEventTypes)
	r.With(s.requirePlatformAdmin).Get("/system-logs", s.adminListSystemLogs)
}

func parseUUIDParam(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, name))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", "요청 ID가 올바르지 않습니다.")
		return uuid.Nil, false
	}
	return id, true
}

func queryInt(r *http.Request, name string, fallback int) int {
	value, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || value < 0 {
		return fallback
	}
	return value
}

// signingKeyAdvisoryDays is when the console starts suggesting a rotation. It
// is advice, not a failure: a key past it still signs and verifies normally.
const signingKeyAdvisoryDays = 180

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	var realmID *uuid.UUID
	if !principal.PlatformAdmin {
		realmID = &principal.RealmID
	}
	var counts struct {
		Realms, Users, Clients, ActiveSessions, PendingApprovals int
	}
	err := s.store.Pool.QueryRow(r.Context(), `SELECT
		(SELECT count(*) FROM realms WHERE ($1::uuid IS NULL OR id=$1)),
		(SELECT count(*) FROM users WHERE ($1::uuid IS NULL OR realm_id=$1)),
		(SELECT count(*) FROM clients WHERE ($1::uuid IS NULL OR realm_id=$1)),
		(SELECT count(*) FROM sso_sessions WHERE revoked_at IS NULL AND expires_at>now()
		    AND ($1::uuid IS NULL OR realm_id=$1)),
		(SELECT count(*) FROM approval_requests WHERE status='PENDING'
		    AND ($1::uuid IS NULL OR realm_id=$1))`, realmID).Scan(&counts.Realms, &counts.Users,
		&counts.Clients, &counts.ActiveSessions, &counts.PendingApprovals)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	var readiness struct {
		IssuerHTTPS, SigningKeysReady                    bool
		FederationFailures, LockedUsers, ExpiringAPIKeys int
		// Signing keys are never rotated automatically, and nothing told the
		// operator when one had aged: a Realm could run for years on the key
		// created at bootstrap while the console reported it as healthy.
		AgingSigningKeys int
	}
	err = s.store.Pool.QueryRow(r.Context(), `SELECT
		NOT EXISTS(SELECT 1 FROM realms WHERE enabled=true AND ($1::uuid IS NULL OR id=$1)
		    AND issuer_url NOT LIKE 'https://%'),
		NOT EXISTS(SELECT 1 FROM realms r WHERE r.enabled=true AND ($1::uuid IS NULL OR r.id=$1)
		    AND NOT EXISTS(SELECT 1 FROM signing_keys k WHERE k.realm_id=r.id AND k.status='ACTIVE')),
		(SELECT count(*) FROM user_federations WHERE enabled=true AND last_sync_status='FAILURE'
		    AND ($1::uuid IS NULL OR realm_id=$1)),
		(SELECT count(*) FROM users WHERE locked_until>now() AND ($1::uuid IS NULL OR realm_id=$1)),
		(SELECT count(*) FROM personal_api_keys k JOIN users u ON u.id=k.user_id
		    WHERE k.revoked_at IS NULL AND k.expires_at BETWEEN now() AND now()+interval '7 days'
		    AND ($1::uuid IS NULL OR u.realm_id=$1)),
		(SELECT count(*) FROM signing_keys k JOIN realms r ON r.id=k.realm_id
		    WHERE k.status='ACTIVE' AND r.enabled=true AND k.created_at < now()-make_interval(days => $2)
		    AND ($1::uuid IS NULL OR k.realm_id=$1))`, realmID, signingKeyAdvisoryDays).Scan(&readiness.IssuerHTTPS,
		&readiness.SigningKeysReady, &readiness.FederationFailures, &readiness.LockedUsers,
		&readiness.ExpiringAPIKeys, &readiness.AgingSigningKeys)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	// Reported rather than judged here: a difference between the two clocks
	// shifts every session and token lifetime by its size, and the refresh
	// rotation grace is where it stops being a shift and starts signing people
	// out — so that window is the threshold worth naming.
	skew, roundTrip, skewErr := s.store.ClockSkew(r.Context())
	if skewErr != nil {
		s.logger.Warn("clock difference could not be measured",
			"trace_id", traceIDFrom(r.Context()), "error", skewErr)
	}
	writeJSON(w, http.StatusOK, map[string]any{"realms": counts.Realms, "users": counts.Users,
		"clients": counts.Clients, "active_sessions": counts.ActiveSessions, "pending_approvals": counts.PendingApprovals,
		"readiness": map[string]any{"issuer_https": readiness.IssuerHTTPS, "signing_keys_ready": readiness.SigningKeysReady,
			"federation_failures": readiness.FederationFailures, "locked_users": readiness.LockedUsers,
			"expiring_api_keys": readiness.ExpiringAPIKeys, "aging_signing_keys": readiness.AgingSigningKeys,
			"signing_key_advisory_days":   signingKeyAdvisoryDays,
			"clock_skew_seconds":          skew.Seconds(),
			"clock_skew_round_trip_ms":    roundTrip.Milliseconds(),
			"clock_skew_advisory_seconds": store.RefreshRotationGrace.Seconds()}})
}

func (s *Server) adminListRealms(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	var items any
	var err error
	if principal.PlatformAdmin {
		items, err = s.store.ListRealms(r.Context())
	} else {
		var realm any
		realm, err = s.store.RealmByID(r.Context(), principal.RealmID)
		if err == nil {
			items = []any{realm}
		}
	}
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminGetRealm(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	realm, err := s.store.RealmByID(r.Context(), id)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, realm)
}

func (s *Server) adminCreateRealm(w http.ResponseWriter, r *http.Request) {
	var input store.CreateRealmInput
	if !decodeJSON(w, r, &input) {
		return
	}
	realm, err := s.store.CreateRealm(r.Context(), input)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if err := s.store.EnsureActiveSigningKey(r.Context(), realm.ID); err != nil {
		s.logger.Error("initial realm key creation failed", "realm_id", realm.ID, "error", err)
		writeError(w, r, http.StatusInternalServerError, "key_creation_failed", "Realm은 생성되었으나 서명 키를 만들지 못했습니다.")
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realm.ID, &principal.UserID, principal.Username, "REALM_CREATE", "SUCCESS", "realm", realm.ID.String(), nil)
	writeJSON(w, http.StatusCreated, realm)
}

func (s *Server) adminUpdateRealm(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	var input store.UpdateRealmInput
	if !decodeJSON(w, r, &input) {
		return
	}
	principal, _ := principalFrom(r.Context())
	// Suspending a Realm now stops its sessions and its API keys, not just new
	// logins. Applied to the Realm the administrator is signed in to, that
	// ends the very session making the request and every key that could undo
	// it, leaving no way back except editing the database by hand. Other
	// Realms can still be suspended, which is what the flag is for.
	if !input.Enabled && id == principal.RealmID {
		writeError(w, r, http.StatusConflict, "realm_self_disable",
			"자신이 로그인한 Realm은 비활성화할 수 없습니다. 비활성화하면 이 Realm의 모든 세션과 API 키가 중단되어 되돌릴 수단이 남지 않습니다.")
		return
	}
	realm, err := s.store.UpdateRealm(r.Context(), id, input)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, &id, &principal.UserID, principal.Username, "REALM_UPDATE", "SUCCESS", "realm", id.String(), map[string]any{"approval_enabled": realm.ApprovalEnabled})
	writeJSON(w, http.StatusOK, realm)
}

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	query := r.URL.Query().Get("q")
	sort := store.UserSort{Column: r.URL.Query().Get("sort"), Descending: r.URL.Query().Get("order") == "desc"}
	items, err := s.store.ListUsers(r.Context(), realmID, query, sort, queryInt(r, "limit", 100), queryInt(r, "offset", 0))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	total, err := s.store.CountUsers(r.Context(), realmID, query)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	var input store.CreateUserInput
	if !decodeJSON(w, r, &input) {
		return
	}
	user, err := s.store.CreateUser(r.Context(), realmID, input)
	if err != nil {
		if errors.Is(err, store.ErrInvalidInput) {
			writeStoreError(w, r, err)
			return
		}
		writeStoreError(w, r, err)
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "USER_CREATE", "SUCCESS", "user", user.ID.String(), nil)
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) adminUpdateUser(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	userID, ok := parseUUIDParam(w, r, "userID")
	if !ok {
		return
	}
	current, err := s.store.UserByID(r.Context(), userID)
	if err != nil || current.RealmID != realmID {
		writeStoreError(w, r, store.ErrNotFound)
		return
	}
	principal, _ := principalFrom(r.Context())
	if current.PlatformAdmin && !principal.PlatformAdmin {
		writeError(w, r, http.StatusForbidden, "insufficient_permission", "플랫폼 관리자 계정은 플랫폼 관리자만 변경할 수 있습니다.")
		return
	}
	var input store.UpdateUserInput
	if !decodeJSON(w, r, &input) {
		return
	}
	user, err := s.store.UpdateUser(r.Context(), userID, input)
	if errors.Is(err, store.ErrInvalidManager) {
		writeError(w, r, http.StatusBadRequest, "invalid_manager",
			"승인자는 본인이 아닌, 같은 Realm에 속한 다른 사용자여야 합니다.")
		return
	}
	if errors.Is(err, store.ErrFederationReadOnly) {
		writeError(w, r, http.StatusConflict, "federation_read_only", "READ_ONLY LDAP 계정은 원본 디렉터리에서 수정하세요.")
		return
	}
	if errors.Is(err, store.ErrFederationOperation) {
		writeError(w, r, http.StatusBadGateway, "ldap_update_failed", "LDAP 디렉터리에서 사용자 정보를 변경하지 못했습니다.")
		return
	}
	if err != nil || user.RealmID != realmID {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, &realmID, &principal.UserID, principal.Username, "USER_UPDATE", "SUCCESS", "user", user.ID.String(), userAuditDetail(current, user))
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) adminResetPassword(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	userID, ok := parseUUIDParam(w, r, "userID")
	if !ok {
		return
	}
	user, err := s.store.UserByID(r.Context(), userID)
	if err != nil || user.RealmID != realmID {
		writeError(w, r, http.StatusNotFound, "not_found", "사용자를 찾을 수 없습니다.")
		return
	}
	principal, _ := principalFrom(r.Context())
	if user.PlatformAdmin && !principal.PlatformAdmin {
		writeError(w, r, http.StatusForbidden, "insufficient_permission", "플랫폼 관리자 계정은 플랫폼 관리자만 변경할 수 있습니다.")
		return
	}
	var input struct {
		NewPassword string `json:"new_password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := s.store.ChangePassword(r.Context(), userID, "", input.NewPassword, true); err != nil {
		if errors.Is(err, store.ErrFederationPasswordExternal) {
			writeError(w, r, http.StatusConflict, "federation_password_external", "이 계정의 비밀번호는 원본 LDAP 디렉터리에서 변경하세요.")
			return
		}
		if errors.Is(err, store.ErrFederationOperation) {
			writeError(w, r, http.StatusBadGateway, "ldap_password_update_failed", "LDAP 디렉터리에서 비밀번호를 변경하지 못했습니다.")
			return
		}
		writeStoreError(w, r, err)
		return
	}
	ended, detail := s.endOtherSessions(r, userID, nil)
	s.audit(r, &realmID, &principal.UserID, principal.Username, "PASSWORD_RESET",
		partialIfNot(ended), "user", userID.String(), detail)
	writeSessionsEnded(w, ended, detail,
		"비밀번호는 재설정되었지만 이 계정의 세션을 종료하지 못했습니다. 세션 화면에서 직접 종료하세요.",
		"비밀번호는 재설정되었고 이 계정의 세션도 종료했지만, 그 세션의 Refresh Token을 폐기하지 못했습니다. 연동 애플리케이션에서 계속 사용될 수 있습니다.")
}

func (s *Server) adminListClients(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	items, err := s.store.ListClients(r.Context(), realmID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminCreateClient(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	var input store.CreateClientInput
	if !decodeJSON(w, r, &input) {
		return
	}
	created, err := s.store.CreateClient(r.Context(), realmID, input)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "CLIENT_CREATE", "SUCCESS", "client", created.Client.ID.String(), nil)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) adminUpdateClient(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	clientID, ok := parseUUIDParam(w, r, "clientID")
	if !ok {
		return
	}
	current, err := s.store.ClientByID(r.Context(), clientID)
	if err != nil || current.RealmID != realmID {
		writeError(w, r, http.StatusNotFound, "not_found", "Client를 찾을 수 없습니다.")
		return
	}
	var input store.UpdateClientInput
	if !decodeJSON(w, r, &input) {
		return
	}
	client, err := s.store.UpdateClient(r.Context(), clientID, input)
	if err != nil || client.RealmID != realmID {
		if err == nil {
			err = store.ErrNotFound
		}
		writeStoreError(w, r, err)
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "CLIENT_UPDATE", "SUCCESS", "client", client.ID.String(), nil)
	writeJSON(w, http.StatusOK, client)
}

func (s *Server) adminRotateClientSecret(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	clientID, ok := parseUUIDParam(w, r, "clientID")
	if !ok {
		return
	}
	client, err := s.store.ClientByID(r.Context(), clientID)
	if err != nil || client.RealmID != realmID {
		writeError(w, r, http.StatusNotFound, "not_found", "Client를 찾을 수 없습니다.")
		return
	}
	secret, err := s.store.RotateClientSecret(r.Context(), clientID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "CLIENT_SECRET_ROTATE", "SUCCESS", "client", client.ID.String(), nil)
	writeJSON(w, http.StatusOK, map[string]any{"client_secret": secret})
}

func (s *Server) adminListRoles(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	items, err := s.store.ListRoles(r.Context(), realmID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminCreateRole(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	role, err := s.store.CreateRole(r.Context(), realmID, input.Name, input.Description)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "ROLE_CREATE", "SUCCESS", "role", role.ID.String(), nil)
	writeJSON(w, http.StatusCreated, role)
}

func (s *Server) adminUpdateRole(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	roleID, ok := parseUUIDParam(w, r, "roleID")
	if !ok {
		return
	}
	var input struct {
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	role, err := s.store.UpdateRole(r.Context(), realmID, roleID, input.Description)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "ROLE_UPDATE", "SUCCESS", "role", role.ID.String(), nil)
	writeJSON(w, http.StatusOK, role)
}

func (s *Server) adminDeleteRole(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	roleID, ok := parseUUIDParam(w, r, "roleID")
	if !ok {
		return
	}
	if err := s.store.DeleteRole(r.Context(), realmID, roleID); err != nil {
		writeStoreError(w, r, err)
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "ROLE_DELETE", "SUCCESS", "role", roleID.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminListClientRoles(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	clientID, ok := parseUUIDParam(w, r, "clientID")
	if !ok {
		return
	}
	client, err := s.store.ClientByID(r.Context(), clientID)
	if err != nil || client.RealmID != realmID {
		writeStoreError(w, r, store.ErrNotFound)
		return
	}
	items, err := s.store.ListClientRoles(r.Context(), realmID, clientID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminCreateClientRole(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	clientID, ok := parseUUIDParam(w, r, "clientID")
	if !ok {
		return
	}
	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	role, err := s.store.CreateClientRole(r.Context(), realmID, clientID, input.Name, input.Description)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "CLIENT_ROLE_CREATE", "SUCCESS", "client_role", role.ID.String(), nil)
	writeJSON(w, http.StatusCreated, role)
}

func (s *Server) adminDeleteClientRole(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	clientID, ok := parseUUIDParam(w, r, "clientID")
	if !ok {
		return
	}
	roleID, ok := parseUUIDParam(w, r, "roleID")
	if !ok {
		return
	}
	if err := s.store.DeleteClientRole(r.Context(), realmID, clientID, roleID); err != nil {
		writeStoreError(w, r, err)
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "CLIENT_ROLE_DELETE", "SUCCESS", "client_role", roleID.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

// adminUnlockUser releases a lockout without forcing a password change.
func (s *Server) adminUnlockUser(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	userID, ok := parseUUIDParam(w, r, "userID")
	if !ok {
		return
	}
	wasLocked, err := s.store.UnlockUser(r.Context(), realmID, userID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	user, err := s.store.UserByID(r.Context(), userID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "USER_UNLOCK", "SUCCESS", "user",
		userID.String(), map[string]any{"was_locked": wasLocked})
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) adminGetUserRoleMappings(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	userID, ok := parseUUIDParam(w, r, "userID")
	if !ok {
		return
	}
	mappings, err := s.store.GetUserRoleMappings(r.Context(), realmID, userID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, mappings)
}

func (s *Server) adminReplaceUserRoleMappings(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	userID, ok := parseUUIDParam(w, r, "userID")
	if !ok {
		return
	}
	target, err := s.store.UserByID(r.Context(), userID)
	if err != nil || target.RealmID != realmID {
		writeStoreError(w, r, store.ErrNotFound)
		return
	}
	principal, _ := principalFrom(r.Context())
	if target.PlatformAdmin && !principal.PlatformAdmin {
		writeError(w, r, http.StatusForbidden, "insufficient_permission", "플랫폼 관리자 계정은 플랫폼 관리자만 변경할 수 있습니다.")
		return
	}
	var input struct {
		RealmRoleIDs  []uuid.UUID `json:"realm_role_ids"`
		ClientRoleIDs []uuid.UUID `json:"client_role_ids"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	mappings, err := s.store.ReplaceUserRoleMappings(r.Context(), realmID, userID, input.RealmRoleIDs, input.ClientRoleIDs)
	if err != nil {
		// Only sentences the store wrote reach the caller. Echoing whatever
		// came back put database text in the response, under a status that
		// blamed the request for a write that failed on our side.
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, &realmID, &principal.UserID, principal.Username, "USER_ROLE_MAPPING_UPDATE", "SUCCESS", "user", userID.String(),
		map[string]any{"realm_roles": len(mappings.RealmRoleIDs), "client_roles": len(mappings.ClientRoleIDs)})
	writeJSON(w, http.StatusOK, mappings)
}

func (s *Server) adminListRealmSessions(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	items, err := s.store.ListSessions(r.Context(), &realmID, nil, queryInt(r, "limit", 200))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminRevokeSession(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	sessionID, ok := parseUUIDParam(w, r, "sessionID")
	if !ok {
		return
	}
	var sessionRealmID uuid.UUID
	var targetPlatformAdmin bool
	if err := s.store.Pool.QueryRow(r.Context(), `SELECT s.realm_id,u.platform_admin FROM sso_sessions s
		JOIN users u ON u.id=s.user_id WHERE s.id=$1`, sessionID).Scan(&sessionRealmID, &targetPlatformAdmin); err != nil || sessionRealmID != realmID {
		writeError(w, r, http.StatusNotFound, "not_found", "세션을 찾을 수 없습니다.")
		return
	}
	principal, _ := principalFrom(r.Context())
	if targetPlatformAdmin && !principal.PlatformAdmin {
		writeError(w, r, http.StatusForbidden, "insufficient_permission", "플랫폼 관리자 세션은 플랫폼 관리자만 종료할 수 있습니다.")
		return
	}
	// Every other sign-out in the service goes through this helper, which
	// tells apart a session that did not end from one that ended while its
	// refresh tokens survived. Calling the store directly and answering the
	// error meant an administrator who ended a session that really did end got
	// a failure, and the trail got no entry at all for it — the one record
	// saying that session was forced out.
	ended, detail := s.endSession(r, sessionID)
	s.audit(r, &realmID, &principal.UserID, principal.Username, "ADMIN_FORCE_LOGOUT",
		partialIfNot(ended), "session", sessionID.String(), detail)
	writeSessionEnded(w, ended,
		"세션은 종료했지만 이 세션의 Refresh Token을 폐기하지 못했습니다. 연동 애플리케이션에서 계속 사용될 수 있습니다.")
}

func (s *Server) adminListKeys(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	items, err := s.store.ListSigningKeys(r.Context(), realmID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	// The threshold travels with the keys so the screen showing them and the
	// dashboard counting them cannot disagree about the same key. The console
	// used to carry its own copy of the number with a comment promising it
	// matched, which is the kind of promise nothing enforces.
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "advisory_days": signingKeyAdvisoryDays})
}

func (s *Server) adminRotateKey(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	key, err := s.store.RotateSigningKey(r.Context(), realmID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "SIGNING_KEY_ROTATE", "SUCCESS", "signing_key", key.ID.String(), map[string]any{"kid": key.KID})
	writeJSON(w, http.StatusCreated, key)
}

func (s *Server) adminListApprovals(w http.ResponseWriter, r *http.Request) {
	var realmID *uuid.UUID
	principal, _ := principalFrom(r.Context())
	if !principal.PlatformAdmin {
		realmID = &principal.RealmID
	} else if raw := r.URL.Query().Get("realm_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_id", "Realm ID가 올바르지 않습니다.")
			return
		}
		realmID = &parsed
	}
	items, err := s.store.ListApprovalRequests(r.Context(), realmID, nil, nil)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminDecideApproval(w http.ResponseWriter, r *http.Request) {
	requestID, ok := parseUUIDParam(w, r, "requestID")
	if !ok {
		return
	}
	var input struct {
		Decision string `json:"decision"`
		Note     string `json:"note"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Decision != "approve" && input.Decision != "reject" {
		writeError(w, r, http.StatusBadRequest, "invalid_decision", "approve 또는 reject를 지정하세요.")
		return
	}
	principal, _ := principalFrom(r.Context())
	request, err := s.store.DecideApprovalRequest(r.Context(), requestID, principal.UserID,
		principal.PlatformAdmin, principal.RealmAdmin, principal.RealmID, input.Decision == "approve", input.Note)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, &request.RealmID, &principal.UserID, principal.Username, "APPROVAL_DECISION", "SUCCESS", "approval", request.ID.String(), map[string]any{"decision": request.Status})
	writeJSON(w, http.StatusOK, request)
}

func (s *Server) adminListAudit(w http.ResponseWriter, r *http.Request) {
	var realmID *uuid.UUID
	principal, _ := principalFrom(r.Context())
	if !principal.PlatformAdmin {
		realmID = &principal.RealmID
	} else if raw := r.URL.Query().Get("realm_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_id", "Realm ID가 올바르지 않습니다.")
			return
		}
		realmID = &parsed
	}
	page, err := s.store.ListAudit(r.Context(), store.AuditFilter{
		RealmID:   realmID,
		EventType: r.URL.Query().Get("event_type"),
		Result:    strings.ToUpper(r.URL.Query().Get("result")),
		Actor:     r.URL.Query().Get("actor"),
		TraceID:   r.URL.Query().Get("trace_id"),
		Ascending: r.URL.Query().Get("order") == "asc",
		Limit:     queryInt(r, "limit", 100),
		Offset:    queryInt(r, "offset", 0),
	})
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// adminListAuditEventTypes backs the console's event filter with the types the
// deployment has actually recorded.
func (s *Server) adminListAuditEventTypes(w http.ResponseWriter, r *http.Request) {
	var realmID *uuid.UUID
	principal, _ := principalFrom(r.Context())
	if !principal.PlatformAdmin {
		realmID = &principal.RealmID
	}
	types, err := s.store.AuditEventTypes(r.Context(), realmID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": types})
}

func (s *Server) adminListSystemLogs(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListSystemLogs(r.Context(), strings.ToUpper(r.URL.Query().Get("level")),
		r.URL.Query().Get("q"), strings.TrimSpace(r.URL.Query().Get("trace")),
		queryInt(r, "limit", 200), queryInt(r, "offset", 0))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminQuickSearch(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if len([]rune(query)) < 2 {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
		return
	}
	principal, _ := principalFrom(r.Context())
	var realmID *uuid.UUID
	if !principal.PlatformAdmin {
		realmID = &principal.RealmID
	}
	// The paths below must be routes the console actually has. They used to
	// point at /admin/realms/{id}/users and /admin/realms/{id}/clients, which
	// do not exist: selecting a user or a client fell through to the catch-all
	// route and threw the administrator out to their personal profile. The
	// Realm now travels as the query parameter the admin screens read, and the
	// term is carried along so the destination opens on the match.
	rows, err := s.store.Pool.Query(r.Context(), `
		SELECT kind,id,label,description,path,sort FROM (
		  SELECT 'realm' kind,id::text,name label,display_name description,
		    '/admin/realms/'||id::text path,1 sort
		  FROM realms WHERE ($2::uuid IS NULL OR id=$2) AND (name ILIKE '%'||$1||'%' OR display_name ILIKE '%'||$1||'%')
		  UNION ALL
		  SELECT 'user',u.id::text,u.username,u.email,
		    '/admin/users?realm='||r.name||'&q='||u.username,2
		  FROM users u JOIN realms r ON r.id=u.realm_id
		  WHERE ($2::uuid IS NULL OR u.realm_id=$2)
		    AND (u.username ILIKE '%'||$1||'%' OR u.email ILIKE '%'||$1||'%' OR u.display_name ILIKE '%'||$1||'%')
		  UNION ALL
		  SELECT 'client',c.id::text,c.client_id,c.name,
		    '/admin/clients?realm='||r.name||'&q='||c.client_id,3
		  FROM clients c JOIN realms r ON r.id=c.realm_id
		  WHERE ($2::uuid IS NULL OR c.realm_id=$2) AND (c.client_id ILIKE '%'||$1||'%' OR c.name ILIKE '%'||$1||'%')
		  UNION ALL
		  SELECT 'federation',f.id::text,f.name,f.connection_url,
		    '/admin/user-federation?realm='||r.name,4
		  FROM user_federations f JOIN realms r ON r.id=f.realm_id
		  WHERE ($2::uuid IS NULL OR f.realm_id=$2) AND (f.name ILIKE '%'||$1||'%' OR f.connection_url ILIKE '%'||$1||'%')
		) results ORDER BY sort,label LIMIT 20`, query, realmID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	defer rows.Close()
	items := make([]map[string]string, 0)
	for rows.Next() {
		item := map[string]string{}
		var kind, id, label, description, path string
		var sortKey int
		if err := rows.Scan(&kind, &id, &label, &description, &path, &sortKey); err != nil {
			writeStoreError(w, r, err)
			return
		}
		item["kind"], item["id"], item["label"], item["description"], item["path"] = kind, id, label, description, path
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
