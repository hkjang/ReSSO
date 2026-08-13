package httpserver

import (
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
	r.Post("/realms", s.adminCreateRealm)
	r.Get("/realms/{realmID}", s.adminGetRealm)
	r.Put("/realms/{realmID}", s.adminUpdateRealm)
	r.Get("/realms/{realmID}/users", s.adminListUsers)
	r.Post("/realms/{realmID}/users", s.adminCreateUser)
	r.Put("/realms/{realmID}/users/{userID}", s.adminUpdateUser)
	r.Put("/realms/{realmID}/users/{userID}/password", s.adminResetPassword)
	r.Get("/realms/{realmID}/clients", s.adminListClients)
	r.Post("/realms/{realmID}/clients", s.adminCreateClient)
	r.Put("/realms/{realmID}/clients/{clientID}", s.adminUpdateClient)
	r.Post("/realms/{realmID}/clients/{clientID}/rotate-secret", s.adminRotateClientSecret)
	r.Get("/realms/{realmID}/roles", s.adminListRoles)
	r.Post("/realms/{realmID}/roles", s.adminCreateRole)
	r.Get("/realms/{realmID}/sessions", s.adminListRealmSessions)
	r.Delete("/realms/{realmID}/sessions/{sessionID}", s.adminRevokeSession)
	r.Get("/realms/{realmID}/keys", s.adminListKeys)
	r.Post("/realms/{realmID}/keys/rotate", s.adminRotateKey)
	r.Get("/approvals", s.adminListApprovals)
	r.Post("/approvals/{requestID}/decision", s.adminDecideApproval)
	r.Get("/audit", s.adminListAudit)
	r.Get("/system-logs", s.adminListSystemLogs)
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

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	var counts struct {
		Realms, Users, Clients, ActiveSessions, PendingApprovals int
	}
	err := s.store.Pool.QueryRow(r.Context(), `SELECT
        (SELECT count(*) FROM realms),
        (SELECT count(*) FROM users),
        (SELECT count(*) FROM clients),
        (SELECT count(*) FROM sso_sessions WHERE revoked_at IS NULL AND expires_at>now()),
        (SELECT count(*) FROM approval_requests WHERE status='PENDING')`).Scan(&counts.Realms, &counts.Users,
		&counts.Clients, &counts.ActiveSessions, &counts.PendingApprovals)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"realms": counts.Realms, "users": counts.Users,
		"clients": counts.Clients, "active_sessions": counts.ActiveSessions, "pending_approvals": counts.PendingApprovals})
}

func (s *Server) adminListRealms(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListRealms(r.Context())
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
		writeError(w, r, http.StatusBadRequest, "realm_creation_failed", err.Error())
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
	realm, err := s.store.UpdateRealm(r.Context(), id, input)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "realm_update_failed", err.Error())
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &id, &principal.UserID, principal.Username, "REALM_UPDATE", "SUCCESS", "realm", id.String(), map[string]any{"approval_enabled": realm.ApprovalEnabled})
	writeJSON(w, http.StatusOK, realm)
}

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	items, err := s.store.ListUsers(r.Context(), realmID, r.URL.Query().Get("q"), queryInt(r, "limit", 100), queryInt(r, "offset", 0))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
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
		writeError(w, r, http.StatusBadRequest, "user_creation_failed", err.Error())
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
	var input store.UpdateUserInput
	if !decodeJSON(w, r, &input) {
		return
	}
	user, err := s.store.UpdateUser(r.Context(), userID, input)
	if err != nil || user.RealmID != realmID {
		writeStoreError(w, r, err)
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "USER_UPDATE", "SUCCESS", "user", user.ID.String(), map[string]any{"enabled": user.Enabled})
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
	var input struct {
		NewPassword string `json:"new_password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := s.store.ChangePassword(r.Context(), userID, "", input.NewPassword, true); err != nil {
		writeError(w, r, http.StatusBadRequest, "password_reset_failed", err.Error())
		return
	}
	_ = s.store.RevokeAllUserSessions(r.Context(), userID, nil)
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "PASSWORD_RESET", "SUCCESS", "user", userID.String(), nil)
	w.WriteHeader(http.StatusNoContent)
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
		writeError(w, r, http.StatusBadRequest, "client_creation_failed", err.Error())
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
		writeError(w, r, http.StatusBadRequest, "role_creation_failed", err.Error())
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "ROLE_CREATE", "SUCCESS", "role", role.ID.String(), nil)
	writeJSON(w, http.StatusCreated, role)
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
	if err := s.store.RevokeSession(r.Context(), sessionID); err != nil {
		writeStoreError(w, r, err)
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "ADMIN_FORCE_LOGOUT", "SUCCESS", "session", sessionID.String(), nil)
	w.WriteHeader(http.StatusNoContent)
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
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
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
	if raw := r.URL.Query().Get("realm_id"); raw != "" {
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
	request, err := s.store.DecideApprovalRequest(r.Context(), requestID, principal.UserID, true, input.Decision == "approve", input.Note)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, &request.RealmID, &principal.UserID, principal.Username, "APPROVAL_DECISION", "SUCCESS", "approval", request.ID.String(), map[string]any{"decision": request.Status})
	writeJSON(w, http.StatusOK, request)
}

func (s *Server) adminListAudit(w http.ResponseWriter, r *http.Request) {
	var realmID *uuid.UUID
	if raw := r.URL.Query().Get("realm_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_id", "Realm ID가 올바르지 않습니다.")
			return
		}
		realmID = &parsed
	}
	items, err := s.store.ListAudit(r.Context(), realmID, queryInt(r, "limit", 100), queryInt(r, "offset", 0))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminListSystemLogs(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListSystemLogs(r.Context(), strings.ToUpper(r.URL.Query().Get("level")),
		r.URL.Query().Get("q"), queryInt(r, "limit", 200), queryInt(r, "offset", 0))
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
	rows, err := s.store.Pool.Query(r.Context(), `
        SELECT kind,id,label,description,path FROM (
          SELECT 'realm' kind,id::text,name label,display_name description,'/admin/realms/'||id::text path
          FROM realms WHERE name ILIKE '%'||$1||'%' OR display_name ILIKE '%'||$1||'%'
          UNION ALL
          SELECT 'user',u.id::text,u.username,u.email,'/admin/realms/'||u.realm_id::text||'/users'
          FROM users u WHERE u.username ILIKE '%'||$1||'%' OR u.email ILIKE '%'||$1||'%'
          UNION ALL
          SELECT 'client',c.id::text,c.client_id,c.name,'/admin/realms/'||c.realm_id::text||'/clients'
          FROM clients c WHERE c.client_id ILIKE '%'||$1||'%' OR c.name ILIKE '%'||$1||'%'
        ) results LIMIT 20`, query)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	defer rows.Close()
	items := make([]map[string]string, 0)
	for rows.Next() {
		item := map[string]string{}
		var kind, id, label, description, path string
		if err := rows.Scan(&kind, &id, &label, &description, &path); err != nil {
			writeStoreError(w, r, err)
			return
		}
		item["kind"], item["id"], item["label"], item["description"], item["path"] = kind, id, label, description, path
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
