package httpserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/config"
	"github.com/hkjang/ReSSO/internal/domain"
	"github.com/hkjang/ReSSO/internal/store"
	"github.com/hkjang/ReSSO/internal/version"
)

const mcpProtocolVersion = "2025-06-18"

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (s *Server) mcpProtectedResource(w http.ResponseWriter, r *http.Request) {
	master, err := s.store.RealmByName(r.Context(), config.DefaultBootstrapRealm)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	scheme := "http"
	if s.requestIsSecure(r) {
		scheme = "https"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 scheme + "://" + r.Host + "/mcp",
		"authorization_servers":    []string{master.IssuerURL},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"mcp:read", "admin:read"},
	})
}

func (s *Server) mcpMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "POST")
	writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "MCP Streamable HTTP 요청은 POST를 사용하세요.")
}

func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		parsed, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(parsed.Host, r.Host) {
			writeError(w, r, http.StatusForbidden, "invalid_origin", "MCP 요청 Origin이 서버 Host와 일치하지 않습니다.")
			return
		}
	}
	principal, err := s.authenticateMCPPrincipal(r)
	if err != nil || !slices.Contains(principal.Scopes, "mcp:read") {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="/.well-known/oauth-protected-resource", scope="mcp:read"`)
		writeError(w, r, http.StatusUnauthorized, "authentication_required", "mcp:read 범위의 개인 API 키가 필요합니다.")
		return
	}
	var request mcpRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&request); err != nil || request.JSONRPC != "2.0" || request.Method == "" {
		s.writeMCPError(w, request.ID, -32600, "Invalid Request", nil)
		return
	}
	if request.Method == "notifications/initialized" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("MCP-Protocol-Version", mcpProtocolVersion)
	switch request.Method {
	case "initialize":
		writeJSON(w, http.StatusOK, mcpResponse{JSONRPC: "2.0", ID: request.ID, Result: map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "ReSSO", "version": version.Version},
			"instructions":    "ReSSO의 Realm, Client, User 및 상태를 읽기 전용으로 조회합니다. 비밀정보는 반환하지 않습니다.",
		}})
	case "ping":
		writeJSON(w, http.StatusOK, mcpResponse{JSONRPC: "2.0", ID: request.ID, Result: map[string]any{}})
	case "tools/list":
		writeJSON(w, http.StatusOK, mcpResponse{JSONRPC: "2.0", ID: request.ID, Result: map[string]any{"tools": s.mcpTools(principal)}})
	case "tools/call":
		result, callErr := s.callMCPTool(r, principal, request.Params)
		s.auditMCPCall(r, principal, request.Params, callErr)
		if callErr != nil {
			writeJSON(w, http.StatusOK, mcpResponse{JSONRPC: "2.0", ID: request.ID, Result: map[string]any{
				"content": []any{map[string]any{"type": "text", "text": callErr.Error()}}, "isError": true,
			}})
			return
		}
		writeJSON(w, http.StatusOK, mcpResponse{JSONRPC: "2.0", ID: request.ID, Result: result})
	default:
		s.writeMCPError(w, request.ID, -32601, "Method not found", nil)
	}
}

func (s *Server) authenticateMCPPrincipal(r *http.Request) (domain.Principal, error) {
	raw := bearerToken(r)
	if principal, err := s.store.AuthenticateAPIKey(r.Context(), raw); err == nil {
		return principal, nil
	}
	realm, err := s.store.RealmByName(r.Context(), config.DefaultBootstrapRealm)
	if err != nil {
		return domain.Principal{}, err
	}
	if !realm.Enabled {
		return domain.Principal{}, errors.New("MCP authorization Realm is unavailable")
	}
	verified, err := s.oidc.Verify(r.Context(), realm, raw, "")
	scopes := strings.Fields(verified.Extra.Scope)
	if err != nil || verified.Extra.Type != "Bearer" ||
		!slices.Contains(scopes, "mcp:read") || verified.Extra.AuthorizedParty == "" ||
		len(verified.Claims.Audience) != 1 || verified.Claims.Audience[0] != verified.Extra.AuthorizedParty {
		return domain.Principal{}, errors.New("invalid MCP bearer token")
	}
	userID, err := uuid.Parse(verified.Claims.Subject)
	if err != nil {
		return domain.Principal{}, errors.New("MCP access token must represent a user")
	}
	sessionID, err := uuid.Parse(verified.Extra.SessionID)
	if err != nil || verified.Extra.SessionState != verified.Extra.SessionID {
		return domain.Principal{}, errors.New("MCP access token must be bound to a user session")
	}
	if err := s.store.ValidateActiveSessionBinding(r.Context(), sessionID, userID, realm.ID); err != nil {
		return domain.Principal{}, errors.New("MCP access token session is unavailable")
	}
	user, err := s.store.UserByID(r.Context(), userID)
	if err != nil || !user.Enabled || user.RealmID != realm.ID {
		return domain.Principal{}, errors.New("MCP user is unavailable")
	}
	realmAdmin, err := s.store.UserHasRealmRole(r.Context(), user.ID, "realm-admin")
	if err != nil {
		return domain.Principal{}, errors.New("MCP user authorization is unavailable")
	}
	return domain.Principal{UserID: user.ID, RealmID: user.RealmID, Username: user.Username,
		PlatformAdmin: user.PlatformAdmin, RealmAdmin: realmAdmin, Scopes: scopes}, nil
}

// auditMCPCall records an agent reading people or relying parties.
//
// Nothing about this endpoint was recorded before, which left an operator with
// no way to answer the question a disclosure prompts — was our directory read,
// and by whom — and no trace of it going forward either. An agent acting on
// somebody's behalf through a long-lived key is exactly the access an audit
// obligation is about.
//
// Only the tools that return people and relying parties are recorded. Service
// status is harmless and an agent may poll it, and filling a year of retention
// with that would bury the entries worth finding. Refusals are recorded too:
// an attempt that was turned away is the signal that somebody tried.
func (s *Server) auditMCPCall(r *http.Request, principal domain.Principal, raw json.RawMessage, callErr error) {
	var call struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &call); err != nil || call.Name == "" {
		return
	}
	if !slices.Contains(auditedMCPTools, call.Name) {
		return
	}
	outcome := "SUCCESS"
	detail := map[string]any{"tool": call.Name}
	if callErr != nil {
		outcome = "FAILURE"
		detail["refused"] = callErr.Error()
	}
	realmID := principal.RealmID
	s.audit(r, &realmID, &principal.UserID, principal.Username, "MCP_TOOL_CALL", outcome,
		"tool", call.Name, detail)
}

// auditedMCPTools are the ones that return records about people or the relying
// parties they sign in to. They are also the ones gated on admin:read.
var auditedMCPTools = []string{
	"resso_search_users", "resso_list_clients", "resso_list_realms", "resso_list_user_federations",
}

func (s *Server) writeMCPError(w http.ResponseWriter, id json.RawMessage, code int, message string, data any) {
	writeJSON(w, http.StatusOK, mcpResponse{JSONRPC: "2.0", ID: id, Error: &mcpError{Code: code, Message: message, Data: data}})
}

// mcpReadsDirectory reports whether a principal may read the records of
// people and relying parties rather than just the service's own health.
//
// Every user may mint a personal API key carrying mcp:read, so that scope
// alone establishes only that an agent is acting for someone. The REST routes
// returning these same records require an administrator holding admin:read,
// and the member list of a realm is precisely what turns one compromised
// account into a target list for everyone else, so the bar has to match.
func mcpReadsDirectory(principal domain.Principal) bool {
	return (principal.PlatformAdmin || principal.RealmAdmin) && slices.Contains(principal.Scopes, "admin:read")
}

func (s *Server) mcpTools(principal domain.Principal) []any {
	tools := []any{
		map[string]any{"name": "resso_service_status", "description": "ReSSO 버전과 데이터베이스 상태를 조회합니다.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}},
	}
	if mcpReadsDirectory(principal) {
		tools = append(tools,
			map[string]any{"name": "resso_list_clients", "description": "접근 가능한 Realm의 OIDC Client 목록을 조회합니다. Secret은 반환하지 않습니다.",
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"realm_id": map[string]any{"type": "string", "format": "uuid"}}, "additionalProperties": false}},
			map[string]any{"name": "resso_search_users", "description": "접근 가능한 Realm에서 사용자를 검색합니다.",
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
					"realm_id": map[string]any{"type": "string", "format": "uuid"}, "query": map[string]any{"type": "string", "minLength": 2}},
					"required": []string{"query"}, "additionalProperties": false}})
	}
	if principal.PlatformAdmin && slices.Contains(principal.Scopes, "admin:read") {
		tools = append(tools, map[string]any{"name": "resso_list_realms", "description": "모든 Realm의 공개 운영 설정을 조회합니다.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}})
		tools = append(tools, map[string]any{"name": "resso_list_user_federations", "description": "Realm의 LDAP User Federation 연결 및 동기화 상태를 조회합니다. 자격증명은 반환하지 않습니다.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"realm_id": map[string]any{"type": "string", "format": "uuid"}}, "additionalProperties": false}})
	}
	return tools
}

func (s *Server) callMCPTool(r *http.Request, principal domain.Principal, raw json.RawMessage) (map[string]any, error) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &call); err != nil {
		return nil, errors.New("도구 호출 형식이 올바르지 않습니다")
	}
	var output any
	var err error
	switch call.Name {
	case "resso_service_status":
		if pingErr := s.store.Pool.Ping(r.Context()); pingErr != nil {
			output = map[string]any{"status": "not_ready", "version": version.Current()}
		} else {
			output = map[string]any{"status": "ready", "version": version.Current()}
		}
	case "resso_list_realms":
		if !principal.PlatformAdmin || !slices.Contains(principal.Scopes, "admin:read") {
			return nil, errors.New("admin:read 권한이 필요합니다")
		}
		output, err = s.store.ListRealms(r.Context())
	case "resso_list_clients":
		realmID, parseErr := mcpDirectoryRealm(call.Arguments, principal)
		if parseErr != nil {
			return nil, parseErr
		}
		output, err = s.store.ListClients(r.Context(), realmID)
	case "resso_list_user_federations":
		if !principal.PlatformAdmin || !slices.Contains(principal.Scopes, "admin:read") {
			return nil, errors.New("admin:read 권한이 필요합니다")
		}
		realmID, parseErr := mcpRealmID(call.Arguments, principal)
		if parseErr != nil {
			return nil, parseErr
		}
		providers, listErr := s.store.ListLDAPFederations(r.Context(), realmID)
		if listErr != nil {
			err = listErr
			break
		}
		items := make([]map[string]any, 0, len(providers))
		for _, provider := range providers {
			items = append(items, map[string]any{"id": provider.ID, "realm_id": provider.RealmID, "name": provider.Name,
				"vendor": provider.Vendor, "enabled": provider.Enabled, "connection_url": provider.ConnectionURL,
				"priority": provider.Priority, "edit_mode": provider.EditMode, "last_sync_at": provider.LastSyncAt,
				"last_sync_status": provider.LastSyncStatus, "last_sync_added": provider.LastSyncAdded,
				"last_sync_updated": provider.LastSyncUpdated, "last_sync_failed": provider.LastSyncFailed})
		}
		output = items
	case "resso_search_users":
		var args struct {
			RealmID string `json:"realm_id"`
			Query   string `json:"query"`
		}
		if err := json.Unmarshal(call.Arguments, &args); err != nil || len([]rune(strings.TrimSpace(args.Query))) < 2 {
			return nil, errors.New("두 글자 이상의 query가 필요합니다")
		}
		realmID, permitErr := mcpDirectoryRealm(call.Arguments, principal)
		if permitErr != nil {
			return nil, permitErr
		}
		output, err = s.store.ListUsers(r.Context(), realmID, args.Query, store.UserSort{}, 20, 0)
	default:
		return nil, errors.New("등록되지 않은 도구입니다")
	}
	if err != nil {
		return nil, errors.New("도구 실행 중 데이터를 조회하지 못했습니다")
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return nil, err
	}
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": string(encoded)}},
		"structuredContent": output, "isError": false}, nil
}

// mcpDirectoryRealm resolves which realm a directory tool should read, and
// refuses the request outright when the caller would not be allowed to ask.
// Reaching outside one's own realm stays reserved for platform administrators.
func mcpDirectoryRealm(raw json.RawMessage, principal domain.Principal) (uuid.UUID, error) {
	if !mcpReadsDirectory(principal) {
		return uuid.Nil, errors.New("관리자 권한과 admin:read 범위가 필요합니다")
	}
	realmID, err := mcpRealmID(raw, principal)
	if err != nil {
		return uuid.Nil, err
	}
	if realmID != principal.RealmID && !principal.PlatformAdmin {
		return uuid.Nil, errors.New("다른 Realm을 조회할 권한이 없습니다")
	}
	return realmID, nil
}

func mcpRealmID(raw json.RawMessage, principal domain.Principal) (uuid.UUID, error) {
	var args struct {
		RealmID string `json:"realm_id"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return uuid.Nil, errors.New("arguments 형식이 올바르지 않습니다")
		}
	}
	if args.RealmID == "" {
		return principal.RealmID, nil
	}
	id, err := uuid.Parse(args.RealmID)
	if err != nil {
		return uuid.Nil, errors.New("realm_id가 올바른 UUID가 아닙니다")
	}
	return id, nil
}
