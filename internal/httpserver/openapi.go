package httpserver

import (
	"net/http"

	"github.com/hkjang/ReSSO/internal/version"
)

func (s *Server) openAPISpec(w http.ResponseWriter, r *http.Request) {
	profileUpdate := openAPIJSONOperation("Personal", "내 프로필 변경", true,
		"UpdateProfileInput", "User", "200", "Updated user")
	createUser := openAPIJSONOperation("Administration", "사용자 생성", true,
		"CreateUserInput", "User", "201", "Created user")
	updateUser := withUnendedSessions(openAPIJSONOperation("Administration", "사용자 변경", true,
		"UpdateUserInput", "User", "200", "Updated user"))
	resetPassword := withPartialSessionRevocation(openAPIJSONOperation("Administration",
		"사용자 비밀번호 재설정", true, "ResetPasswordInput", "", "204",
		"Password reset and the account's sessions ended"))
	changePassword := withPartialSessionRevocation(openAPIJSONOperation("Personal",
		"내 비밀번호 변경", true, "ChangePasswordInput", "", "204",
		"Password changed and the other sessions ended"))
	writeJSON(w, http.StatusOK, map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "ReSSO Administration and Personal API",
			"version":     version.Version,
			"description": "Keycloak-compatible OIDC 서비스의 관리·개인화 API. OIDC 프로토콜 계약은 각 Realm의 discovery endpoint를 사용하세요.",
		},
		"servers": []any{map[string]any{"url": "/"}},
		"tags": []any{
			map[string]any{"name": "Metadata"}, map[string]any{"name": "Personal"},
			map[string]any{"name": "Administration"}, map[string]any{"name": "User Federation"}, map[string]any{"name": "MCP"},
		},
		"paths": map[string]any{
			"/api/v1/meta":        openAPIPath("get", "Metadata", "서비스 버전 조회", false),
			"/api/v1/me":          openAPIReadPath("Personal", "현재 사용자 컨텍스트 조회"),
			"/api/v1/me/profile":  map[string]any{"put": profileUpdate},
			"/api/v1/me/password": map[string]any{"put": changePassword},
			"/api/v1/me/sessions": openAPIReadPath("Personal", "내 로그인 세션 조회"),
			"/api/v1/me/api-keys": map[string]any{
				"get":  openAPIReadOperation("Personal", "내 API 키 조회"),
				"post": openAPIOperation("Personal", "개인 API 키 생성", true),
			},
			"/api/admin/v1/realms": map[string]any{
				"get":  openAPIReadOperation("Administration", "Realm 목록"),
				"post": openAPIOperation("Administration", "Realm 생성", true),
			},
			"/api/admin/v1/realms/{realmID}/users": map[string]any{
				"parameters": []any{openAPIPathParameter("realmID")},
				"get":        openAPIReadOperation("Administration", "사용자 목록"),
				"post":       createUser,
			},
			"/api/admin/v1/realms/{realmID}/users/{userID}": map[string]any{
				"parameters": []any{openAPIPathParameter("realmID"), openAPIPathParameter("userID")},
				"put":        updateUser,
			},
			"/api/admin/v1/realms/{realmID}/users/{userID}/password": map[string]any{
				"parameters": []any{openAPIPathParameter("realmID"), openAPIPathParameter("userID")},
				"put":        resetPassword,
			},
			"/api/admin/v1/audit/event-types": map[string]any{
				"get": openAPIReadOperation("Administration", "감사 이벤트 유형 목록"),
			},
			"/api/admin/v1/realms/{realmID}/users/{userID}/unlock": map[string]any{
				"parameters": []any{openAPIPathParameter("realmID"), openAPIPathParameter("userID")},
				"post":       openAPIOperation("Administration", "잠긴 사용자 잠금 해제", true),
			},
			"/api/admin/v1/realms/{realmID}/clients": map[string]any{
				"parameters": []any{openAPIPathParameter("realmID")},
				"get":        openAPIReadOperation("Administration", "OIDC Client 목록"),
				"post":       openAPIOperation("Administration", "OIDC Client 생성", true),
			},
			"/api/admin/v1/realms/{realmID}/roles": map[string]any{
				"parameters": []any{openAPIPathParameter("realmID")},
				"get":        openAPIReadOperation("Administration", "Realm Role 목록"),
				"post":       openAPIOperation("Administration", "Realm Role 생성", true),
			},
			"/api/admin/v1/realms/{realmID}/roles/{roleID}": map[string]any{
				"parameters": []any{openAPIPathParameter("realmID"), openAPIPathParameter("roleID")},
				"put":        openAPIOperation("Administration", "Realm Role 설명 변경", true),
				"delete":     openAPIOperation("Administration", "Realm Role 삭제", true),
			},
			"/api/admin/v1/realms/{realmID}/users/{userID}/role-mappings": map[string]any{
				"parameters": []any{openAPIPathParameter("realmID"), openAPIPathParameter("userID")},
				"get":        openAPIReadOperation("Administration", "사용자 Role 매핑 조회"),
				"put":        openAPIOperation("Administration", "사용자 Role 매핑 교체", true),
			},
			"/api/admin/v1/realms/{realmID}/clients/{clientID}/roles": map[string]any{
				"parameters": []any{openAPIPathParameter("realmID"), openAPIPathParameter("clientID")},
				"get":        openAPIReadOperation("Administration", "Client Role 목록"),
				"post":       openAPIOperation("Administration", "Client Role 생성", true),
			},
			"/api/admin/v1/realms/{realmID}/user-federations": map[string]any{
				"parameters": []any{openAPIPathParameter("realmID")},
				"get":        openAPIReadOperation("User Federation", "LDAP 공급자 목록"),
				"post":       openAPIOperation("User Federation", "LDAP 공급자 생성", true),
			},
			"/api/admin/v1/realms/{realmID}/user-federations/{federationID}": map[string]any{
				"parameters": []any{openAPIPathParameter("realmID"), openAPIPathParameter("federationID")},
				"get":        openAPIReadOperation("User Federation", "LDAP 공급자 조회"),
				"put":        withUnfinishedSignOut(openAPIOperation("User Federation", "LDAP 공급자 변경", true), "PartialProviderChange"),
				"delete":     withUnfinishedSignOut(openAPIOperation("User Federation", "LDAP 공급자 삭제", true), "PartialProviderDeletion"),
			},
			"/api/admin/v1/realms/{realmID}/user-federations/{federationID}/test-connection":     openAPIParameterizedPath("post", "User Federation", "LDAP 연결 테스트", true, "realmID", "federationID"),
			"/api/admin/v1/realms/{realmID}/user-federations/{federationID}/test-authentication": openAPIParameterizedPath("post", "User Federation", "LDAP 사용자 인증 테스트", true, "realmID", "federationID"),
			"/api/admin/v1/realms/{realmID}/user-federations/{federationID}/sync":                openAPIParameterizedPath("post", "User Federation", "LDAP 전체 사용자 동기화", true, "realmID", "federationID"),
			"/api/admin/v1/realms/{realmID}/keys/rotate":                                         openAPIParameterizedPath("post", "Administration", "Realm 서명 키 회전", true, "realmID"),
			"/api/admin/v1/audit": openAPIReadPath("Administration", "감사 이벤트 조회"),
			"/api/admin/v1/realms/{realmID}/api-keys": map[string]any{
				"parameters": []any{openAPIPathParameter("realmID")},
				"get":        openAPIReadOperation("Administration", "Realm의 개인 API 키 조회 (metadata)"),
			},
			"/api/admin/v1/system-logs": openAPIReadPath("Administration", "서버 구조화 로그 조회"),
			"/mcp":                      openAPIPath("post", "MCP", "MCP Streamable HTTP JSON-RPC endpoint", true),

			// The document is served as the API contract, so it has to cover
			// every route the server registers. A test walks the router and
			// fails when one is missing, which is how these were found absent.
			"/api/openapi.json":               openAPIPath("get", "Metadata", "이 OpenAPI 문서", false),
			"/api/v1/auth/login":              openAPIPath("post", "Personal", "브라우저 로그인", false),
			"/api/v1/auth/logout":             withPartialTokenRevocation("post", openAPIPath("post", "Personal", "브라우저 로그아웃", true)),
			"/api/v1/auth/challenge/{token}":  openAPIParameterizedPath("get", "Personal", "로그인 요청 컨텍스트 조회", false, "token"),
			"/api/v1/me/sessions/{id}":        withPartialTokenRevocation("delete", openAPIParameterizedPath("delete", "Personal", "내 세션 종료", true, "id")),
			"/api/v1/me/api-keys/{id}":        openAPIParameterizedPath("delete", "Personal", "내 API 키 폐기", true, "id"),
			"/api/v1/me/api-keys/{id}/rotate": openAPIParameterizedPath("post", "Personal", "내 API 키 회전", true, "id"),
			"/api/v1/me/approval-capability":  openAPIReadPath("Personal", "내 검토 권한 조회"),
			"/api/v1/me/requestable-roles":    openAPIReadPath("Personal", "요청 가능한 Role 조회"),
			"/api/v1/me/requests": map[string]any{
				"get":  openAPIReadOperation("Personal", "내 접근 요청 조회"),
				"post": openAPIOperation("Personal", "Role 할당 요청 생성", true),
			},
			"/api/v1/me/reviews":                           openAPIReadPath("Personal", "내가 검토할 요청 조회"),
			"/api/v1/me/reviews/{requestID}/decision":      openAPIParameterizedPath("post", "Personal", "요청 승인 또는 반려", true, "requestID"),
			"/api/admin/v1/dashboard":                      openAPIReadPath("Administration", "운영 현황과 준비 상태 조회"),
			"/api/admin/v1/quick-search":                   openAPIReadPath("Administration", "사용자와 Client 통합 검색"),
			"/api/admin/v1/approvals":                      openAPIReadPath("Administration", "접근 요청 조회"),
			"/api/admin/v1/approvals/{requestID}/decision": openAPIParameterizedPath("post", "Administration", "접근 요청 승인 또는 반려", true, "requestID"),
			"/api/admin/v1/realms/{realmID}": map[string]any{
				"parameters": []any{openAPIPathParameter("realmID")},
				"get":        openAPIReadOperation("Administration", "Realm 조회"),
				"put":        openAPIOperation("Administration", "Realm 설정 변경", true),
			},
			"/api/admin/v1/realms/{realmID}/keys":                              openAPIParameterizedPath("get", "Administration", "Realm 서명 키 목록", false, "realmID"),
			"/api/admin/v1/realms/{realmID}/sessions":                          openAPIParameterizedPath("get", "Administration", "Realm SSO 세션 조회", false, "realmID"),
			"/api/admin/v1/realms/{realmID}/sessions/{sessionID}":              withPartialTokenRevocation("delete", openAPIParameterizedPath("delete", "Administration", "SSO 세션 강제 종료", true, "realmID", "sessionID")),
			"/api/admin/v1/realms/{realmID}/clients/{clientID}":                openAPIParameterizedPath("put", "Administration", "OIDC Client 변경", true, "realmID", "clientID"),
			"/api/admin/v1/realms/{realmID}/clients/{clientID}/rotate-secret":  openAPIParameterizedPath("post", "Administration", "Client Secret 회전", true, "realmID", "clientID"),
			"/api/admin/v1/realms/{realmID}/clients/{clientID}/roles/{roleID}": openAPIParameterizedPath("delete", "Administration", "Client Role 삭제", true, "realmID", "clientID", "roleID"),
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"SessionCookie": map[string]any{"type": "apiKey", "in": "cookie", "name": sessionCookieName},
				"PersonalAPIKey": map[string]any{"type": "http", "scheme": "bearer", "bearerFormat": "ReSSO personal API key",
					"description": "GET 요청은 api:read, 관리자 GET 요청은 추가로 admin:read 범위가 필요합니다."},
			},
			"schemas": openAPISchemas(),
		},
	})
}

func openAPIPathParameter(name string) map[string]any {
	return map[string]any{
		"name": name, "in": "path", "required": true,
		"schema": map[string]any{"type": "string", "format": "uuid"},
	}
}

func openAPIJSONOperation(tag, summary string, secured bool, requestSchema, responseSchema, status, description string) map[string]any {
	operation := openAPIOperation(tag, summary, secured)
	operation["requestBody"] = map[string]any{
		"required": true,
		"content": map[string]any{"application/json": map[string]any{
			"schema": map[string]any{"$ref": "#/components/schemas/" + requestSchema},
		}},
	}
	response := map[string]any{"description": description}
	if responseSchema != "" {
		response["content"] = map[string]any{"application/json": map[string]any{
			"schema": map[string]any{"$ref": "#/components/schemas/" + responseSchema},
		}}
	}
	responses := map[string]any{status: response}
	for code, errorResponse := range openAPIErrorResponses() {
		responses[code] = errorResponse
	}
	operation["responses"] = responses
	return operation
}

// openAPISchemas collects every component schema the document references.
func openAPISchemas() map[string]any {
	schemas := openAPIUserSchemas()
	schemas["Error"] = openAPIErrorSchema()
	return schemas
}

// openAPIErrorSchema names the codes worth branching on. The list is not every
// code the service can emit — it is the ones where a caller does something
// other than show the message: wait, re-read, or send the user somewhere.
func openAPIErrorSchema() map[string]any {
	return map[string]any{
		"type":        "object",
		"description": "모든 오류 응답이 공유하는 형태입니다. trace_id는 서버 로그·감사 이벤트와 대조할 수 있습니다.",
		"required":    []string{"error", "message"},
		"properties": map[string]any{
			"error": map[string]any{
				"type":        "string",
				"description": "기계가 분기할 식별자. 아래는 동작이 달라지는 주요 값입니다.",
				"examples": []string{
					"authentication_required", "invalid_credentials", "account_locked", "account_disabled",
					"browser_session_required", "invalid_csrf", "insufficient_permission",
					"invalid_input", "invalid_manager", "not_found", "conflict",
					"rate_limited", "internal_error",
				},
			},
			"message":  map[string]any{"type": "string", "description": "사용자에게 보여줄 수 있는 설명."},
			"trace_id": map[string]any{"type": "string", "format": "uuid", "description": "이 요청의 추적 식별자."},
		},
	}
}

func openAPIUserSchemas() map[string]any {
	optionalEmail := map[string]any{
		"description": "빈 문자열은 이메일 미등록을 뜻합니다. 비어 있지 않으면 단일 ASCII RFC mailbox여야 합니다.",
		"oneOf": []any{
			map[string]any{"type": "string", "const": ""},
			map[string]any{"type": "string", "format": "email", "maxLength": 320},
		},
	}
	emailVerified := map[string]any{
		"type":        "boolean",
		"description": "관리자가 이메일 소유 또는 외부 검증 근거를 확인한 상태입니다. 이메일 변경·삭제 시 false로 초기화됩니다.",
	}
	return map[string]any{
		"OptionalEmail": optionalEmail,
		"User": map[string]any{
			"type":     "object",
			"required": []string{"id", "realm_id", "username", "email", "email_verified", "display_name", "enabled"},
			"properties": map[string]any{
				"id":             map[string]any{"type": "string", "format": "uuid"},
				"realm_id":       map[string]any{"type": "string", "format": "uuid"},
				"username":       map[string]any{"type": "string"},
				"email":          map[string]any{"$ref": "#/components/schemas/OptionalEmail"},
				"email_verified": emailVerified,
				"display_name":   map[string]any{"type": "string"},
				"enabled":        map[string]any{"type": "boolean"},
			},
		},
		"CreateUserInput": map[string]any{
			"type":     "object",
			"required": []string{"username", "password"},
			"properties": map[string]any{
				"username":       map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
				"email":          map[string]any{"$ref": "#/components/schemas/OptionalEmail"},
				"email_verified": emailVerified,
				"display_name":   map[string]any{"type": "string"},
				"password":       map[string]any{"type": "string", "format": "password", "minLength": 1},
				"enabled":        map[string]any{"type": "boolean"},
				"manager_id":     nullableUUIDSchema(),
			},
		},
		"UpdateUserInput": map[string]any{
			"type":     "object",
			"required": []string{"email", "display_name", "enabled"},
			"properties": map[string]any{
				"email": map[string]any{"$ref": "#/components/schemas/OptionalEmail"},
				"email_verified": map[string]any{
					"type":        []string{"boolean", "null"},
					"description": "생략 또는 null이면 기존 상태를 유지합니다. 이메일을 바꾸는 요청에서는 true도 무시되고 false로 초기화됩니다.",
				},
				"display_name": map[string]any{"type": "string"},
				"enabled":      map[string]any{"type": "boolean"},
				"manager_id":   nullableUUIDSchema(),
			},
		},
		"UpdateProfileInput": map[string]any{
			"type":     "object",
			"required": []string{"email", "display_name"},
			"properties": map[string]any{
				"email":        map[string]any{"$ref": "#/components/schemas/OptionalEmail"},
				"display_name": map[string]any{"type": "string"},
			},
		},
		"ResetPasswordInput": map[string]any{
			"type":     "object",
			"required": []string{"new_password"},
			"properties": map[string]any{
				"new_password": map[string]any{"type": "string", "format": "password", "minLength": 1},
			},
		},
		"ChangePasswordInput": map[string]any{
			"type":     "object",
			"required": []string{"current_password", "new_password"},
			"properties": map[string]any{
				"current_password": map[string]any{"type": "string", "format": "password"},
				"new_password":     map[string]any{"type": "string", "format": "password", "minLength": 1},
			},
		},
		"PartialProviderChange": map[string]any{
			"type": "object",
			"description": "공급자는 변경됐지만 그 공급자의 계정을 모든 애플리케이션에서 로그아웃시키지 못한 경우의 응답. " +
				"공급자의 모든 필드를 그대로 담고 아래 두 항목이 더해집니다. 감사 이벤트는 PARTIAL로 기록됩니다.",
			"required": []string{"users_signed_out", "message"},
			"properties": map[string]any{
				"users_signed_out": map[string]any{"type": "boolean", "enum": []any{false}},
				"message":          map[string]any{"type": "string"},
			},
		},
		"PartialAccountDisable": map[string]any{
			"type": "object",
			"description": "계정은 비활성화됐지만 열려 있는 세션을 모두 종료하지 못한 경우의 응답. " +
				"계정의 모든 필드를 그대로 담고 아래 두 항목이 더해집니다. 감사 이벤트는 PARTIAL로 기록되고 " +
				"detail.users_signed_out이 false입니다. 같은 요청을 다시 보내면 종료를 다시 시도합니다.",
			"required": []string{"sessions_ended", "message"},
			"properties": map[string]any{
				"sessions_ended": map[string]any{"type": "boolean", "enum": []any{false}},
				"message":        map[string]any{"type": "string"},
			},
		},
		"PartialProviderDeletion": map[string]any{
			"type":        "object",
			"description": "공급자는 삭제됐지만 연결된 계정을 모든 애플리케이션에서 로그아웃시키지 못한 경우의 응답. 감사 이벤트는 PARTIAL로 기록됩니다.",
			"required":    []string{"deleted", "users_signed_out", "message"},
			"properties": map[string]any{
				"deleted":          map[string]any{"type": "boolean", "enum": []any{true}},
				"users_signed_out": map[string]any{"type": "boolean", "enum": []any{false}},
				"message":          map[string]any{"type": "string"},
			},
		},
		"PartialTokenRevocation": map[string]any{
			"type":        "object",
			"description": "세션은 종료했지만 그 세션의 Refresh Token을 폐기하지 못한 경우의 응답. 감사 이벤트는 PARTIAL로 기록됩니다.",
			"required":    []string{"session_ended", "refresh_tokens_revoked", "message"},
			"properties": map[string]any{
				"session_ended":          map[string]any{"type": "boolean", "enum": []any{true}},
				"refresh_tokens_revoked": map[string]any{"type": "boolean", "enum": []any{false}},
				"message":                map[string]any{"type": "string"},
			},
		},
		"PartialSessionRevocation": map[string]any{
			"type":        "object",
			"description": "비밀번호는 바뀌었지만 세션 종료 또는 그 세션의 Refresh Token 폐기가 실패한 경우의 응답. other_sessions_ended가 true이면 세션은 종료됐고 Refresh Token만 남은 것입니다. 감사 이벤트는 PARTIAL로 기록됩니다.",
			"required":    []string{"other_sessions_ended", "refresh_tokens_revoked", "message"},
			"properties": map[string]any{
				"other_sessions_ended":   map[string]any{"type": "boolean"},
				"refresh_tokens_revoked": map[string]any{"type": "boolean", "enum": []any{false}},
				"message":                map[string]any{"type": "string"},
			},
		},
	}
}

// withPartialSessionRevocation declares the second shape a password endpoint
// can answer with. Changing a password ends the account's other sessions, and
// that step can fail on its own after the password is already changed — the
// request is not refused, so a client that assumes 204 is a client that never
// learns those sessions are still live.
// withUnfinishedSignOut declares the second shape a provider change can answer
// with. Disabling or unlinking a provider signs its accounts out, and that step
// runs after the change has landed, so it can fall short on its own — the
// change is done, and a client that assumes one shape never learns the accounts
// are still signed in elsewhere.
// withUnendedSessions declares the second shape the user update can answer
// with. Disabling an account writes the row first and ends its sessions after,
// so the account is off either way and only the sweep can fall short — the
// same split the provider endpoints already describe.
func withUnendedSessions(operation map[string]any) map[string]any {
	responses, _ := operation["responses"].(map[string]any)
	responses["200"] = map[string]any{
		"description": "The account was updated; if it was disabled and its sessions could not all be ended, " +
			"the body carries sessions_ended and message beside every field of the account",
		"content": map[string]any{"application/json": map[string]any{
			"schema": map[string]any{"oneOf": []any{
				map[string]any{"$ref": "#/components/schemas/User"},
				map[string]any{"$ref": "#/components/schemas/PartialAccountDisable"},
			}},
		}},
	}
	return operation
}

func withUnfinishedSignOut(operation map[string]any, schema string) map[string]any {
	responses, _ := operation["responses"].(map[string]any)
	responses["200"] = map[string]any{
		"description": "The provider changed, but its accounts could not be signed out everywhere",
		"content": map[string]any{"application/json": map[string]any{
			"schema": map[string]any{"$ref": "#/components/schemas/" + schema},
		}},
	}
	return operation
}

// withPartialTokenRevocation declares the second shape an endpoint that ends
// one session can answer with. The session is gone either way; what can fail
// on its own is revoking the refresh tokens issued from it, and a relying
// party holding one of those is not signed out by the session ending.
func withPartialTokenRevocation(method string, item map[string]any) map[string]any {
	operation, _ := item[method].(map[string]any)
	responses, _ := operation["responses"].(map[string]any)
	responses["200"] = map[string]any{
		"description": "Session ended, but the refresh tokens issued from it could not be revoked",
		"content": map[string]any{"application/json": map[string]any{
			"schema": map[string]any{"$ref": "#/components/schemas/PartialTokenRevocation"},
		}},
	}
	return item
}

func withPartialSessionRevocation(operation map[string]any) map[string]any {
	responses, _ := operation["responses"].(map[string]any)
	responses["200"] = map[string]any{
		"description": "Password changed, but the account's other sessions could not be ended",
		"content": map[string]any{"application/json": map[string]any{
			"schema": map[string]any{"$ref": "#/components/schemas/PartialSessionRevocation"},
		}},
	}
	return operation
}

func nullableUUIDSchema() map[string]any {
	return map[string]any{
		"oneOf": []any{
			map[string]any{"type": "string", "format": "uuid"},
			map[string]any{"type": "null"},
		},
	}
}

func openAPIPath(method, tag, summary string, secured bool) map[string]any {
	return map[string]any{method: openAPIOperation(tag, summary, secured)}
}

func openAPIParameterizedPath(method, tag, summary string, secured bool, parameters ...string) map[string]any {
	items := make([]any, 0, len(parameters))
	for _, parameter := range parameters {
		items = append(items, openAPIPathParameter(parameter))
	}
	return map[string]any{
		"parameters": items,
		method:       openAPIOperation(tag, summary, secured),
	}
}

func openAPIReadPath(tag, summary string) map[string]any {
	return map[string]any{"get": openAPIReadOperation(tag, summary)}
}

func openAPIReadOperation(tag, summary string) map[string]any {
	operation := openAPIOperation(tag, summary, true)
	operation["security"] = []any{map[string]any{"SessionCookie": []string{}}, map[string]any{"PersonalAPIKey": []string{"api:read"}}}
	return operation
}

// openAPIErrorResponses describes what every endpoint returns when it refuses.
//
// The console offers this document as the API contract, and a contract that
// says only "Request error" leaves an integrator to discover the shape by
// provoking one. Every refusal carries the same three fields, and the ones
// worth retrying carry Retry-After, so both belong here rather than in the
// caller's guesswork.
func openAPIErrorResponses() map[string]any {
	body := map[string]any{
		"description": "Request error",
		"content": map[string]any{"application/json": map[string]any{
			"schema": map[string]any{"$ref": "#/components/schemas/Error"},
		}},
	}
	limited := map[string]any{
		"description": "Too many requests",
		"headers": map[string]any{"Retry-After": map[string]any{
			"description": "다시 시도해도 되는 시점까지의 초. 계정 잠금(401 account_locked)에도 함께 반환됩니다.",
			"schema":      map[string]any{"type": "integer", "minimum": 1},
		}},
		"content": map[string]any{"application/json": map[string]any{
			"schema": map[string]any{"$ref": "#/components/schemas/Error"},
		}},
	}
	return map[string]any{"4XX": body, "429": limited, "5XX": body}
}

func openAPIOperation(tag, summary string, secured bool) map[string]any {
	responses := map[string]any{"200": map[string]any{"description": "Success"}}
	for status, response := range openAPIErrorResponses() {
		responses[status] = response
	}
	operation := map[string]any{"tags": []string{tag}, "summary": summary, "responses": responses}
	if secured {
		if tag == "MCP" {
			operation["security"] = []any{map[string]any{"PersonalAPIKey": []string{}}}
		} else {
			operation["security"] = []any{map[string]any{"SessionCookie": []string{}}}
		}
	}
	return operation
}
