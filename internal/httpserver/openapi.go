package httpserver

import (
	"net/http"

	"github.com/hkjang/ReSSO/internal/version"
)

func (s *Server) openAPISpec(w http.ResponseWriter, r *http.Request) {
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
			"/api/v1/me/profile":  openAPIPath("put", "Personal", "내 프로필 변경", true),
			"/api/v1/me/password": openAPIPath("put", "Personal", "내 비밀번호 변경", true),
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
				"get":  openAPIReadOperation("Administration", "사용자 목록"),
				"post": openAPIOperation("Administration", "사용자 생성", true),
			},
			"/api/admin/v1/realms/{realmID}/clients": map[string]any{
				"get":  openAPIReadOperation("Administration", "OIDC Client 목록"),
				"post": openAPIOperation("Administration", "OIDC Client 생성", true),
			},
			"/api/admin/v1/realms/{realmID}/roles": map[string]any{
				"get":  openAPIReadOperation("Administration", "Realm Role 목록"),
				"post": openAPIOperation("Administration", "Realm Role 생성", true),
			},
			"/api/admin/v1/realms/{realmID}/roles/{roleID}": map[string]any{
				"put":    openAPIOperation("Administration", "Realm Role 설명 변경", true),
				"delete": openAPIOperation("Administration", "Realm Role 삭제", true),
			},
			"/api/admin/v1/realms/{realmID}/users/{userID}/role-mappings": map[string]any{
				"get": openAPIReadOperation("Administration", "사용자 Role 매핑 조회"),
				"put": openAPIOperation("Administration", "사용자 Role 매핑 교체", true),
			},
			"/api/admin/v1/realms/{realmID}/clients/{clientID}/roles": map[string]any{
				"get":  openAPIReadOperation("Administration", "Client Role 목록"),
				"post": openAPIOperation("Administration", "Client Role 생성", true),
			},
			"/api/admin/v1/realms/{realmID}/user-federations": map[string]any{
				"get":  openAPIReadOperation("User Federation", "LDAP 공급자 목록"),
				"post": openAPIOperation("User Federation", "LDAP 공급자 생성", true),
			},
			"/api/admin/v1/realms/{realmID}/user-federations/{federationID}": map[string]any{
				"get":    openAPIReadOperation("User Federation", "LDAP 공급자 조회"),
				"put":    openAPIOperation("User Federation", "LDAP 공급자 변경", true),
				"delete": openAPIOperation("User Federation", "LDAP 공급자 삭제", true),
			},
			"/api/admin/v1/realms/{realmID}/user-federations/{federationID}/test-connection":     openAPIPath("post", "User Federation", "LDAP 연결 테스트", true),
			"/api/admin/v1/realms/{realmID}/user-federations/{federationID}/test-authentication": openAPIPath("post", "User Federation", "LDAP 사용자 인증 테스트", true),
			"/api/admin/v1/realms/{realmID}/user-federations/{federationID}/sync":                openAPIPath("post", "User Federation", "LDAP 전체 사용자 동기화", true),
			"/api/admin/v1/realms/{realmID}/keys/rotate":                                         openAPIPath("post", "Administration", "Realm 서명 키 회전", true),
			"/api/admin/v1/audit":       openAPIReadPath("Administration", "감사 이벤트 조회"),
			"/api/admin/v1/system-logs": openAPIReadPath("Administration", "서버 구조화 로그 조회"),
			"/mcp":                      openAPIPath("post", "MCP", "MCP Streamable HTTP JSON-RPC endpoint", true),
		},
		"components": map[string]any{"securitySchemes": map[string]any{
			"SessionCookie": map[string]any{"type": "apiKey", "in": "cookie", "name": sessionCookieName},
			"PersonalAPIKey": map[string]any{"type": "http", "scheme": "bearer", "bearerFormat": "ReSSO personal API key",
				"description": "GET 요청은 api:read, 관리자 GET 요청은 추가로 admin:read 범위가 필요합니다."},
		}},
	})
}

func openAPIPath(method, tag, summary string, secured bool) map[string]any {
	return map[string]any{method: openAPIOperation(tag, summary, secured)}
}

func openAPIReadPath(tag, summary string) map[string]any {
	return map[string]any{"get": openAPIReadOperation(tag, summary)}
}

func openAPIReadOperation(tag, summary string) map[string]any {
	operation := openAPIOperation(tag, summary, true)
	operation["security"] = []any{map[string]any{"SessionCookie": []string{}}, map[string]any{"PersonalAPIKey": []string{"api:read"}}}
	return operation
}

func openAPIOperation(tag, summary string, secured bool) map[string]any {
	operation := map[string]any{"tags": []string{tag}, "summary": summary,
		"responses": map[string]any{"200": map[string]any{"description": "Success"}, "4XX": map[string]any{"description": "Request error"}}}
	if secured {
		if tag == "MCP" {
			operation["security"] = []any{map[string]any{"PersonalAPIKey": []string{}}}
		} else {
			operation["security"] = []any{map[string]any{"SessionCookie": []string{}}}
		}
	}
	return operation
}
