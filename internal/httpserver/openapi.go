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
			map[string]any{"name": "Administration"}, map[string]any{"name": "MCP"},
		},
		"paths": map[string]any{
			"/api/v1/meta":        openAPIPath("get", "Metadata", "서비스 버전 조회", false),
			"/api/v1/me":          openAPIPath("get", "Personal", "현재 사용자 컨텍스트 조회", true),
			"/api/v1/me/profile":  openAPIPath("put", "Personal", "내 프로필 변경", true),
			"/api/v1/me/password": openAPIPath("put", "Personal", "내 비밀번호 변경", true),
			"/api/v1/me/sessions": openAPIPath("get", "Personal", "내 로그인 세션 조회", true),
			"/api/v1/me/api-keys": map[string]any{
				"get":  openAPIOperation("Personal", "내 API 키 조회", true),
				"post": openAPIOperation("Personal", "개인 API 키 생성", true),
			},
			"/api/admin/v1/realms": map[string]any{
				"get":  openAPIOperation("Administration", "Realm 목록", true),
				"post": openAPIOperation("Administration", "Realm 생성", true),
			},
			"/api/admin/v1/realms/{realmID}/users": map[string]any{
				"get":  openAPIOperation("Administration", "사용자 목록", true),
				"post": openAPIOperation("Administration", "사용자 생성", true),
			},
			"/api/admin/v1/realms/{realmID}/clients": map[string]any{
				"get":  openAPIOperation("Administration", "OIDC Client 목록", true),
				"post": openAPIOperation("Administration", "OIDC Client 생성", true),
			},
			"/api/admin/v1/realms/{realmID}/keys/rotate": openAPIPath("post", "Administration", "Realm 서명 키 회전", true),
			"/api/admin/v1/audit":                        openAPIPath("get", "Administration", "감사 이벤트 조회", true),
			"/api/admin/v1/system-logs":                  openAPIPath("get", "Administration", "서버 구조화 로그 조회", true),
			"/mcp":                                       openAPIPath("post", "MCP", "MCP Streamable HTTP JSON-RPC endpoint", true),
		},
		"components": map[string]any{"securitySchemes": map[string]any{
			"SessionCookie":  map[string]any{"type": "apiKey", "in": "cookie", "name": sessionCookieName},
			"PersonalAPIKey": map[string]any{"type": "http", "scheme": "bearer"},
		}},
	})
}

func openAPIPath(method, tag, summary string, secured bool) map[string]any {
	return map[string]any{method: openAPIOperation(tag, summary, secured)}
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
