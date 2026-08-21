package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAPIIncludesUserMutationContracts(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)
	response := httptest.NewRecorder()
	(&Server{}).openAPISpec(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; want %d", response.Code, http.StatusOK)
	}
	var spec map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths := spec["paths"].(map[string]any)
	userPath, ok := paths["/api/admin/v1/realms/{realmID}/users/{userID}"].(map[string]any)
	if !ok || userPath["put"] == nil {
		t.Fatalf("user PUT path missing: %#v", userPath)
	}
	if parameters, ok := userPath["parameters"].([]any); !ok || len(parameters) != 2 {
		t.Fatalf("user path parameters = %#v; want realmID and userID", userPath["parameters"])
	}
	passwordPath, ok := paths["/api/admin/v1/realms/{realmID}/users/{userID}/password"].(map[string]any)
	if !ok || passwordPath["put"] == nil {
		t.Fatalf("password PUT path missing: %#v", passwordPath)
	}
	components := spec["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	for _, name := range []string{"OptionalEmail", "User", "CreateUserInput", "UpdateUserInput", "UpdateProfileInput", "ResetPasswordInput"} {
		if schemas[name] == nil {
			t.Errorf("schema %q missing", name)
		}
	}
	for path, rawPath := range paths {
		pathItem := rawPath.(map[string]any)
		declared := map[string]bool{}
		if parameters, ok := pathItem["parameters"].([]any); ok {
			for _, rawParameter := range parameters {
				parameter := rawParameter.(map[string]any)
				if parameter["in"] == "path" {
					declared[parameter["name"].(string)] = true
				}
			}
		}
		remaining := path
		for {
			start := strings.IndexByte(remaining, '{')
			if start < 0 {
				break
			}
			end := strings.IndexByte(remaining[start:], '}')
			if end < 0 {
				t.Fatalf("malformed path template %q", path)
			}
			name := remaining[start+1 : start+end]
			if !declared[name] {
				t.Errorf("path %q does not declare parameter %q", path, name)
			}
			remaining = remaining[start+end+1:]
		}
	}
}
