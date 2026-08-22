package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
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

// TestOpenAPICoversEveryRegisteredRoute walks the router and fails when a route
// the server answers is absent from the document it publishes as its contract.
// Twenty-five routes were missing when this was written, including login and
// logout, so a client generated from the document covered about half the API.
func TestOpenAPICoversEveryRegisteredRoute(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)
	response := httptest.NewRecorder()
	(&Server{}).openAPISpec(response, request)
	var spec map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatal("spec has no paths object")
	}

	router, ok := New(nil, nil, nil, nil).Handler().(*chi.Mux)
	if !ok {
		t.Fatal("handler is not a chi router")
	}
	var missing []string
	walkErr := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		// The OIDC protocol contract lives in each Realm's discovery document,
		// and the SPA fallback is not an API route.
		route = strings.TrimSuffix(route, "/")
		if !strings.HasPrefix(route, "/api/") {
			return nil
		}
		item, ok := paths[route].(map[string]any)
		if !ok {
			missing = append(missing, method+" "+route)
			return nil
		}
		if item[strings.ToLower(method)] == nil {
			missing = append(missing, method+" "+route)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if len(missing) > 0 {
		t.Fatalf("routes missing from the OpenAPI document:\n  %s", strings.Join(missing, "\n  "))
	}
}

// The console offers this document as the API contract and the service
// promises a consistent error format, so every operation has to describe what
// a refusal looks like — and every schema it points at has to exist, since a
// dangling $ref breaks generation for the whole document, not just one path.
func TestOpenAPIDescribesErrorsAndResolvesEveryReference(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)
	response := httptest.NewRecorder()
	(&Server{}).openAPISpec(response, request)
	var document map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	components, _ := document["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	if _, ok := schemas["Error"]; !ok {
		t.Fatal("the document defines no Error schema")
	}

	paths, _ := document["paths"].(map[string]any)
	if len(paths) == 0 {
		t.Fatal("the document defines no paths")
	}
	for path, rawItem := range paths {
		item, _ := rawItem.(map[string]any)
		for method, rawOperation := range item {
			if method == "parameters" {
				continue
			}
			operation, _ := rawOperation.(map[string]any)
			responses, _ := operation["responses"].(map[string]any)
			for _, status := range []string{"4XX", "5XX"} {
				response, ok := responses[status].(map[string]any)
				if !ok {
					t.Errorf("%s %s does not describe a %s response", method, path, status)
					continue
				}
				if _, ok := response["content"]; !ok {
					t.Errorf("%s %s describes %s without a body schema", method, path, status)
				}
			}
		}
	}

	for _, ref := range collectRefs(document) {
		name, found := strings.CutPrefix(ref, "#/components/schemas/")
		if !found {
			t.Errorf("unexpected reference form: %s", ref)
			continue
		}
		if _, ok := schemas[name]; !ok {
			t.Errorf("the document references a schema it does not define: %s", name)
		}
	}
}

// collectRefs walks the decoded document and returns every $ref value.
func collectRefs(node any) []string {
	switch typed := node.(type) {
	case map[string]any:
		refs := make([]string, 0)
		for key, value := range typed {
			if key == "$ref" {
				if ref, ok := value.(string); ok {
					refs = append(refs, ref)
				}
				continue
			}
			refs = append(refs, collectRefs(value)...)
		}
		return refs
	case []any:
		refs := make([]string, 0)
		for _, value := range typed {
			refs = append(refs, collectRefs(value)...)
		}
		return refs
	}
	return nil
}
