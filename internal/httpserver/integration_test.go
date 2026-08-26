package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/ReSSO/internal/cryptoutil"
	"github.com/hkjang/ReSSO/internal/domain"
	"github.com/hkjang/ReSSO/internal/observability"
	ressooidc "github.com/hkjang/ReSSO/internal/oidc"
	"github.com/hkjang/ReSSO/internal/store"
)

func TestIntegrationLoginCountsFailuresAndResetsOnSuccess(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	bootstrap, err := data.Bootstrap(context.Background(), "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(context.Background(),
		`UPDATE realms SET max_login_attempts=50 WHERE id=$1`, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()

	response := postIntegrationLogin(t, client, server.URL, "admin", "wrong-password")
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid login status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	bucket := "login/account/" + bootstrap.RealmID.String() + "/admin"
	decision, err := data.CheckLoginRateLimit(context.Background(), bucket, 30, 5*time.Minute)
	if err != nil || decision.Attempts != 1 {
		t.Fatalf("failure bucket = %+v, err=%v", decision, err)
	}

	response = postIntegrationLogin(t, client, server.URL, "admin", "bootstrap-password-123")
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("valid login status = %d, body=%s", response.StatusCode, body)
	}
	_ = response.Body.Close()
	decision, err = data.CheckLoginRateLimit(context.Background(), bucket, 30, 5*time.Minute)
	if err != nil || !decision.Allowed || decision.Attempts != 0 {
		t.Fatalf("successful login did not reset bucket: %+v, err=%v", decision, err)
	}

	for range 30 {
		if _, err := data.RecordLoginFailure(context.Background(), bucket, 30, 5*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	response = postIntegrationLogin(t, client, server.URL, "admin", "bootstrap-password-123")
	defer response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("limited login status = %d, body=%s", response.StatusCode, body)
	}
	retryAfter, err := strconv.Atoi(response.Header.Get("Retry-After"))
	if err != nil || retryAfter < 1 || retryAfter > 300 {
		t.Fatalf("Retry-After = %q", response.Header.Get("Retry-After"))
	}
}

func TestIntegrationMCPUserTokenRequiresExactActiveSessionBinding(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.UserByID(ctx, bootstrap.AdminUserID)
	if err != nil {
		t.Fatal(err)
	}
	// A client identifier is intentionally set to the platform administrator's
	// UUID. Its client-credentials token must never be interpreted as that user.
	created, err := data.CreateClient(ctx, bootstrap.RealmID, store.CreateClientInput{
		ClientID:      bootstrap.AdminUserID.String(),
		Name:          "MCP impersonation regression",
		Type:          "confidential",
		GrantTypes:    []string{"client_credentials"},
		DefaultScopes: []string{"mcp:read", "admin:read"},
	})
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	clientToken := requestIntegrationClientCredentialsToken(t, client, server.URL,
		created.Client.ClientID, created.ClientSecret)
	response := postIntegrationMCP(t, client, server.URL, clientToken)
	if response.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		t.Fatalf("client-credentials MCP status = %d, body=%s", response.StatusCode, body)
	}
	_ = response.Body.Close()

	session, err := data.CreateSession(ctx, realm.ID, user.ID, time.Hour,
		"127.0.0.1", "mcp-integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.ValidateActiveSessionBinding(ctx, session.Session.ID, user.ID, realm.ID); err != nil {
		t.Fatalf("valid session binding was rejected: %v", err)
	}
	if err := data.ValidateActiveSessionBinding(ctx, session.Session.ID, uuid.New(), realm.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session accepted a different user binding: %v", err)
	}
	if err := data.ValidateActiveSessionBinding(ctx, session.Session.ID, user.ID, uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session accepted a different Realm binding: %v", err)
	}
	expiredSession, err := data.CreateSession(ctx, realm.ID, user.ID, -time.Minute,
		"127.0.0.1", "mcp-integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.ValidateActiveSessionBinding(ctx, expiredSession.Session.ID, user.ID, realm.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session binding remained active: %v", err)
	}
	service := ressooidc.Service{Store: data}
	userTokens, err := service.IssueUserTokens(ctx, realm, created.Client, user,
		session.Session.ID, []string{"mcp:read", "admin:read"}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	response = postIntegrationMCP(t, client, server.URL, userTokens.AccessToken)
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		t.Fatalf("active user-session MCP status = %d, body=%s", response.StatusCode, body)
	}
	_ = response.Body.Close()

	if err := data.RevokeSession(ctx, session.Session.ID); err != nil {
		t.Fatal(err)
	}
	response = postIntegrationMCP(t, client, server.URL, userTokens.AccessToken)
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("revoked-session MCP status = %d, body=%s", response.StatusCode, body)
	}
}

func requestIntegrationClientCredentialsToken(t *testing.T, client *http.Client, baseURL, clientID, secret string) string {
	t.Helper()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"scope":         {"mcp:read admin:read"},
	}
	response, err := client.Post(baseURL+"/realms/master/protocol/openid-connect/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("client-credentials token status = %d, body=%s", response.StatusCode, body)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil || token.AccessToken == "" {
		t.Fatalf("decode client-credentials token: token=%q err=%v", token.AccessToken, err)
	}
	return token.AccessToken
}

func postIntegrationMCP(t *testing.T, client *http.Client, baseURL, token string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func postIntegrationLogin(t *testing.T, client *http.Client, baseURL, username, password string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"realm":"master","username":%q,"password":%q}`, username, password)
	request, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/auth/login", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func openHTTPIntegrationStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("RESSO_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set RESSO_TEST_POSTGRES_DSN to run PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "resso_http_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme == "" {
		admin.Close()
		t.Fatal("RESSO_TEST_POSTGRES_DSN must be a PostgreSQL URL")
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	sealer, err := cryptoutil.NewSealer(bytes.Repeat([]byte{'i'}, 32))
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Open(ctx, parsed.String(), sealer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, data.Pool); err != nil {
		data.Close()
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		data.Close()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop HTTP integration schema: %v", err)
		}
		admin.Close()
	})
	return data
}

func TestIntegrationBackchannelLogoutTokenIsSignedAndScoped(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	bootstrap, err := data.Bootstrap(context.Background(), "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	created, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "logout-rp", Name: "Logout RP", Type: "confidential",
		RedirectURIs:         []string{"https://rp.example.com/callback"},
		BackchannelLogoutURI: "https://rp.example.com/backchannel-logout",
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionID, userID := uuid.New(), bootstrap.AdminUserID

	service := &ressooidc.Service{Store: data}
	raw, err := service.IssueLogoutToken(ctx, realm, created.Client, sessionID, userID)
	if err != nil {
		t.Fatal(err)
	}

	// Verify against the Realm's published JWKS, exactly as a relying party
	// would, then assert the claims required by Back-Channel Logout 1.0.
	keys, err := data.PublishedSigningKeys(ctx, realm.ID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	if typ, _ := parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string); typ != "logout+jwt" {
		t.Fatalf("logout token typ header = %q, want logout+jwt", typ)
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(keys[0].PublicJWK, &jwk); err != nil {
		t.Fatal(err)
	}
	var standard jwt.Claims
	var extra map[string]any
	if err := parsed.Claims(jwk.Key, &standard, &extra); err != nil {
		t.Fatalf("logout token did not verify against the published JWKS: %v", err)
	}
	if standard.Issuer != realm.IssuerURL {
		t.Fatalf("iss = %q, want %q", standard.Issuer, realm.IssuerURL)
	}
	if len(standard.Audience) != 1 || standard.Audience[0] != "logout-rp" {
		t.Fatalf("aud = %v", standard.Audience)
	}
	if standard.Subject != userID.String() {
		t.Fatalf("sub = %q, want %q", standard.Subject, userID)
	}
	if standard.ID == "" || standard.IssuedAt == nil || standard.Expiry == nil {
		t.Fatalf("logout token is missing jti/iat/exp: %+v", standard)
	}
	if extra["sid"] != sessionID.String() {
		t.Fatalf("sid = %v, want %q", extra["sid"], sessionID)
	}
	events, ok := extra["events"].(map[string]any)
	if !ok {
		t.Fatalf("events claim = %v", extra["events"])
	}
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Fatalf("events claim is missing the back-channel logout event: %v", events)
	}
	// A logout token must never carry a nonce.
	if _, present := extra["nonce"]; present {
		t.Fatal("logout token carries a nonce")
	}
}

func TestIntegrationMetricsRequireAdminAuthorizationAndRecordRequests(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	if _, bootstrapErr := data.Bootstrap(context.Background(), "admin", "bootstrap-password-123"); bootstrapErr != nil {
		t.Fatal(bootstrapErr)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar

	// Operational detail must not be readable by anyone who can reach the port.
	response, err := client.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous /metrics status = %d, want 401", response.StatusCode)
	}

	login := postIntegrationLogin(t, client, server.URL, "admin", "bootstrap-password-123")
	if login.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(login.Body)
		t.Fatalf("login status = %d, body=%s", login.StatusCode, body)
	}
	_ = login.Body.Close()

	response, err = client.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authenticated /metrics status = %d, body=%s", response.StatusCode, body)
	}
	rendered := string(body)
	for _, want := range []string{
		"# TYPE resso_http_requests_total counter",
		`resso_login_attempts_total{result="success"} 1`,
		"resso_http_request_duration_seconds_bucket",
		"resso_uptime_seconds",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, rendered)
		}
	}
	// Route patterns, not raw paths, keep the series count bounded.
	if strings.Contains(rendered, `route="/api/v1/auth/login"`) == false {
		t.Fatalf("login route was not recorded:\n%s", rendered)
	}
}

func TestIntegrationClientSecretBruteForceIsLimitedWithoutBlockingNeighbours(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	bootstrap, err := data.Bootstrap(context.Background(), "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	newClient := func(identifier string) store.CreatedClient {
		created, err := data.CreateClient(ctx, bootstrap.RealmID, store.CreateClientInput{
			ClientID: identifier, Name: identifier, Type: "confidential",
			RedirectURIs:  []string{"https://rp.example.com/callback"},
			GrantTypes:    []string{"client_credentials"},
			DefaultScopes: []string{"openid"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	target := newClient("target-client")
	neighbour := newClient("neighbour-client")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()

	tokenRequest := func(identifier, secret string) int {
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {identifier}, "client_secret": {secret}}
		response, err := client.PostForm(server.URL+"/realms/master/protocol/openid-connect/token", form)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return response.StatusCode
	}

	blockedAfter := 0
	for attempt := 1; attempt <= clientAuthMaxFailures+5; attempt++ {
		status := tokenRequest("target-client", "wrong-secret")
		if status == http.StatusTooManyRequests {
			blockedAfter = attempt
			break
		}
		if status != http.StatusUnauthorized {
			t.Fatalf("attempt %d returned %d, want 401", attempt, status)
		}
	}
	if blockedAfter == 0 {
		t.Fatalf("guessing was never rate limited within %d attempts", clientAuthMaxFailures+5)
	}
	if blockedAfter > clientAuthMaxFailures+1 {
		t.Fatalf("guessing was limited only after %d attempts", blockedAfter)
	}

	// Relying parties routinely share one egress address. A neighbour with a
	// correct secret must not be locked out by the client being guessed.
	if status := tokenRequest("neighbour-client", neighbour.ClientSecret); status != http.StatusOK {
		t.Fatalf("an unrelated client was blocked by another client's failures: status %d", status)
	}
	// The blocked client stays blocked even with the right secret.
	if status := tokenRequest("target-client", target.ClientSecret); status != http.StatusTooManyRequests {
		t.Fatalf("the limited client was not still blocked: status %d", status)
	}
}

func TestIntegrationQuickSearchPointsAtRoutesTheConsoleHas(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	bootstrap, err := data.Bootstrap(context.Background(), "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := data.CreateUser(ctx, bootstrap.RealmID, store.CreateUserInput{
		Username: "searchable", DisplayName: "Searchable One", Password: "searchable-password-1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateClient(ctx, bootstrap.RealmID, store.CreateClientInput{
		ClientID: "searchable-client", Name: "Searchable Client", Type: "public",
		RedirectURIs: []string{"https://rp.example.com/cb"}}); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	login := postIntegrationLogin(t, client, server.URL, "admin", "bootstrap-password-123")
	_ = login.Body.Close()

	response, err := client.Get(server.URL + "/api/admin/v1/quick-search?q=searchable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var payload struct {
		Items []struct{ Kind, Label, Path string } `json:"items"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Items) < 2 {
		t.Fatalf("quick search returned %d items", len(payload.Items))
	}
	// Every destination must be a route the console actually registers.
	// The user and client entries used to point at /admin/realms/{id}/users
	// and /admin/realms/{id}/clients, which do not exist: selecting one fell
	// through to the catch-all and landed on the personal profile instead.
	known := map[string]bool{"/admin/users": true, "/admin/clients": true, "/admin/user-federation": true, "/admin/realms": true}
	for _, item := range payload.Items {
		target, query, _ := strings.Cut(item.Path, "?")
		if strings.HasPrefix(target, "/admin/realms/") {
			continue // the Realm detail route takes an identifier
		}
		if !known[target] {
			t.Fatalf("%s %q points at %q, which the console does not route", item.Kind, item.Label, item.Path)
		}
		if !strings.Contains(query, "realm=master") {
			t.Fatalf("%s %q does not carry its Realm: %q", item.Kind, item.Label, item.Path)
		}
		if item.Kind == "user" || item.Kind == "client" {
			if !strings.Contains(query, "q=") {
				t.Fatalf("%s %q does not carry the search term: %q", item.Kind, item.Label, item.Path)
			}
		}
	}
}

// A personal API key carrying only mcp:read belongs to whoever asked for one —
// every user may mint one. The directory tools must still refuse it: the REST
// routes that return the same records sit behind requireAdmin, and reading the
// member list of a realm is what turns one compromised account into a target
// list for the rest.
func TestIntegrationMCPDirectoryToolsRefuseNonAdminKeys(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	intern, err := data.CreateUser(ctx, bootstrap.RealmID, store.CreateUserInput{
		Username: "intern", Password: "intern-password-123", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	internKey, err := data.CreatePersonalAPIKey(ctx, intern.ID, "agent", []string{"mcp:read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	adminKey, err := data.CreatePersonalAPIKey(ctx, bootstrap.AdminUserID, "agent",
		[]string{"mcp:read", "admin:read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()

	listed := callIntegrationMCP(t, client, server.URL, internKey.Secret,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	for _, name := range []string{"resso_search_users", "resso_list_clients"} {
		if strings.Contains(listed, name) {
			t.Errorf("tools/list offered %s to a non-admin key: %s", name, listed)
		}
	}

	for _, call := range []string{
		`{"name":"resso_search_users","arguments":{"query":"ad"}}`,
		`{"name":"resso_list_clients","arguments":{}}`,
	} {
		body := callIntegrationMCP(t, client, server.URL, internKey.Secret,
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":`+call+`}`)
		if !strings.Contains(body, `"isError":true`) {
			t.Errorf("non-admin key ran %s: %s", call, body)
		}
		if strings.Contains(body, "admin") && !strings.Contains(body, `"isError":true`) {
			t.Errorf("non-admin key read directory records: %s", body)
		}
	}

	// The same tools must keep working for a key that does carry admin:read,
	// so the fix bounds the audience rather than removing the capability.
	body := callIntegrationMCP(t, client, server.URL, adminKey.Secret,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"resso_search_users","arguments":{"query":"ad"}}}`)
	if strings.Contains(body, `"isError":true`) || !strings.Contains(body, `"username":"admin"`) {
		t.Fatalf("admin key could not search users: %s", body)
	}
}

func callIntegrationMCP(t *testing.T, client *http.Client, baseURL, token, payload string) string {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("MCP status = %d, body=%s", response.StatusCode, body)
	}
	return string(body)
}

// The refresh exchange rotates before it issues. A rejection that happens
// after the rotation costs the relying party the only token it holds: it works
// for the length of the grace window and then reads as a replay, revoking the
// family and reporting a theft that never happened. Rejecting before the
// rotation is what keeps the caller whole.
// Presenting a rotated refresh token again is the strongest signal this service
// has that a token was taken, and the operations guide sends a reader to the
// audit screen to look for it. The entry named the client and left the actor
// blank, so the screen showed no account and a search by account could never
// return it — for the one event where "whose" is the question.
// A Realm with no key to sign with cannot issue tokens, and that is a fault on
// this side. It was answered as invalid_grant, which tells a relying party its
// refresh token is spent — and the ordinary response to that is to discard it
// and send the person back to sign in, which also cannot work while the key is
// gone. A Realm that lost its key would come back to find every session that
// could have survived thrown away by the clients that tried during it. The
// dashboard has a readiness row for exactly this state, so it is one the
// service expects to be in.
// Suspending a Realm is documented as stopping the whole tenant, and the
// operations guide enumerates what stops: discovery, JWKS, authorization,
// token, userinfo, introspection and revocation. One function decides it for
// all of them, which is the right shape — and nothing checked that every
// protocol route actually goes through it. A route added later that resolves
// the Realm its own way would serve a suspended tenant with the guide still
// promising otherwise.
// Creating a Realm is two writes: the Realm, then its first signing key. When
// the second failed the handler answered 500 and returned — before the line
// that records what happened. The Realm exists from the first write onward, so
// the trail had no answer to "when did this tenant appear", and the only record
// was a server log kept for thirty days against the trail's year. The same
// shape as an administrator ending a session and having it go unrecorded,
// which this service corrected once already.
func TestIntegrationRealmCreatedWithoutItsKeyIsStillRecorded(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	if _, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123"); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar}
	loginResponse := postIntegrationLogin(t, browser, server.URL, "admin", "bootstrap-password-123")
	var login struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(loginResponse.Body).Decode(&login); err != nil {
		t.Fatal(err)
	}
	_ = loginResponse.Body.Close()

	// Only the key write fails. Everything else about the request is ordinary,
	// which is what makes the Realm exist while the response says it went wrong.
	if _, err := data.Pool.Exec(ctx, `CREATE FUNCTION block_key() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'signing key blocked for the test'; END $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `CREATE TRIGGER block_key BEFORE INSERT ON signing_keys
		FOR EACH ROW EXECUTE FUNCTION block_key()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = data.Pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS block_key ON signing_keys")
	})

	body := `{"name":"tenant-without-a-key","display_name":"Tenant","issuer_url":"https://sso.example.com/realms/tenant-without-a-key"}`
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/admin/v1/realms", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", login.CSRFToken)
	response, err := browser.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("creating a Realm whose key could not be written answered %d", response.StatusCode)
	}

	// The Realm is there, which is what makes the missing record matter.
	var exists bool
	if err := data.Pool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM realms WHERE name='tenant-without-a-key')").Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("the Realm was not created, so there is nothing for the trail to be missing")
	}

	page, err := data.ListAudit(ctx, store.AuditFilter{EventType: "REALM_CREATE", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("%d REALM_CREATE entries: a tenant exists that the trail cannot date", len(page.Items))
	}
	if page.Items[0].Result != "PARTIAL" {
		t.Errorf("the entry records %s; the Realm was created and its key was not, which is neither "+
			"a plain success nor nothing happening", page.Items[0].Result)
	}
	var detail map[string]any
	if err := json.Unmarshal(page.Items[0].Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail["signing_key"] != "not_created" {
		t.Errorf("the entry does not say which half failed: %v", detail)
	}
}

func TestIntegrationSuspendedRealmRefusesEveryProtocolEndpoint(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	if _, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123"); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, realm.ID); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	const base = "/realms/master"
	endpoints := []struct{ method, path string }{
		{http.MethodGet, base + "/.well-known/openid-configuration"},
		{http.MethodGet, base + "/protocol/openid-connect/certs"},
		{http.MethodGet, base + "/protocol/openid-connect/auth"},
		{http.MethodPost, base + "/protocol/openid-connect/token"},
		{http.MethodGet, base + "/protocol/openid-connect/userinfo"},
		{http.MethodPost, base + "/protocol/openid-connect/userinfo"},
		{http.MethodGet, base + "/protocol/openid-connect/logout"},
		{http.MethodPost, base + "/protocol/openid-connect/logout"},
	}
	call := func(method, path string) (int, string) {
		t.Helper()
		request, requestErr := http.NewRequest(method, server.URL+path, strings.NewReader(""))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, doErr := server.Client().Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}

	// While it is running, discovery answers — so a refusal below means the
	// suspension and not a path that never existed.
	if status, _ := call(http.MethodGet, base+"/.well-known/openid-configuration"); status != http.StatusOK {
		t.Fatalf("discovery answered %d before the Realm was suspended", status)
	}

	if _, err := data.Pool.Exec(ctx, "UPDATE realms SET enabled=false WHERE id=$1", realm.ID); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range endpoints {
		status, _ := call(endpoint.method, endpoint.path)
		if status < 400 {
			t.Errorf("%s %s answered %d while the Realm was suspended: the operations guide says "+
				"the whole tenant stops", endpoint.method, endpoint.path, status)
		}
	}

	// Introspection and revocation are the two that must not refuse, and it is
	// not an exception to the rule above — it is how the rule is expressed
	// there. RFC 7662 answers an unknown token with active:false and RFC 7009
	// answers 200, both so that neither endpoint becomes a way to ask whether
	// something exists. A suspended Realm has to look exactly like a Realm with
	// nothing in it, which is what these two say.
	status, body := call(http.MethodPost, base+"/protocol/openid-connect/token/introspect")
	if status != http.StatusOK {
		t.Errorf("introspection answered %d for a suspended Realm, which tells a caller it exists", status)
	}
	var introspection struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal([]byte(body), &introspection); err != nil {
		t.Fatalf("introspection answered something that is not the documented shape: %s", body)
	}
	if introspection.Active {
		t.Error("introspection reported a token as active in a suspended Realm")
	}
	if status, _ := call(http.MethodPost, base+"/protocol/openid-connect/revoke"); status != http.StatusOK {
		t.Errorf("revocation answered %d for a suspended Realm; RFC 7009 answers 200 so that the "+
			"endpoint cannot be used to ask what exists", status)
	}

	// Suspension is blocking, not discarding: the guide says re-enabling brings
	// the tenant back.
	if _, err := data.Pool.Exec(ctx, "UPDATE realms SET enabled=true WHERE id=$1", realm.ID); err != nil {
		t.Fatal(err)
	}
	if status, _ := call(http.MethodGet, base+"/.well-known/openid-configuration"); status != http.StatusOK {
		t.Errorf("discovery answered %d after the Realm was enabled again", status)
	}
}

func TestIntegrationTokenEndpointDoesNotBlameTheGrantForAMissingSigningKey(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	created, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "keyless-probe", Name: "Keyless Probe", Type: "public",
		RedirectURIs: []string{"https://probe.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "keyless-integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	userID := bootstrap.AdminUserID
	sessionID := session.Session.ID
	raw, err := data.CreateRefreshToken(ctx, store.RefreshToken{RealmID: realm.ID, ClientID: created.Client.ID,
		UserID: &userID, SessionID: &sessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	// No signing key is created for this Realm, which is the state the
	// dashboard reports as "ACTIVE 키 누락".
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw},
		"client_id": {"keyless-probe"}}
	response, err := server.Client().PostForm(server.URL+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	var answer struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if unmarshalErr := json.Unmarshal(body, &answer); unmarshalErr != nil {
		t.Fatalf("the endpoint answered something that is not an OAuth error: %s", body)
	}
	if answer.Error == "invalid_grant" {
		t.Fatalf("a missing signing key was reported as a bad grant: the client discards a refresh "+
			"token that is perfectly good (%s)", body)
	}
	if answer.Error != "server_error" || response.StatusCode != http.StatusInternalServerError {
		t.Errorf("answered %d %q, want 500 server_error", response.StatusCode, answer.Error)
	}
	if !strings.Contains(answer.Description, "signing key") {
		t.Errorf("the description does not say what is missing: %q", answer.Description)
	}

	// And the token was not consumed by the attempt.
	var rotatedAt *time.Time
	if err := data.Pool.QueryRow(ctx,
		`SELECT rotated_at FROM refresh_tokens WHERE session_id=$1 AND parent_id IS NULL`,
		sessionID).Scan(&rotatedAt); err != nil {
		t.Fatal(err)
	}
	if rotatedAt != nil {
		t.Error("the refresh token was spent by an attempt that could never have produced a token")
	}
}

func TestIntegrationRefreshTokenReuseNamesTheAccount(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	created, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "reuse-probe", Name: "Reuse Probe", Type: "public",
		RedirectURIs: []string{"https://probe.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "reuse-integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	userID := bootstrap.AdminUserID
	sessionID := session.Session.ID
	raw, err := data.CreateRefreshToken(ctx, store.RefreshToken{RealmID: realm.ID, ClientID: created.Client.ID,
		UserID: &userID, SessionID: &sessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, realm.ID); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	refresh := func(token string) (int, string) {
		t.Helper()
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token},
			"client_id": {"reuse-probe"}}
		response, postErr := server.Client().PostForm(
			server.URL+"/realms/master/protocol/openid-connect/token", form)
		if postErr != nil {
			t.Fatal(postErr)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}

	if status, body := refresh(raw); status != http.StatusOK {
		t.Fatalf("the first refresh answered %d: %s", status, body)
	}
	// Past the rotation grace, which exists so that parallel tabs and a retried
	// request whose response was lost are not treated as theft. Inside it the
	// same token is accepted again on purpose; outside it, this is reuse.
	if _, err := data.Pool.Exec(ctx, `UPDATE refresh_tokens SET rotated_at=now()-interval '1 minute'
		WHERE session_id=$1 AND parent_id IS NULL`, sessionID); err != nil {
		t.Fatal(err)
	}
	if status, body := refresh(raw); status != http.StatusBadRequest {
		t.Fatalf("presenting a rotated token again answered %d (%s), so no reuse was detected", status, body)
	}

	page, err := data.ListAudit(ctx, store.AuditFilter{RealmID: &realm.ID,
		EventType: "REFRESH_TOKEN_REUSE", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("%d reuse events were recorded, want 1", len(page.Items))
	}
	if page.Items[0].ActorName != "admin" {
		t.Errorf("the reuse entry names the actor as %q: the audit screen shows no account for it, "+
			"and narrowing the trail to that person never returns it", page.Items[0].ActorName)
	}
	// Narrowing by account is how this is looked for, so it has to work.
	byActor, err := data.ListAudit(ctx, store.AuditFilter{RealmID: &realm.ID,
		EventType: "REFRESH_TOKEN_REUSE", Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byActor.Items) != 1 {
		t.Errorf("searching the trail for that account returned %d reuse events", len(byActor.Items))
	}
}

func TestIntegrationRefreshFailureLeavesTheClientsTokenUsable(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	created, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "refresh-probe", Name: "Refresh Probe", Type: "public",
		RedirectURIs: []string{"https://probe.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "refresh-integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	userID := bootstrap.AdminUserID
	sessionID := session.Session.ID
	raw, err := data.CreateRefreshToken(ctx, store.RefreshToken{RealmID: realm.ID, ClientID: created.Client.ID,
		UserID: &userID, SessionID: &sessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	// A disabled account is the common way this exchange fails, and the
	// rejection must not cost the caller its token.
	if _, err := data.Pool.Exec(ctx, `UPDATE users SET enabled=false WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}, "client_id": {"refresh-probe"}}
	response, err := server.Client().PostForm(server.URL+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh for a disabled account status = %d", response.StatusCode)
	}

	var rotatedAt *time.Time
	var children int
	if err := data.Pool.QueryRow(ctx, `SELECT rotated_at,
		(SELECT count(*) FROM refresh_tokens c WHERE c.parent_id=t.id) FROM refresh_tokens t
		WHERE t.session_id=$1 AND t.parent_id IS NULL`, sessionID).Scan(&rotatedAt, &children); err != nil {
		t.Fatal(err)
	}
	if rotatedAt != nil {
		t.Error("the client's token was left marked rotated after a failed exchange")
	}
	if children != 0 {
		t.Errorf("an undelivered successor token was left behind: %d", children)
	}
}

// Revocation answers 200 whether or not the token matched, which is what the
// specification requires but leaves the audit trail unable to say whether a
// token is actually dead. The entry has to distinguish the three outcomes.
func TestIntegrationRevocationAuditRecordsWhatWasRevoked(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	created, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "revoke-probe", Name: "Revoke Probe", Type: "confidential",
		RedirectURIs: []string{"https://probe.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "revoke-integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	userID := bootstrap.AdminUserID
	sessionID := session.Session.ID
	raw, err := data.CreateRefreshToken(ctx, store.RefreshToken{RealmID: realm.ID, ClientID: created.Client.ID,
		UserID: &userID, SessionID: &sessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	revoke := func(token string) {
		t.Helper()
		form := url.Values{"token": {token}, "client_id": {"revoke-probe"},
			"client_secret": {created.ClientSecret}}
		response, postErr := server.Client().PostForm(server.URL+"/realms/master/protocol/openid-connect/revoke", form)
		if postErr != nil {
			t.Fatal(postErr)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("revoke status = %d", response.StatusCode)
		}
	}

	revoke("not-a-token-anyone-issued")
	revoke(raw)

	page, err := data.ListAudit(ctx, store.AuditFilter{EventType: "TOKEN_REVOKED", Ascending: true, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("audit entries = %d, want 2", len(page.Items))
	}
	detailOf := func(index int) map[string]any {
		t.Helper()
		var decoded map[string]any
		if err := json.Unmarshal(page.Items[index].Detail, &decoded); err != nil {
			t.Fatalf("decode audit detail: %v", err)
		}
		return decoded
	}
	if got := detailOf(0)["revoked"]; got != "none" {
		t.Errorf("an unmatched token recorded revoked=%v, want none", got)
	}
	matched := detailOf(1)
	if got := matched["revoked"]; got != "refresh_token" {
		t.Errorf("a revoked refresh token recorded revoked=%v", got)
	}
	if matched["family_id"] == nil {
		t.Error("the revoked family was not recorded")
	}
}

// Introspection is how a resource server asks, in real time, whether a token
// it was handed still stands. Disabling an account stopped it at userinfo and
// at the refresh grant immediately, but this endpoint kept answering active
// until the access token expired on its own — so the one API built to give the
// current answer was the one giving the stale one, and an operator who had
// just disabled somebody watched them keep working.
func TestIntegrationIntrospectionFollowsTheAccountItReportsOn(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	resourceServer, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "introspection-rs", Name: "Introspecting Resource Server", Type: "confidential",
		RedirectURIs:  []string{"https://rs.example.test/cb"},
		GrantTypes:    []string{"authorization_code", "client_credentials"},
		DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(ctx, realm.ID, store.CreateUserInput{
		Username: "introspected", Password: "introspected-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, user.ID, time.Hour, "127.0.0.1", "introspection-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	service := ressooidc.Service{Store: data}
	userTokens, err := service.IssueUserTokens(ctx, realm, resourceServer.Client, user, session.Session.ID,
		[]string{"openid"}, "", false)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	introspect := func(token string) bool {
		t.Helper()
		form := url.Values{"token": {token}, "client_id": {"introspection-rs"},
			"client_secret": {resourceServer.ClientSecret}}
		response, postErr := server.Client().PostForm(
			server.URL+"/realms/master/protocol/openid-connect/token/introspect", form)
		if postErr != nil {
			t.Fatal(postErr)
		}
		defer response.Body.Close()
		var decoded map[string]any
		if decodeErr := json.NewDecoder(response.Body).Decode(&decoded); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		active, _ := decoded["active"].(bool)
		return active
	}
	userInfoAccepts := func(token string) bool {
		t.Helper()
		request, requestErr := http.NewRequest(http.MethodGet,
			server.URL+"/realms/master/protocol/openid-connect/userinfo", nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, doErr := server.Client().Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	}

	if !introspect(userTokens.AccessToken) || !userInfoAccepts(userTokens.AccessToken) {
		t.Fatal("an enabled account's token was not usable to begin with")
	}
	if _, err := data.UpdateUser(ctx, user.ID, store.UpdateUserInput{
		DisplayName: user.DisplayName, Email: user.Email, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if userInfoAccepts(userTokens.AccessToken) {
		t.Error("userinfo served a disabled account")
	}
	if introspect(userTokens.AccessToken) {
		t.Error("introspection reported active for a disabled account")
	}

	// A client's own token names no person, so nothing about an account can
	// make it inactive. Checking it here keeps the account lookup from being
	// applied to a subject that is a client identifier.
	clientToken, err := service.IssueClientToken(ctx, realm, resourceServer.Client, []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	if !introspect(clientToken.AccessToken) {
		t.Error("a client-credentials token was reported inactive")
	}
}

// max_age is how a relying party demands a fresh proof of identity before
// something sensitive. It was accepted and ignored, so the request came back
// with a code minted from whatever session already existed — indistinguishable,
// from the relying party's side, from a reauthentication that never happened.
func TestIntegrationMaxAgeForcesReauthentication(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "step-up", Name: "Step Up", Type: "public",
		RedirectURIs: []string{"https://step-up.example.test/cb"},
		GrantTypes:   []string{"authorization_code"}, DefaultScopes: []string{"openid"}}); err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "max-age-test", "password")
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Public clients must use PKCE, so every probe carries a valid challenge.
	verifier := strings.Repeat("step-up-verifier", 4)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authorize := func(extra string) *url.URL {
		t.Helper()
		target := server.URL + "/realms/master/protocol/openid-connect/auth?response_type=code&client_id=step-up" +
			"&redirect_uri=" + url.QueryEscape("https://step-up.example.test/cb") + "&scope=openid&state=s" +
			"&code_challenge=" + challenge + "&code_challenge_method=S256" + extra
		request, reqErr := http.NewRequest(http.MethodGet, target, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.Token})
		response, doErr := client.Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		_ = response.Body.Close()
		location, parseErr := url.Parse(response.Header.Get("Location"))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		return location
	}

	// A generous max_age is satisfied by the session that already exists.
	if got := authorize("&max_age=3600"); got.Query().Get("code") == "" {
		t.Fatalf("a fresh session did not satisfy max_age=3600: %s", got)
	}

	// Age the authentication past what the relying party will accept.
	if _, err := data.Pool.Exec(ctx,
		`UPDATE sso_sessions SET created_at=now()-interval '20 minutes' WHERE id=$1`, session.Session.ID); err != nil {
		t.Fatal(err)
	}
	stale := authorize("&max_age=300")
	if stale.Query().Get("code") != "" {
		t.Errorf("max_age=300 was satisfied by a 20-minute-old authentication: %s", stale)
	}
	if stale.Path != "/login" || stale.Query().Get("request") == "" {
		t.Errorf("a stale authentication did not send the user to sign in again: %s", stale)
	}

	// With prompt=none there is nobody to ask, so the relying party has to be
	// told rather than handed a code it asked not to receive.
	silent := authorize("&max_age=300&prompt=none")
	if silent.Query().Get("error") != "login_required" {
		t.Errorf("prompt=none with a stale authentication returned %q", silent.Query().Get("error"))
	}

	// A value that is not a number is refused, not quietly dropped.
	malformed := authorize("&max_age=soon")
	if malformed.Query().Get("error") != "invalid_request" {
		t.Errorf("malformed max_age returned %q", malformed.Query().Get("error"))
	}
}

// A relying party sends request objects to protect the parameters inside them,
// and id_token_hint to name the account it believes it is renewing. Accepting
// either and acting on neither is a silent downgrade: the first honours the
// unsigned query string instead, the second can hand back a code for whoever
// happens to be signed in now.
func TestIntegrationAuthorizationRefusesUnsupportedAndMismatchedHints(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "hint-probe", Name: "Hint Probe", Type: "public",
		RedirectURIs: []string{"https://hint.example.test/cb"},
		GrantTypes:   []string{"authorization_code"}, DefaultScopes: []string{"openid"}}); err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "hint-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	// ID tokens are signed, and the key is created lazily on first use.
	if err := data.EnsureActiveSigningKey(ctx, realm.ID); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	verifier := strings.Repeat("hint-probe-verifier", 3)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authorize := func(extra string) *url.URL {
		t.Helper()
		target := server.URL + "/realms/master/protocol/openid-connect/auth?response_type=code&client_id=hint-probe" +
			"&redirect_uri=" + url.QueryEscape("https://hint.example.test/cb") + "&scope=openid&state=s" +
			"&code_challenge=" + challenge + "&code_challenge_method=S256" + extra
		request, reqErr := http.NewRequest(http.MethodGet, target, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.Token})
		response, doErr := client.Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		_ = response.Body.Close()
		location, parseErr := url.Parse(response.Header.Get("Location"))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		return location
	}

	for parameter, expected := range map[string]string{
		"&request=eyJhbGciOiJub25lIn0.e30.":               "request_not_supported",
		"&request_uri=https%3A%2F%2Fattacker.example%2Fr": "request_uri_not_supported",
	} {
		if got := authorize(parameter).Query().Get("error"); got != expected {
			t.Errorf("%s returned %q, want %q", parameter, got, expected)
		}
	}

	// A hint naming somebody else must not be answered with a code for the
	// person who is actually signed in.
	hint := issueIntegrationIDToken(t, data, realm, "hint-probe", "someone-else")
	mismatch := authorize("&prompt=none&id_token_hint=" + url.QueryEscape(hint))
	if got := mismatch.Query().Get("error"); got != "login_required" {
		t.Errorf("a mismatched id_token_hint returned %q, want login_required", got)
	}
	if mismatch.Query().Get("code") != "" {
		t.Error("a mismatched id_token_hint was answered with a code")
	}

	// The hint for the account that is signed in is satisfied silently.
	admin, err := data.UserByID(ctx, bootstrap.AdminUserID)
	if err != nil {
		t.Fatal(err)
	}
	matching := issueIntegrationIDTokenFor(t, data, realm, "hint-probe", admin, session.Session.ID)
	if got := authorize("&prompt=none&id_token_hint=" + url.QueryEscape(matching)); got.Query().Get("code") == "" {
		t.Errorf("a matching id_token_hint was refused: %s", got)
	}

	// Something that is not a token this issuer signed is refused outright.
	if got := authorize("&id_token_hint=not-a-jwt").Query().Get("error"); got != "invalid_request" {
		t.Errorf("a malformed id_token_hint returned %q", got)
	}
}

// issueIntegrationIDToken mints a real ID token for a freshly created account,
// which is how a hint naming a different person is produced without forging
// anything the server would refuse for the wrong reason.
func issueIntegrationIDToken(t *testing.T, data *store.Store, realm domain.Realm, clientID, username string) string {
	t.Helper()
	ctx := context.Background()
	user, err := data.CreateUser(ctx, realm.ID, store.CreateUserInput{
		Username: username, Password: username + "-password-1234", Enabled: true})
	if err != nil {
		t.Fatalf("create hint user: %v", err)
	}
	session, err := data.CreateSession(ctx, realm.ID, user.ID, time.Hour, "127.0.0.1", "hint-test", "password")
	if err != nil {
		t.Fatalf("create hint session: %v", err)
	}
	return issueIntegrationIDTokenFor(t, data, realm, clientID, user, session.Session.ID)
}

func issueIntegrationIDTokenFor(t *testing.T, data *store.Store, realm domain.Realm,
	clientID string, user domain.User, sessionID uuid.UUID) string {
	t.Helper()
	ctx := context.Background()
	client, err := data.ClientByIdentifier(ctx, realm.ID, clientID)
	if err != nil {
		t.Fatalf("load hint client %q: %v", clientID, err)
	}
	service := ressooidc.Service{Store: data}
	tokens, err := service.IssueUserTokens(ctx, realm, client, user, sessionID, []string{"openid"}, "", false)
	if err != nil {
		t.Fatalf("issue hint tokens: %v", err)
	}
	if tokens.IDToken == "" {
		t.Fatal("no ID token was issued")
	}
	return tokens.IDToken
}

// Shutdown has to write out what is buffered. The last seconds before a
// restart are exactly the ones an operator goes looking for afterwards, and
// the mirror batches on a timer, so without a flush they are simply gone.
func TestIntegrationLogMirrorFlushesOnShutdown(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	metrics := observability.NewRegistry()
	handler := observability.NewDBHandler(slog.NewTextHandler(io.Discard, nil), data, "shutdown-test", metrics)
	logger := slog.New(handler)
	for index := range 5 {
		logger.Info("buffered before shutdown", "index", index)
	}

	// Close returns only once the writer has drained, so no sleep is needed.
	handler.Close(5 * time.Second)

	var written int
	if err := data.Pool.QueryRow(ctx,
		`SELECT count(*) FROM system_logs WHERE component='shutdown-test'`).Scan(&written); err != nil {
		t.Fatal(err)
	}
	if written != 5 {
		t.Errorf("records written on shutdown = %d, want 5", written)
	}
	var exported strings.Builder
	metrics.WritePrometheus(&exported)
	if !strings.Contains(exported.String(), `result="written"`) {
		t.Errorf("the written outcome was not reported: %s", exported.String())
	}
}

// The keys screen and the dashboard both decide whether a signing key has aged
// past the advisory. The console kept its own copy of the threshold with a
// comment promising it matched the server's — a promise nothing enforced — so
// the number now travels with the keys and the screen has nothing to copy.
func TestIntegrationSigningKeyListCarriesTheAdvisoryThreshold(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	if _, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123"); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, realm.ID); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	login := postIntegrationLogin(t, client, server.URL, "admin", "bootstrap-password-123")
	_ = login.Body.Close()
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", login.StatusCode)
	}

	response, err := client.Get(server.URL + "/api/admin/v1/realms/" + realm.ID.String() + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("keys status = %d", response.StatusCode)
	}
	var payload struct {
		Items        []map[string]any `json:"items"`
		AdvisoryDays int              `json:"advisory_days"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Items) == 0 {
		t.Fatal("no signing keys were listed")
	}
	if payload.AdvisoryDays != signingKeyAdvisoryDays {
		t.Errorf("advisory_days = %d, want %d — the screen would fall back to its own number",
			payload.AdvisoryDays, signingKeyAdvisoryDays)
	}
}

// An attempt that cannot be completed is neither a success nor a rejected
// credential. Counting it as neither meant a directory outage — where every
// attempt fails before either outcome — showed up as the login series going
// quiet, and quiet is what a working night looks like.
func TestIntegrationLoginErrorsAreCounted(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	if _, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123"); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	// A linked account whose directory does not answer: the attempt cannot be
	// completed, rather than being right or wrong.
	provider, err := data.CreateLDAPFederation(ctx, realm.ID, store.LDAPFederationInput{
		Name: "gone", Vendor: "OTHER", ConnectionURL: "ldap://127.0.0.1:1",
		UsersDN: "ou=people,dc=example,dc=test", UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "KEEP",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	linked, err := data.CreateUser(ctx, realm.ID, store.CreateUserInput{
		Username: "linked", Password: "linked-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	dn := "uid=linked,ou=people,dc=example,dc=test"
	external := "linked-external"
	if _, err := data.Pool.Exec(ctx,
		`UPDATE users SET federation_id=$2,external_id=$3,external_dn=$4 WHERE id=$1`,
		linked.ID, provider.ID, external, dn); err != nil {
		t.Fatal(err)
	}

	metrics := observability.NewRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, metrics).Handler())
	t.Cleanup(server.Close)

	response := postIntegrationLogin(t, server.Client(), server.URL, "linked", "linked-password-1234")
	_ = response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("an unreachable directory answered %d", response.StatusCode)
	}
	var exported strings.Builder
	metrics.WritePrometheus(&exported)
	if !strings.Contains(exported.String(), `resso_login_attempts_total{result="error"} 1`) {
		t.Errorf("the attempt was not counted as an error:\n%s", exported.String())
	}
}

// A signing key the service cannot open takes every token request with it.
// Counting only successes meant that showed up as the issuance series going
// flat — indistinguishable from a quiet hour, and the only other signal was a
// line in the log.
func TestIntegrationTokenIssuanceFailuresAreCounted(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	if _, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123"); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	created, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "issue-probe", Name: "Issue Probe", Type: "confidential",
		RedirectURIs: []string{"https://probe.example.test/cb"},
		GrantTypes:   []string{"client_credentials"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, realm.ID); err != nil {
		t.Fatal(err)
	}
	// The key is there but its envelope no longer opens, which is what a
	// keyring that does not match the database looks like.
	if _, err := data.Pool.Exec(ctx,
		`UPDATE signing_keys SET private_key_cipher=decode('00', 'hex') WHERE realm_id=$1 AND status='ACTIVE'`,
		realm.ID); err != nil {
		t.Fatal(err)
	}
	data.InvalidateAllSigningKeys()

	metrics := observability.NewRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, metrics).Handler())
	t.Cleanup(server.Close)

	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"issue-probe"},
		"client_secret": {created.ClientSecret}, "scope": {"openid"}}
	response, err := server.Client().PostForm(server.URL+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("an unopenable signing key answered %d", response.StatusCode)
	}
	var exported strings.Builder
	metrics.WritePrometheus(&exported)
	if !strings.Contains(exported.String(), `resso_token_errors_total{grant_type="client_credentials"} 1`) {
		t.Errorf("the failure was not counted:\n%s", exported.String())
	}
	// And it is not passed off as an issuance, which is what the other counter
	// is for.
	if strings.Contains(exported.String(), `resso_tokens_issued_total{grant_type="client_credentials"}`) {
		t.Error("a failed request was counted as an issued token")
	}
}

// An agent reading the user directory through MCP left no trace at all, so a
// disclosure about that access could not be answered — nobody could say
// whether it had happened. Both outcomes are worth recording: the read itself,
// and the attempt that was turned away.
// Every other tool on this surface returns everything it found, so an agent
// reading a bare array is entitled to treat it as the whole answer. The user
// search is capped, and said nothing about it: asked how many people are called
// Kim, an agent would have answered twenty when there were more. It now reports
// what matched alongside what it returned.
func TestIntegrationMCPUserSearchSaysWhenItIsTruncated(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	const matching = 25
	for index := 0; index < matching; index++ {
		if _, err := data.CreateUser(ctx, bootstrap.RealmID, store.CreateUserInput{
			Username: fmt.Sprintf("kim%02d", index), Password: "kim-password-1234",
			Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	key, err := data.CreatePersonalAPIKey(ctx, bootstrap.AdminUserID, "agent",
		[]string{"mcp:read", "admin:read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	read := func(query string) (items int, matched int, truncated bool) {
		t.Helper()
		body := callIntegrationMCP(t, server.Client(), server.URL, key.Secret,
			fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"resso_search_users","arguments":{"query":%q}}}`, query))
		var envelope struct {
			Result struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(body), &envelope); err != nil {
			t.Fatalf("decoding the MCP envelope: %v (body=%s)", err, body)
		}
		if len(envelope.Result.Content) == 0 {
			t.Fatalf("the tool returned no content: %s", body)
		}
		var payload struct {
			Items     []map[string]any `json:"items"`
			Matched   int              `json:"matched"`
			Truncated bool             `json:"truncated"`
		}
		if err := json.Unmarshal([]byte(envelope.Result.Content[0].Text), &payload); err != nil {
			t.Fatalf("the tool answered with something that is not the documented shape: %v (%s)",
				err, envelope.Result.Content[0].Text)
		}
		return len(payload.Items), payload.Matched, payload.Truncated
	}

	items, matched, truncated := read("kim")
	if matched != matching {
		t.Errorf("the tool reported %d matching users, want %d", matched, matching)
	}
	if items >= matched {
		t.Errorf("returned %d of %d: this proves nothing about reporting a cap", items, matched)
	}
	if !truncated {
		t.Error("the answer was cut and did not say so, which is what makes an agent report it as complete")
	}

	// And an answer that fits is not labelled as cut.
	items, matched, truncated = read("admin")
	if truncated || items != matched {
		t.Errorf("a complete answer reported items=%d matched=%d truncated=%v", items, matched, truncated)
	}
}

func TestIntegrationMCPDirectoryReadsAreRecorded(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	intern, err := data.CreateUser(ctx, bootstrap.RealmID, store.CreateUserInput{
		Username: "intern", Password: "intern-password-123", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	adminKey, err := data.CreatePersonalAPIKey(ctx, bootstrap.AdminUserID, "agent",
		[]string{"mcp:read", "admin:read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	internKey, err := data.CreatePersonalAPIKey(ctx, intern.ID, "agent", []string{"mcp:read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	search := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"resso_search_users","arguments":{"query":"ad"}}}`
	status := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"resso_service_status","arguments":{}}}`

	callIntegrationMCP(t, server.Client(), server.URL, adminKey.Secret, search)
	callIntegrationMCP(t, server.Client(), server.URL, internKey.Secret, search)
	// Status is polled and harmless; recording it would bury what matters.
	callIntegrationMCP(t, server.Client(), server.URL, adminKey.Secret, status)

	page, err := data.ListAudit(ctx, store.AuditFilter{EventType: "MCP_TOOL_CALL", Ascending: true, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("recorded %d calls, want the two directory reads only", len(page.Items))
	}
	if page.Items[0].Result != "SUCCESS" || page.Items[0].ActorName != "admin" {
		t.Errorf("the permitted read recorded %+v", page.Items[0])
	}
	if page.Items[1].Result != "FAILURE" || page.Items[1].ActorName != "intern" {
		t.Errorf("the refused attempt recorded %+v", page.Items[1])
	}
	for _, item := range page.Items {
		if item.TargetID != "resso_search_users" {
			t.Errorf("the tool was not recorded: %+v", item)
		}
	}
}

// Switching a Realm off, or a Client, is an operator saying "this stops now".
// Whether it stopped depended on which endpoint was asked. Discovery, JWKS,
// authorization and the token endpoint tested the flags; userinfo,
// introspection, revocation and RP-initiated logout resolved the Realm through
// the same helper and never looked, and introspection and revocation
// authenticated the Client through the same helper and never looked either.
//
// So a suspended tenant went on handing out its users' claims and telling
// resource servers their tokens were good, and a decommissioned Client kept a
// working secret at the one endpoint that is deliberately open to every
// confidential Client of the Realm — able to validate and read the contents of
// tokens minted for anybody else.
func TestIntegrationDisabledRealmAndClientAreRefusedEverywhere(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "suspendable-rs", Name: "Resource Server", Type: "confidential",
		RedirectURIs:           []string{"https://rs.example.test/cb"},
		PostLogoutRedirectURIs: []string{"https://rs.example.test/bye"},
		GrantTypes:             []string{"authorization_code"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(ctx, realm.ID, store.CreateUserInput{
		Username: "tenant-user", Password: "tenant-user-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, user.ID, time.Hour, "127.0.0.1", "suspension-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	service := ressooidc.Service{Store: data}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	base := server.URL + "/realms/master/protocol/openid-connect"

	// Revocation consumes the token it is given, so every probe gets its own.
	// They are all minted here, while the Realm and the Client are still
	// running, because a token already in somebody's hands is exactly what
	// this is about — and issuing one is itself refused once the Realm is
	// suspended, which the token endpoint covers.
	minted := make([]string, 0, 12)
	for range cap(minted) {
		issued, issueErr := service.IssueUserTokens(ctx, realm, rs.Client, user, session.Session.ID,
			[]string{"openid"}, "", false)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		minted = append(minted, issued.AccessToken)
	}
	freshToken := func() string {
		t.Helper()
		if len(minted) == 0 {
			t.Fatal("the test ran out of pre-minted access tokens")
		}
		token := minted[0]
		minted = minted[1:]
		return token
	}
	clientForm := func() url.Values {
		return url.Values{"token": {freshToken()}, "client_id": {"suspendable-rs"},
			"client_secret": {rs.ClientSecret}}
	}
	post := func(path string, form url.Values) (int, map[string]any) {
		t.Helper()
		response, postErr := server.Client().PostForm(base+path, form)
		if postErr != nil {
			t.Fatal(postErr)
		}
		defer response.Body.Close()
		var decoded map[string]any
		_ = json.NewDecoder(response.Body).Decode(&decoded)
		return response.StatusCode, decoded
	}
	userInfoStatus := func() int {
		t.Helper()
		request, requestErr := http.NewRequest(http.MethodGet, base+"/userinfo", nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Authorization", "Bearer "+freshToken())
		response, doErr := server.Client().Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	discoveryStatus := func() int {
		t.Helper()
		response, getErr := server.Client().Get(server.URL + "/realms/master/.well-known/openid-configuration")
		if getErr != nil {
			t.Fatal(getErr)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	introspectionActive := func() bool {
		t.Helper()
		_, body := post("/token/introspect", clientForm())
		active, _ := body["active"].(bool)
		return active
	}

	if discoveryStatus() != http.StatusOK || userInfoStatus() != http.StatusOK || !introspectionActive() {
		t.Fatal("the Realm and Client did not work to begin with")
	}

	setRealmEnabled := func(enabled bool) {
		t.Helper()
		if _, err := data.UpdateRealm(ctx, realm.ID, store.UpdateRealmInput{
			DisplayName: realm.DisplayName, IssuerURL: realm.IssuerURL, Enabled: enabled,
			AccessTokenTTLSeconds:  realm.AccessTokenTTLSeconds,
			RefreshTokenTTLSeconds: realm.RefreshTokenTTLSeconds,
			SessionTTLSeconds:      realm.SessionTTLSeconds,
			PasswordMinLength:      realm.PasswordMinLength, MaxLoginAttempts: realm.MaxLoginAttempts,
			LockoutSeconds: realm.LockoutSeconds}); err != nil {
			t.Fatal(err)
		}
	}

	setRealmEnabled(false)
	if status := discoveryStatus(); status != http.StatusNotFound {
		t.Errorf("a suspended Realm answered discovery with %d", status)
	}
	if status := userInfoStatus(); status != http.StatusUnauthorized {
		t.Errorf("a suspended Realm served userinfo with %d", status)
	}
	if introspectionActive() {
		t.Error("a suspended Realm told a resource server its token was active")
	}
	// RFC 7009 requires 200 whether or not anything matched, so the refusal
	// here is that nothing is revoked, not the status code.
	if status, _ := post("/revoke", clientForm()); status != http.StatusOK {
		t.Errorf("revocation on a suspended Realm answered %d, want 200 per RFC 7009", status)
	}
	setRealmEnabled(true)

	if _, err := data.UpdateClient(ctx, rs.Client.ID, store.UpdateClientInput{
		Name: rs.Client.Name, RedirectURIs: rs.Client.RedirectURIs,
		PostLogoutRedirectURIs: rs.Client.PostLogoutRedirectURIs,
		GrantTypes:             rs.Client.GrantTypes, DefaultScopes: rs.Client.DefaultScopes,
		RequirePKCE: rs.Client.RequirePKCE, Enabled: false,
		AccessTokenTTLSeconds:  rs.Client.AccessTokenTTLSeconds,
		RefreshTokenTTLSeconds: rs.Client.RefreshTokenTTLSeconds}); err != nil {
		t.Fatal(err)
	}
	for path, endpoint := range map[string]string{"/token/introspect": "introspection", "/revoke": "revocation"} {
		status, body := post(path, clientForm())
		if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Errorf("a switched-off Client was accepted at %s: status=%d body=%v", endpoint, status, body)
		}
	}
	// The Realm is still running, and a token minted before the Client was
	// switched off carries its own expiry — this is about the Client's
	// credentials, not about retroactively unmaking what it was issued.
	if status := userInfoStatus(); status != http.StatusOK {
		t.Errorf("switching off one Client broke userinfo for the Realm: %d", status)
	}

	// RP-initiated logout resolves the Client two ways and only one of them
	// tested the flag, so a switched-off Client's registered post-logout
	// target was still honoured when its ID token was presented as the hint.
	hint := issueIntegrationIDTokenFor(t, data, realm, "suspendable-rs", user, session.Session.ID)
	noRedirect := server.Client()
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	logout, err := noRedirect.Get(base + "/logout?id_token_hint=" + url.QueryEscape(hint) +
		"&post_logout_redirect_uri=" + url.QueryEscape("https://rs.example.test/bye"))
	if err != nil {
		t.Fatal(err)
	}
	defer logout.Body.Close()
	if location := logout.Header.Get("Location"); strings.Contains(location, "rs.example.test/bye") {
		t.Errorf("a switched-off Client's post-logout redirect was honoured: %q", location)
	}
}

// Suspending a Realm is an operator taking a tenant offline. It stopped new
// logins and nothing else: everybody already signed in kept their console
// session, and every personal API key its people held went on working —
// the REST API and, through MCP, the directory itself. A key outlives the
// session that issued it, so "log everyone out and wait" was not a workaround
// either.
//
// The guard against suspending your own Realm is part of the same change, not
// a separate nicety: once suspension reaches sessions and keys, applying it to
// the Realm you are signed in to ends the request making it and every
// credential that could undo it, and the only way back is the database.
func TestIntegrationSuspendingARealmReachesSessionsAndKeys(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	key, err := data.CreatePersonalAPIKey(ctx, bootstrap.AdminUserID, "agent",
		[]string{"api:read", "mcp:read", "admin:read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar}
	response := postIntegrationLogin(t, browser, server.URL, "admin", "bootstrap-password-123")
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if session.CSRFToken == "" {
		t.Fatal("logging in returned no CSRF token")
	}

	get := func(client *http.Client, bearer string) int {
		t.Helper()
		request, requestErr := http.NewRequest(http.MethodGet, server.URL+"/api/admin/v1/realms", nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		result, doErr := client.Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer result.Body.Close()
		return result.StatusCode
	}
	withCookie := func() int { return get(browser, "") }
	withKey := func() int { return get(server.Client(), key.Secret) }
	mcpReadsDirectory := func() bool {
		t.Helper()
		request, requestErr := http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"resso_search_users","arguments":{"query":"ad"}}}`))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Authorization", "Bearer "+key.Secret)
		request.Header.Set("Content-Type", "application/json")
		result, doErr := server.Client().Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer result.Body.Close()
		body, _ := io.ReadAll(result.Body)
		return result.StatusCode == http.StatusOK && strings.Contains(string(body), `"username":"admin"`)
	}

	if withCookie() != http.StatusOK || withKey() != http.StatusOK || !mcpReadsDirectory() {
		t.Fatal("the Realm did not work to begin with")
	}

	// Suspending the Realm the administrator is signed in to is refused, and
	// refused before anything is written.
	policy := store.UpdateRealmInput{DisplayName: realm.DisplayName, IssuerURL: realm.IssuerURL,
		Enabled: false, AccessTokenTTLSeconds: realm.AccessTokenTTLSeconds,
		RefreshTokenTTLSeconds: realm.RefreshTokenTTLSeconds, SessionTTLSeconds: realm.SessionTTLSeconds,
		PasswordMinLength: realm.PasswordMinLength, MaxLoginAttempts: realm.MaxLoginAttempts,
		LockoutSeconds: realm.LockoutSeconds}
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut,
		server.URL+"/api/admin/v1/realms/"+realm.ID.String(), bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", session.CSRFToken)
	refusal, err := browser.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var refusalBody map[string]any
	_ = json.NewDecoder(refusal.Body).Decode(&refusalBody)
	_ = refusal.Body.Close()
	if refusal.StatusCode != http.StatusConflict || refusalBody["error"] != "realm_self_disable" {
		t.Errorf("suspending one's own Realm answered %d %v", refusal.StatusCode, refusalBody)
	}
	if reloaded, reloadErr := data.RealmByID(ctx, realm.ID); reloadErr != nil || !reloaded.Enabled {
		t.Fatalf("the refused request still wrote: enabled=%v err=%v", reloaded.Enabled, reloadErr)
	}
	if withCookie() != http.StatusOK {
		t.Error("the refusal ended the administrator's own session")
	}

	// Suspended from outside — which is how a tenant is actually taken
	// offline — everything the Realm's people hold stops.
	if _, err := data.UpdateRealm(ctx, realm.ID, policy); err != nil {
		t.Fatal(err)
	}
	if status := withCookie(); status != http.StatusUnauthorized {
		t.Errorf("a console session of a suspended Realm answered %d", status)
	}
	if status := withKey(); status != http.StatusUnauthorized {
		t.Errorf("an API key of a suspended Realm answered %d", status)
	}
	if mcpReadsDirectory() {
		t.Error("an API key of a suspended Realm read the directory through MCP")
	}
	// Logging in was already refused, and stays refused.
	fresh := postIntegrationLogin(t, &http.Client{}, server.URL, "admin", "bootstrap-password-123")
	_ = fresh.Body.Close()
	if fresh.StatusCode != http.StatusUnauthorized {
		t.Errorf("logging in to a suspended Realm answered %d", fresh.StatusCode)
	}

	// Suspension filters rather than revokes, so lifting it gives the tenant
	// back what had not expired on its own. That is the opposite of disabling
	// an account, which ends its sessions for good — suspending a tenant is a
	// state the whole Realm is in and is routinely temporary, and there is no
	// individual whose session is the reason for it. The console says as much
	// next to the switch, so it is asserted here rather than assumed.
	policy.Enabled = true
	if _, err := data.UpdateRealm(ctx, realm.ID, policy); err != nil {
		t.Fatal(err)
	}
	if status := withCookie(); status != http.StatusOK {
		t.Errorf("lifting the suspension did not restore an unexpired session: %d", status)
	}
	if status := withKey(); status != http.StatusOK {
		t.Errorf("lifting the suspension did not restore an unexpired API key: %d", status)
	}
}

// Changing a password ends the account's other sessions, and that is the whole
// reason the change is offered to somebody who believes their password is
// known. The revocation is a second step that can fail on its own after the
// password has already changed, and both endpoints dropped its error: the
// response was 204, the audit entry said SUCCESS, and nothing was logged. The
// console states the promise on the page while the sessions stayed live.
// The dashboard reports how many personal API keys in the Realm stop working
// within the week and offers a link to see them. The link used to go to the
// audit log, which records what was done to a key and cannot show which keys
// are about to expire — and the only screen listing API keys lists the
// caller's own, so an administrator could read the number and had no way to
// find out whose keys they were. A key that expires unnoticed stops an
// integration without warning.
//
// The number and the rows are asserted against each other here rather than
// against a constant, because the failure worth catching is the two drifting
// apart: they now share one predicate, and a copy of it made in either place
// would pass its own test while contradicting the other.
func TestIntegrationDashboardExpiringKeysAreTheOnesTheLinkShows(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	owner, err := data.CreateUser(ctx, bootstrap.RealmID, store.CreateUserInput{
		Username: "integrator", Password: "integrator-password-123", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// Three days out counts, thirty does not, and a key already revoked is not
	// something anyone needs to renew.
	for _, key := range []struct {
		name    string
		days    int
		revoked bool
	}{{"expiring soon", 3, false}, {"expiring later", 30, false}, {"already revoked", 3, true}} {
		expiresAt := time.Now().UTC().Add(time.Duration(key.days) * 24 * time.Hour)
		created, keyErr := data.CreatePersonalAPIKey(ctx, owner.ID, key.name, []string{"api:read"}, &expiresAt, nil)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		if key.revoked {
			if _, execErr := data.Pool.Exec(ctx,
				"UPDATE personal_api_keys SET revoked_at=now() WHERE id=$1", created.Key.ID); execErr != nil {
				t.Fatal(execErr)
			}
		}
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar}
	login := postIntegrationLogin(t, browser, server.URL, "admin", "bootstrap-password-123")
	_ = login.Body.Close()

	get := func(path string, into any) {
		t.Helper()
		response, getErr := browser.Get(server.URL + path)
		if getErr != nil {
			t.Fatal(getErr)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s answered %d", path, response.StatusCode)
		}
		if decodeErr := json.NewDecoder(response.Body).Decode(into); decodeErr != nil {
			t.Fatal(decodeErr)
		}
	}

	var dashboard struct {
		Readiness struct {
			ExpiringAPIKeys int `json:"expiring_api_keys"`
		} `json:"readiness"`
	}
	get("/api/admin/v1/dashboard?realm="+bootstrap.RealmID.String(), &dashboard)

	var listing struct {
		Items []struct {
			Name     string `json:"name"`
			Username string `json:"username"`
			Prefix   string `json:"prefix"`
			Secret   string `json:"secret"`
		} `json:"items"`
	}
	get("/api/admin/v1/realms/"+bootstrap.RealmID.String()+"/api-keys?expiring=true", &listing)

	if dashboard.Readiness.ExpiringAPIKeys != len(listing.Items) {
		t.Fatalf("the dashboard counted %d keys expiring within the week and the screen it "+
			"links to lists %d", dashboard.Readiness.ExpiringAPIKeys, len(listing.Items))
	}
	if len(listing.Items) != 1 {
		t.Fatalf("listed %d keys, want only the one expiring within the week", len(listing.Items))
	}
	if listing.Items[0].Name != "expiring soon" {
		t.Errorf("listed %q", listing.Items[0].Name)
	}
	// Whose key it is, which is the thing an administrator came for.
	if listing.Items[0].Username != "integrator" {
		t.Errorf("the listing does not say whose key it is: %q", listing.Items[0].Username)
	}
	// Metadata only. The prefix identifies a key to its owner; the secret is
	// not stored in a readable form and must not appear here.
	if listing.Items[0].Prefix == "" {
		t.Error("the listing carries no prefix, so the owner cannot tell which key it is")
	}
	if listing.Items[0].Secret != "" {
		t.Error("the listing returned a secret")
	}

	// Without the filter it is the Realm's keys, so an administrator can also
	// answer "who holds keys at all".
	var all struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	get("/api/admin/v1/realms/"+bootstrap.RealmID.String()+"/api-keys", &all)
	if len(all.Items) != 3 {
		t.Errorf("the unfiltered listing returned %d keys, want all 3", len(all.Items))
	}
}

func TestIntegrationPasswordChangeAdmitsWhenSessionsSurvive(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar}
	response := postIntegrationLogin(t, browser, server.URL, "admin", "bootstrap-password-123")
	var login struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&login); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()

	changePassword := func(current, replacement string) (int, map[string]any) {
		t.Helper()
		body := fmt.Sprintf(`{"current_password":%q,"new_password":%q}`, current, replacement)
		request, requestErr := http.NewRequest(http.MethodPut, server.URL+"/api/v1/me/password",
			strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", login.CSRFToken)
		result, doErr := browser.Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer result.Body.Close()
		var decoded map[string]any
		_ = json.NewDecoder(result.Body).Decode(&decoded)
		return result.StatusCode, decoded
	}
	lastAudit := func() (string, map[string]any) {
		t.Helper()
		page, auditErr := data.ListAudit(ctx, store.AuditFilter{EventType: "PASSWORD_CHANGE", Limit: 1})
		if auditErr != nil {
			t.Fatal(auditErr)
		}
		if len(page.Items) == 0 {
			t.Fatal("the password change was not audited at all")
		}
		var detail map[string]any
		_ = json.Unmarshal(page.Items[0].Detail, &detail)
		return page.Items[0].Result, detail
	}
	otherSession := func() bool {
		t.Helper()
		session, sessionErr := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID,
			time.Hour, "127.0.0.1", "password-change-test", "password")
		if sessionErr != nil {
			t.Fatal(sessionErr)
		}
		return session.Token != ""
	}

	// An ordinary change keeps the contract it had: 204, and SUCCESS.
	_ = otherSession()
	if status, body := changePassword("bootstrap-password-123", "first-replacement-1234"); status != http.StatusNoContent {
		t.Fatalf("an ordinary password change answered %d %v", status, body)
	}
	if result, detail := lastAudit(); result != "SUCCESS" || len(detail) != 0 {
		t.Errorf("an ordinary change audited as %s %v", result, detail)
	}

	// A live session for the next change to end. Without one there is nothing
	// for the revoking UPDATE to touch, so it would succeed by doing nothing
	// and the assertions below would read as the fix having failed. Asserted
	// rather than assumed, so a future failure here names its own cause.
	_ = otherSession()
	var liveBeforeChange int
	if err := data.Pool.QueryRow(ctx, `SELECT count(*) FROM sso_sessions
		WHERE user_id=$1 AND revoked_at IS NULL`, bootstrap.AdminUserID).Scan(&liveBeforeChange); err != nil {
		t.Fatal(err)
	}
	if liveBeforeChange < 2 {
		t.Fatalf("only %d live sessions before the change; the revocation would touch nothing "+
			"and the outcome below would say nothing about the fix", liveBeforeChange)
	}

	// Now let only the revoking UPDATE fail. Reads and last_access touches are
	// untouched, so the request still authenticates — which is what makes this
	// the shape of a real transient failure rather than a broken database.
	if _, err := data.Pool.Exec(ctx, `CREATE FUNCTION block_revocation() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'revocation blocked for the test'; END $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `CREATE TRIGGER block_revocation BEFORE UPDATE ON sso_sessions
		FOR EACH ROW WHEN (NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL)
		EXECUTE FUNCTION block_revocation()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = data.Pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS block_revocation ON sso_sessions")
	})

	status, body := changePassword("first-replacement-1234", "second-replacement-1234")
	if status != http.StatusOK {
		t.Fatalf("a change whose revocation failed answered %d %v", status, body)
	}
	if body["other_sessions_ended"] != false {
		t.Errorf("the response did not say the sessions survived: %v", body)
	}
	if message, _ := body["message"].(string); message == "" {
		t.Error("the response carried no explanation for the person reading it")
	}
	// The password really did change, so refusing would have been the wrong
	// answer — the point is that the caller is told what did not happen.
	if _, err := data.AuthenticatePassword(ctx, domain.Realm{ID: bootstrap.RealmID},
		"admin", "second-replacement-1234"); err != nil {
		t.Fatal(err)
	}
	// Both changes are audited, and reading "the last one" is only meaningful
	// if the second is there. Audit writes are best effort — the handler logs
	// and carries on if one fails — so a missing second entry makes this read
	// the first change's, which is SUCCESS with an empty detail: the exact
	// shape this test failed with twice. Blocking an audit write reproduces it
	// precisely, so the count is checked before the contents and a missing
	// record says so in its own words.
	var written int
	if err := data.Pool.QueryRow(ctx,
		"SELECT count(*) FROM audit_events WHERE event_type='PASSWORD_CHANGE'").Scan(&written); err != nil {
		t.Fatal(err)
	}
	if written != 2 {
		t.Fatalf("%d PASSWORD_CHANGE entries, want 2: the second change's record never landed, "+
			"so what follows would be reading the first change's", written)
	}
	result, detail := lastAudit()
	if result != "PARTIAL" || detail["other_sessions_ended"] != false || detail["error"] == nil {
		// This failed intermittently with "SUCCESS and an empty detail", which
		// is exactly what the first change of this test writes. Reading the
		// wrong entry was written off here on the grounds that the listing
		// broke timestamp ties with the bigserial id — but a tie was never
		// what it took. The audit response and the audit result are the same
		// variable (partialIfNot(ended)), and the response assertion above
		// passed, so the second entry could not have said SUCCESS; with both
		// entries present, the only way to read SUCCESS was for the listing to
		// return the older row, which needs the first row's timestamp to be
		// the larger one. The listing now orders by id, which no clock can
		// move. The counts below stay because they name their own cause if
		// this ever fails again.
		var liveNow, blockedByTrigger, auditEntries int
		if err := data.Pool.QueryRow(ctx, `SELECT count(*) FROM sso_sessions
			WHERE user_id=$1 AND revoked_at IS NULL`, bootstrap.AdminUserID).Scan(&liveNow); err != nil {
			t.Fatal(err)
		}
		if err := data.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_trigger
			WHERE tgname='block_revocation' AND NOT tgisinternal`).Scan(&blockedByTrigger); err != nil {
			t.Fatal(err)
		}
		// How many entries there are separates the two remaining explanations.
		// Audit writes are best effort — the handler logs and carries on if one
		// fails — so a single entry means the second change's record never
		// landed and this read the first change's, which is SUCCESS with an
		// empty detail. Two entries would mean the revocation really did
		// succeed against the trigger.
		if err := data.Pool.QueryRow(ctx,
			"SELECT count(*) FROM audit_events WHERE event_type='PASSWORD_CHANGE'").Scan(&auditEntries); err != nil {
			t.Fatal(err)
		}
		t.Errorf("audit=%s detail=%v; PASSWORD_CHANGE entries=%d (2 expected); "+
			"live sessions before the change=%d, now=%d, trigger present=%d",
			result, detail, auditEntries, liveBeforeChange, liveNow, blockedByTrigger)
	}
}

// Logging out is the one "make it stop" a person has, and both endpoints that
// offer it dropped the error from the revocation. The browser cookies are
// cleared either way, so the person sees themselves signed out — while the
// session stays live, every relying party holding a refresh token bound to it
// goes on renewing, and no back-channel logout is sent at all, because sending
// it is what the revocation does. The audit entry said SUCCESS.
func TestIntegrationLogoutRecordsASessionItCouldNotEnd(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	var told []store.RevokedSession
	data.OnSessionRevoked = func(revoked store.RevokedSession) { told = append(told, revoked) }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	signIn := func() (*http.Client, string) {
		t.Helper()
		jar, jarErr := cookiejar.New(nil)
		if jarErr != nil {
			t.Fatal(jarErr)
		}
		browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		response := postIntegrationLogin(t, browser, server.URL, "admin", "bootstrap-password-123")
		var login struct {
			CSRFToken string `json:"csrf_token"`
		}
		if err := json.NewDecoder(response.Body).Decode(&login); err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return browser, login.CSRFToken
	}
	liveSessions := func() int {
		t.Helper()
		var live int
		if err := data.Pool.QueryRow(ctx, `SELECT count(*) FROM sso_sessions
			WHERE user_id=$1 AND revoked_at IS NULL`, bootstrap.AdminUserID).Scan(&live); err != nil {
			t.Fatal(err)
		}
		return live
	}
	lastLogout := func() (string, map[string]any) {
		t.Helper()
		page, auditErr := data.ListAudit(ctx, store.AuditFilter{EventType: "LOGOUT", Limit: 1})
		if auditErr != nil {
			t.Fatal(auditErr)
		}
		if len(page.Items) == 0 {
			t.Fatal("the logout was not audited at all")
		}
		var detail map[string]any
		_ = json.Unmarshal(page.Items[0].Detail, &detail)
		return page.Items[0].Result, detail
	}

	// An ordinary console logout: the session goes, the relying parties hear
	// about it, and the entry reads SUCCESS with nothing to add.
	browser, csrf := signIn()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-CSRF-Token", csrf)
	response, err := browser.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("an ordinary logout answered %d", response.StatusCode)
	}
	if live := liveSessions(); live != 0 {
		t.Fatalf("an ordinary logout left %d sessions live", live)
	}
	if len(told) != 1 {
		t.Errorf("relying parties heard about %d revocations, want 1", len(told))
	}
	if result, detail := lastLogout(); result != "SUCCESS" || len(detail) != 0 {
		t.Errorf("an ordinary logout audited as %s %v", result, detail)
	}

	// Now block only the revoking UPDATE, so the request still authenticates.
	if _, err := data.Pool.Exec(ctx, `CREATE FUNCTION block_revocation() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'revocation blocked for the test'; END $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `CREATE TRIGGER block_revocation BEFORE UPDATE ON sso_sessions
		FOR EACH ROW WHEN (NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL)
		EXECUTE FUNCTION block_revocation()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = data.Pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS block_revocation ON sso_sessions")
	})

	// Both endpoints that end a session have to record it. The console one
	// answers the browser; the OpenID Connect one redirects the relying party,
	// which is why neither can carry the news in a body.
	for _, logout := range []struct {
		what string
		do   func(*http.Client, string) int
	}{
		{"console logout", func(browser *http.Client, csrf string) int {
			request, requestErr := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/logout", nil)
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			request.Header.Set("X-CSRF-Token", csrf)
			result, doErr := browser.Do(request)
			if doErr != nil {
				t.Fatal(doErr)
			}
			defer result.Body.Close()
			return result.StatusCode
		}},
		{"RP-initiated logout", func(browser *http.Client, _ string) int {
			result, getErr := browser.Get(server.URL + "/realms/master/protocol/openid-connect/logout")
			if getErr != nil {
				t.Fatal(getErr)
			}
			defer result.Body.Close()
			return result.StatusCode
		}},
	} {
		told = nil
		browser, csrf := signIn()
		before := liveSessions()
		if before == 0 {
			t.Fatalf("%s has no live session to end; the outcome below would say nothing "+
				"about the fix", logout.what)
		}
		status := logout.do(browser, csrf)
		if status >= 400 {
			t.Errorf("%s answered %d; the person is signed out of the browser either way "+
				"and has no remedy to offer", logout.what, status)
		}
		if liveSessions() != before {
			t.Errorf("%s revoked something despite the block", logout.what)
		}
		if len(told) != 0 {
			t.Errorf("%s told relying parties about a revocation that did not happen", logout.what)
		}
		result, detail := lastLogout()
		if result != "PARTIAL" {
			t.Errorf("%s audited as %s, want PARTIAL", logout.what, result)
		}
		if detail["session_revoked"] != false || detail["error"] == nil {
			t.Errorf("%s did not record what failed: %v", logout.what, detail)
		}
	}
}

// Naming collisions are the most ordinary mistake an administrator makes, and
// every one of them reached the console as the raw constraint violation —
// `duplicate key value violates unique constraint "clients_realm_id_client_id_key"
// (SQLSTATE 23505)`. A Realm name that did not fit its shape arrived the same
// way, from a CHECK constraint, while the console's own form states that rule
// in its helper text and only a browser was enforcing it. The policy numbers
// beside these fields already got the opposite treatment, and say so in the
// comment above realmPolicyBounds.
func TestIntegrationTakenNamesAreExplainedNotDumped(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar}
	response := postIntegrationLogin(t, browser, server.URL, "admin", "bootstrap-password-123")
	var login struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&login); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()

	post := func(path, body string) (int, map[string]any) {
		t.Helper()
		request, requestErr := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", login.CSRFToken)
		result, doErr := browser.Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer result.Body.Close()
		var decoded map[string]any
		_ = json.NewDecoder(result.Body).Decode(&decoded)
		return result.StatusCode, decoded
	}
	realmPath := "/api/admin/v1/realms/" + bootstrap.RealmID.String()

	// Something for each collision to collide with.
	if _, err := data.UpdateUser(ctx, bootstrap.AdminUserID, store.UpdateUserInput{
		DisplayName: "Administrator", Email: "admin@example.test", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if status, body := post(realmPath+"/clients",
		`{"client_id":"portal","name":"Portal","type":"public","redirect_uris":["https://portal.example.test/cb"]}`); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("creating the first client answered %d %v", status, body)
	}
	if status, body := post(realmPath+"/roles", `{"name":"auditor","description":""}`); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("creating the first role answered %d %v", status, body)
	}

	// What each message has to name is the field the constraint decided was at
	// fault, not the value the request carried — the value is the one thing the
	// handler cannot know when a table has several unique constraints.
	for _, collision := range []struct {
		what, path, body string
		wantStatus       int
		wantIn           string
	}{
		{"a taken username", realmPath + "/users",
			`{"username":"admin","password":"another-password-1234","enabled":true}`,
			http.StatusConflict, "사용자 이름"},
		{"a taken client id", realmPath + "/clients",
			`{"client_id":"portal","name":"Second","type":"public","redirect_uris":["https://second.example.test/cb"]}`,
			http.StatusConflict, "Client ID"},
		{"a taken role name", realmPath + "/roles",
			`{"name":"auditor","description":""}`,
			http.StatusConflict, "Role 이름"},
		{"a taken realm name", "/api/admin/v1/realms",
			`{"name":"master","display_name":"Second","issuer_url":"https://second.example.test/realms/master"}`,
			http.StatusConflict, "Realm 이름"},
		{"a realm name that does not fit", "/api/admin/v1/realms",
			`{"name":"My Realm","display_name":"Spaced","issuer_url":"https://spaced.example.test/realms/x"}`,
			http.StatusBadRequest, "하이픈"},
		// The same table, a different constraint: the message has to follow the
		// constraint that fired rather than the field the handler knows about.
		{"a taken email", realmPath + "/users",
			`{"username":"someone-else","email":"admin@example.test","password":"another-password-1234","enabled":true}`,
			http.StatusConflict, "이메일"},
	} {
		status, body := post(collision.path, collision.body)
		message, _ := body["message"].(string)
		if status != collision.wantStatus {
			t.Errorf("%s answered %d, want %d (%v)", collision.what, status, collision.wantStatus, body)
		}
		if !strings.Contains(message, collision.wantIn) {
			t.Errorf("%s did not say what the problem was: %q", collision.what, message)
		}
		// Whatever the message says, it must not be the database saying it.
		for _, leak := range []string{"SQLSTATE", "constraint", "violates", "pq:", "ERROR:"} {
			if strings.Contains(message, leak) {
				t.Errorf("%s leaked database text (%q): %q", collision.what, leak, message)
			}
		}
	}

	// A name that is free still works, so this bounds the refusal rather than
	// widening it.
	if status, body := post(realmPath+"/roles", `{"name":"reviewer","description":""}`); status >= 400 {
		t.Errorf("creating a role with a free name answered %d %v", status, body)
	}
}

// prompt is a space-delimited set, and it was compared as one value. So
// `prompt=login consent` — which several SDKs send — did not match "login",
// the existing session was reused, and a code came back: a relying party
// asking for a fresh proof of identity before something sensitive received one
// minted from an hour-old session, with nothing in the response to say so.
// That is the same silence max_age and id_token_hint were fixed for.
func TestIntegrationPromptIsReadAsTheListItIs(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateClient(ctx, bootstrap.RealmID, store.CreateClientInput{
		ClientID: "prompt-rp", Name: "Prompt RP", Type: "public",
		RedirectURIs: []string{"http://localhost:9999/cb"},
		GrantTypes:   []string{"authorization_code"}, DefaultScopes: []string{"openid"},
		RequirePKCE: true}); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response := postIntegrationLogin(t, browser, server.URL, "admin", "bootstrap-password-123")
	_ = response.Body.Close()

	authorize := func(prompt string) string {
		t.Helper()
		query := url.Values{
			"client_id": {"prompt-rp"}, "redirect_uri": {"http://localhost:9999/cb"},
			"response_type": {"code"}, "scope": {"openid"}, "state": {"prompt-state"},
			"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
			"code_challenge_method": {"S256"},
		}
		if prompt != "" {
			query.Set("prompt", prompt)
		}
		result, doErr := browser.Get(server.URL + "/realms/master/protocol/openid-connect/auth?" + query.Encode())
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer result.Body.Close()
		return result.Header.Get("Location")
	}

	// Without a prompt the live session is what the parameter exists to
	// override, so this has to keep working or the rest proves nothing.
	if location := authorize(""); !strings.Contains(location, "code=") {
		t.Fatalf("an ordinary authorization did not reuse the session: %q", location)
	}
	for _, asking := range []string{"login", "login consent", "consent login", "select_account login"} {
		if location := authorize(asking); !strings.Contains(location, "/login?request=") {
			t.Errorf("prompt=%q did not ask the person to authenticate again: %q", asking, location)
		}
	}
	// A value this server has no screen for is not a reason to refuse; it is
	// ignored, and the session is reused as it would be without it.
	for _, ignored := range []string{"consent", "select_account", "consent select_account"} {
		if location := authorize(ignored); !strings.Contains(location, "code=") {
			t.Errorf("prompt=%q was treated as something to act on: %q", ignored, location)
		}
	}
	// none forbids interaction and login demands it; a request asking for both
	// cannot be answered, and answering whichever is checked first is how the
	// other goes unnoticed.
	location := authorize("none login")
	if !strings.Contains(location, "error=invalid_request") {
		t.Errorf("prompt=%q was answered rather than refused: %q", "none login", location)
	}
}

// The discovery document is the contract a relying party configures itself
// from without asking anybody, so an advertisement that does not match
// behaviour is found by an integrator at the worst moment. Each claim checked
// here is exercised in both directions: what the document offers has to work,
// and something it does not offer has to be refused rather than quietly
// treated as something else.
func TestIntegrationDiscoveryAdvertisesWhatTheEndpointsDo(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	created, err := data.CreateClient(ctx, bootstrap.RealmID, store.CreateClientInput{
		ClientID: "discovery-rp", Name: "Discovery RP", Type: "confidential",
		RedirectURIs:  []string{"http://localhost:9999/cb"},
		GrantTypes:    []string{"authorization_code", "refresh_token", "client_credentials"},
		DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	response, err := client.Get(server.URL + "/realms/master/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	offers := func(field, value string) bool {
		for _, entry := range document[field].([]any) {
			if entry == value {
				return true
			}
		}
		return false
	}

	// The authorization endpoint, asked with one parameter varied at a time.
	authorize := func(overrides url.Values) string {
		t.Helper()
		query := url.Values{
			"client_id": {"discovery-rp"}, "redirect_uri": {"http://localhost:9999/cb"},
			"response_type": {"code"}, "scope": {"openid"}, "state": {"discovery"},
			"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
			"code_challenge_method": {"S256"},
		}
		for key, values := range overrides {
			query[key] = values
		}
		result, doErr := client.Get(server.URL + "/realms/master/protocol/openid-connect/auth?" + query.Encode())
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer result.Body.Close()
		return result.Header.Get("Location")
	}

	if !offers("response_types_supported", "code") || !offers("response_modes_supported", "query") {
		t.Fatal("the document no longer offers the code flow this test is written against")
	}
	if location := authorize(nil); strings.Contains(location, "error=") {
		t.Errorf("response_type=code is advertised and was refused: %q", location)
	}
	for field, refusal := range map[string]struct {
		params    url.Values
		wantError string
	}{
		"an unadvertised response_type": {url.Values{"response_type": {"token"}}, "unsupported_response_type"},
		"an unadvertised response_mode": {url.Values{"response_mode": {"fragment"}}, "unsupported_response_mode"},
		// plain PKCE is the one that matters: it puts the verifier in the
		// authorization request, so anyone who sees the request can redeem
		// the code. The document offers only S256.
		"an unadvertised code_challenge_method": {url.Values{"code_challenge_method": {"plain"},
			"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}}, "invalid_request"},
		// The document says it supports neither, and says so rather than
		// ignoring them, which would use the unsigned query string instead.
		"the request parameter":     {url.Values{"request": {"eyJhbGciOiJub25lIn0."}}, "request_not_supported"},
		"the request_uri parameter": {url.Values{"request_uri": {"https://rp.example.test/req"}}, "request_uri_not_supported"},
	} {
		if location := authorize(refusal.params); !strings.Contains(location, "error="+refusal.wantError) {
			t.Errorf("%s was answered with %q, want %s", field, location, refusal.wantError)
		}
	}
	if offers("code_challenge_methods_supported", "plain") {
		t.Error("the document offers plain PKCE, which the authorization endpoint refuses")
	}

	// The token endpoint, for a grant the document does not list.
	secret, err := data.RotateClientSecret(ctx, created.Client.ID)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"password"}, "client_id": {"discovery-rp"},
		"client_secret": {secret}, "username": {"admin"}, "password": {"bootstrap-password-123"}}
	result, err := client.PostForm(server.URL+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.NewDecoder(result.Body).Decode(&body)
	_ = result.Body.Close()
	if offers("grant_types_supported", "password") {
		t.Error("the document offers the password grant")
	}
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("an unadvertised grant answered %v, want unsupported_grant_type", body)
	}
}

// RFC 7009 answers 200 for a token the server does not recognise, and every
// failure here was reported as exactly that. The caller got 200, the trail
// recorded SUCCESS with revoked=none, and introspection went on answering
// active=true for the token the caller had just been told was gone. Revocation
// is what somebody reaches for when a token has leaked, so being told it worked
// when it did not is the one outcome that matters. §2.2.1 covers this case:
// 503, and the client is to assume the token still exists.
func TestIntegrationRevocationThatCannotBePerformedIsNotReportedAsDone(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	client, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "revoke-unavailable", Name: "Revoker", Type: "confidential",
		RedirectURIs: []string{"https://rs.example.test/cb"},
		GrantTypes:   []string{"authorization_code"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(ctx, realm.ID, store.CreateUserInput{
		Username: "leaked", Password: "leaked-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, user.ID, time.Hour, "127.0.0.1", "revoke-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	service := ressooidc.Service{Store: data}
	tokens, err := service.IssueUserTokens(ctx, realm, client.Client, user, session.Session.ID,
		[]string{"openid"}, "", false)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	// The record of revoked access tokens cannot be written or read.
	if _, err := data.Pool.Exec(ctx, "ALTER TABLE revoked_access_tokens RENAME COLUMN jti TO jti_moved"); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if _, err := data.Pool.Exec(ctx, "ALTER TABLE revoked_access_tokens RENAME COLUMN jti_moved TO jti"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(restore)

	form := url.Values{"token": {tokens.AccessToken}, "client_id": {"revoke-unavailable"},
		"client_secret": {client.ClientSecret}}
	response, err := server.Client().PostForm(server.URL+"/realms/master/protocol/openid-connect/revoke", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("a revocation that could not be performed answered %d, want %d so the caller knows the token is still live",
			response.StatusCode, http.StatusServiceUnavailable)
	}

	page, err := data.ListAudit(ctx, store.AuditFilter{EventType: "TOKEN_REVOKED", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(page.Items))
	}
	if page.Items[0].Result != "FAILURE" {
		t.Errorf("the trail records result=%s for a revocation that did not happen", page.Items[0].Result)
	}
	var decoded map[string]any
	if err := json.Unmarshal(page.Items[0].Detail, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["error"] == nil {
		t.Errorf("the trail gives no reason: %v", decoded)
	}

	// And the token really is still live, which is why the answer matters.
	restore()
	introspection := url.Values{"token": {tokens.AccessToken}, "client_id": {"revoke-unavailable"},
		"client_secret": {client.ClientSecret}}
	introspected, err := server.Client().PostForm(
		server.URL+"/realms/master/protocol/openid-connect/token/introspect", introspection)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = introspected.Body.Close() }()
	var report map[string]any
	if err := json.NewDecoder(introspected.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if active, _ := report["active"].(bool); !active {
		t.Errorf("the token was not actually left live, so this test is not measuring what it claims")
	}
}

// The login succeeded, the session exists and its cookies are in the browser —
// only the authorization code failed. Returning at that point recorded nothing:
// no entry in the trail saying anyone logged in, and no movement on the counter
// operators are told to watch, so a database that had stopped taking writes
// looked like a quiet minute while sessions were being handed out.
func TestIntegrationALoginThatCannotMintItsCodeIsStillRecorded(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	if _, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123"); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	client, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "code-failure", Name: "Code Failure", Type: "public",
		RedirectURIs: []string{"https://rp.example.test/cb"},
		GrantTypes:   []string{"authorization_code"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(ctx, realm.ID, store.CreateUserInput{
		Username: "coder", Password: "coder-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	requestToken, err := data.CreateAuthorizationRequest(ctx, store.AuthorizationRequest{
		RealmID: realm.ID, ClientID: client.Client.ID, RedirectURI: "https://rp.example.test/cb",
		ResponseType: "code", Scope: []string{"openid"}, State: "xyz"})
	if err != nil {
		t.Fatal(err)
	}
	// The code cannot be written.
	if _, err := data.Pool.Exec(ctx,
		"ALTER TABLE authorization_codes RENAME COLUMN code_hash TO code_hash_moved"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = data.Pool.Exec(context.Background(),
			"ALTER TABLE authorization_codes RENAME COLUMN code_hash_moved TO code_hash")
	})

	metrics := observability.NewRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, metrics).Handler())
	t.Cleanup(server.Close)

	body := fmt.Sprintf(`{"realm":"master","username":"coder","password":"coder-password-1234","request":%q}`, requestToken)
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/login", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusInternalServerError)
	}

	// The session really was handed out — which is why the silence mattered.
	var sessions int
	if err := data.Pool.QueryRow(ctx,
		"SELECT count(*) FROM sso_sessions WHERE user_id=$1 AND revoked_at IS NULL", user.ID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("live sessions = %d, want the one the login created", sessions)
	}

	page, err := data.ListAudit(ctx, store.AuditFilter{EventType: "LOGIN_SUCCESS", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("a live session was handed out with %d entries in the trail", len(page.Items))
	}
	if page.Items[0].Result != "PARTIAL" {
		t.Errorf("the trail records result=%s; the login happened but the code did not",
			page.Items[0].Result)
	}
	var detail map[string]any
	if err := json.Unmarshal(page.Items[0].Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail["error"] == nil {
		t.Errorf("the trail gives no reason: %v", detail)
	}

	var exported strings.Builder
	metrics.WritePrometheus(&exported)
	if !strings.Contains(exported.String(), `resso_login_attempts_total{result="error"} 1`) {
		t.Errorf("the failure left the counter flat, which is what a quiet minute looks like:\n%s",
			exported.String())
	}
}

// A token the service judged dead and a token it could not judge both answer
// 200 with active=false, which is the right direction — a resource server
// handed a 5xx might fail open. But the two were the same call in every signal
// the service publishes: the request counter records a healthy introspection,
// the access line says status=200, and the store error was dropped where it
// happened. An outage confined to this endpoint looked exactly like every token
// being dead, with every resource server refusing every request and nothing
// here to say why.
func TestIntegrationAnIntrospectionItCannotJudgeIsDistinguishable(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	resourceServer, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "unjudged-rs", Name: "RS", Type: "confidential",
		RedirectURIs: []string{"https://rs.example.test/cb"},
		GrantTypes:   []string{"authorization_code"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(ctx, realm.ID, store.CreateUserInput{
		Username: "unjudged", Password: "unjudged-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, user.ID, time.Hour, "127.0.0.1", "introspection", "password")
	if err != nil {
		t.Fatal(err)
	}
	service := ressooidc.Service{Store: data}
	tokens, err := service.IssueUserTokens(ctx, realm, resourceServer.Client, user, session.Session.ID,
		[]string{"openid"}, "", false)
	if err != nil {
		t.Fatal(err)
	}

	metrics := observability.NewRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, metrics).Handler())
	t.Cleanup(server.Close)
	introspect := func() (int, bool) {
		t.Helper()
		form := url.Values{"token": {tokens.AccessToken}, "client_id": {"unjudged-rs"},
			"client_secret": {resourceServer.ClientSecret}}
		response, postErr := server.Client().PostForm(
			server.URL+"/realms/master/protocol/openid-connect/token/introspect", form)
		if postErr != nil {
			t.Fatal(postErr)
		}
		defer func() { _ = response.Body.Close() }()
		var decoded map[string]any
		if decodeErr := json.NewDecoder(response.Body).Decode(&decoded); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		active, _ := decoded["active"].(bool)
		return response.StatusCode, active
	}

	if status, active := introspect(); status != http.StatusOK || !active {
		t.Fatalf("a healthy introspection answered %d active=%v", status, active)
	}
	var healthy strings.Builder
	metrics.WritePrometheus(&healthy)
	if strings.Contains(healthy.String(), "resso_introspection_errors_total{") {
		t.Errorf("a healthy introspection was counted as unjudged:\n%s", healthy.String())
	}

	// Only the session lookup breaks; the rest of the service is fine.
	if _, err := data.Pool.Exec(ctx,
		"ALTER TABLE sso_sessions RENAME COLUMN created_at TO created_at_moved"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = data.Pool.Exec(context.Background(),
			"ALTER TABLE sso_sessions RENAME COLUMN created_at_moved TO created_at")
	})

	// The answer deliberately does not change: refusing is the safe direction.
	if status, active := introspect(); status != http.StatusOK || active {
		t.Errorf("an unjudgeable token answered %d active=%v, want 200 and inactive", status, active)
	}
	var broken strings.Builder
	metrics.WritePrometheus(&broken)
	if !strings.Contains(broken.String(), `resso_introspection_errors_total{stage="session"} 1`) {
		t.Errorf("an outage confined to introspection left no signal:\n%s", broken.String())
	}
}

// Revoking an access token had no test that it works, only one that a failure
// to record it is reported. The revocation handler decides between three
// outcomes and this is the branch none of them covered, so the whole path from
// "the client asks" to "the resource server is told no" could have broken
// without a single test noticing.
func TestIntegrationRevokingAnAccessTokenStopsItBeingAccepted(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	client, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "access-revoker", Name: "Revoker", Type: "confidential",
		RedirectURIs: []string{"https://rp.example.test/cb"},
		GrantTypes:   []string{"authorization_code"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(ctx, realm.ID, store.CreateUserInput{
		Username: "holder", Password: "holder-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, user.ID, time.Hour, "127.0.0.1", "revoke-access", "password")
	if err != nil {
		t.Fatal(err)
	}
	service := ressooidc.Service{Store: data}
	tokens, err := service.IssueUserTokens(ctx, realm, client.Client, user, session.Session.ID,
		[]string{"openid"}, "", false)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	introspect := func() bool {
		t.Helper()
		form := url.Values{"token": {tokens.AccessToken}, "client_id": {"access-revoker"},
			"client_secret": {client.ClientSecret}}
		response, postErr := server.Client().PostForm(
			server.URL+"/realms/master/protocol/openid-connect/token/introspect", form)
		if postErr != nil {
			t.Fatal(postErr)
		}
		defer func() { _ = response.Body.Close() }()
		var decoded map[string]any
		if decodeErr := json.NewDecoder(response.Body).Decode(&decoded); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		active, _ := decoded["active"].(bool)
		return active
	}
	userInfoStatus := func() int {
		t.Helper()
		request, requestErr := http.NewRequest(http.MethodGet,
			server.URL+"/realms/master/protocol/openid-connect/userinfo", nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		response, doErr := server.Client().Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		_ = response.Body.Close()
		return response.StatusCode
	}

	if !introspect() {
		t.Fatal("a freshly issued access token was already inactive")
	}
	if status := userInfoStatus(); status != http.StatusOK {
		t.Fatalf("userinfo refused a freshly issued token: %d", status)
	}

	form := url.Values{"token": {tokens.AccessToken}, "client_id": {"access-revoker"},
		"client_secret": {client.ClientSecret}}
	response, err := server.Client().PostForm(server.URL+"/realms/master/protocol/openid-connect/revoke", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("revoke answered %d, want 200", response.StatusCode)
	}

	if introspect() {
		t.Error("introspection still reports a revoked access token as active")
	}
	if status := userInfoStatus(); status == http.StatusOK {
		t.Error("userinfo still accepts a revoked access token")
	}

	// The trail has to say which kind of token went, and name it.
	page, err := data.ListAudit(ctx, store.AuditFilter{EventType: "TOKEN_REVOKED", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(page.Items))
	}
	if page.Items[0].Result != "SUCCESS" {
		t.Errorf("a revocation that worked recorded result=%s", page.Items[0].Result)
	}
	var detail map[string]any
	if err := json.Unmarshal(page.Items[0].Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail["revoked"] != "access_token" {
		t.Errorf("the trail records revoked=%v, want access_token", detail["revoked"])
	}
	if detail["jti"] == nil {
		t.Error("the trail does not name the token it revoked")
	}
}

// An administrator forcing a session out is the one record saying it happened.
// The handler called the store directly and answered its error, so once the
// store began reporting refresh tokens it could not revoke, a session that
// really did end came back as a failure with no entry in the trail at all.
// Which half failed also decides what the entry may say: the session is gone,
// and calling it unrevoked would send whoever reads it to end a session that
// no longer exists while the live refresh tokens go unmentioned.
func TestIntegrationForcingASessionOutIsRecordedEvenWhenHalfOfItFails(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	client, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "forced-out", Name: "RP", Type: "confidential",
		RedirectURIs: []string{"https://rp.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	victim, err := data.CreateUser(ctx, realm.ID, store.CreateUserInput{
		Username: "forced", Password: "forced-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, victim.ID, time.Hour, "127.0.0.1", "forced", "password")
	if err != nil {
		t.Fatal(err)
	}
	sessionID := session.Session.ID
	if _, err := data.CreateRefreshToken(ctx, store.RefreshToken{RealmID: realm.ID, ClientID: client.Client.ID,
		UserID: &victim.ID, SessionID: &sessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	adminSession, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "admin", "password")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := data.Pool.Exec(ctx,
		"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at TO revoked_at_moved"); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if _, err := data.Pool.Exec(context.Background(),
			"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at_moved TO revoked_at"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(restore)

	request, err := http.NewRequest(http.MethodDelete,
		server.URL+"/api/admin/v1/realms/"+realm.ID.String()+"/sessions/"+sessionID.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(&http.Cookie{Name: "resso_session", Value: adminSession.Token})
	request.Header.Set("X-CSRF-Token", adminSession.CSRFToken)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var adminBody map[string]any
	_ = json.NewDecoder(response.Body).Decode(&adminBody)
	_ = response.Body.Close()
	restore()

	if response.StatusCode != http.StatusOK {
		t.Errorf("a session that really ended answered %d, want 200 carrying what did not happen",
			response.StatusCode)
	}
	if adminBody["session_ended"] != true || adminBody["refresh_tokens_revoked"] != false {
		t.Errorf("the response does not describe this request: %v", adminBody)
	}
	// The session did end, which is why losing the record matters.
	var revoked bool
	if err := data.Pool.QueryRow(ctx,
		"SELECT revoked_at IS NOT NULL FROM sso_sessions WHERE id=$1", sessionID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("the session was not revoked, so this is not measuring what it claims")
	}
	page, err := data.ListAudit(ctx, store.AuditFilter{EventType: "ADMIN_FORCE_LOGOUT", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("a forced sign-out left %d entries in the trail", len(page.Items))
	}
	if page.Items[0].Result != "PARTIAL" {
		t.Errorf("the trail records result=%s for a sign-out that half worked", page.Items[0].Result)
	}
	var detail map[string]any
	if err := json.Unmarshal(page.Items[0].Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail["session_revoked"] != true {
		t.Errorf("the trail says the session was not revoked, and it was: %v", detail)
	}
	if detail["refresh_tokens_revoked"] != false {
		t.Errorf("the trail does not record the refresh tokens that survived: %v", detail)
	}
}

// Ending one's own session has the same two halves, and the same handler shape
// that treated the second failing as the whole thing failing: an error for a
// session that had ended, nothing in the trail, and — when it is this browser's
// own session — the cookies left in place for a session that no longer works,
// so the next request fails in a way nobody can read.
func TestIntegrationEndingMyOwnSessionSurvivesRefreshTokensItCannotRevoke(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	client, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "own-session", Name: "RP", Type: "confidential",
		RedirectURIs: []string{"https://rp.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	mine, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "own", "password")
	if err != nil {
		t.Fatal(err)
	}
	sessionID := mine.Session.ID
	userID := bootstrap.AdminUserID
	if _, err := data.CreateRefreshToken(ctx, store.RefreshToken{RealmID: realm.ID, ClientID: client.Client.ID,
		UserID: &userID, SessionID: &sessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	if _, err := data.Pool.Exec(ctx,
		"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at TO revoked_at_moved"); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if _, err := data.Pool.Exec(context.Background(),
			"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at_moved TO revoked_at"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(restore)

	request, err := http.NewRequest(http.MethodDelete,
		server.URL+"/api/v1/me/sessions/"+sessionID.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(&http.Cookie{Name: "resso_session", Value: mine.Token})
	request.Header.Set("X-CSRF-Token", mine.CSRFToken)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.NewDecoder(response.Body).Decode(&body)
	_ = response.Body.Close()
	restore()

	if response.StatusCode != http.StatusOK {
		t.Errorf("ending a session that really ended answered %d, want 200 carrying what did not happen",
			response.StatusCode)
	}
	if body["session_ended"] != true || body["refresh_tokens_revoked"] != false {
		t.Errorf("the response does not describe this request: %v", body)
	}
	// It was this browser's own session, so its cookies have to go with it.
	cleared := false
	for _, cookie := range response.Cookies() {
		if cookie.Name == "resso_session" && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the browser kept a cookie for a session that no longer works")
	}
	var revoked bool
	if err := data.Pool.QueryRow(ctx,
		"SELECT revoked_at IS NOT NULL FROM sso_sessions WHERE id=$1", sessionID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("the session was not revoked, so this is not measuring what it claims")
	}
	page, err := data.ListAudit(ctx, store.AuditFilter{EventType: "SESSION_REVOKE", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("ending a session left %d entries in the trail", len(page.Items))
	}
	if page.Items[0].Result != "PARTIAL" {
		t.Errorf("the trail records result=%s for a sign-out that half worked", page.Items[0].Result)
	}
}

// A password change falls short in two different ways and they need different
// sentences. Saying "the other sessions could not be ended" when they were
// ended, and only their refresh tokens survived, sends somebody who changed
// their password because they believe it is known to go looking for sessions
// to close — and find none, while what actually survived goes unmentioned.
func TestIntegrationAPasswordChangeSaysWhichHalfFellShort(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	client, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "password-rp", Name: "RP", Type: "confidential",
		RedirectURIs: []string{"https://rp.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(ctx, realm.ID, store.CreateUserInput{
		Username: "changer", Password: "changer-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	here, err := data.CreateSession(ctx, realm.ID, user.ID, time.Hour, "127.0.0.1", "here", "password")
	if err != nil {
		t.Fatal(err)
	}
	elsewhere, err := data.CreateSession(ctx, realm.ID, user.ID, time.Hour, "127.0.0.1", "elsewhere", "password")
	if err != nil {
		t.Fatal(err)
	}
	otherID := elsewhere.Session.ID
	if _, err := data.CreateRefreshToken(ctx, store.RefreshToken{RealmID: realm.ID, ClientID: client.Client.ID,
		UserID: &user.ID, SessionID: &otherID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	if _, err := data.Pool.Exec(ctx,
		"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at TO revoked_at_moved"); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if _, err := data.Pool.Exec(context.Background(),
			"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at_moved TO revoked_at"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(restore)

	body := `{"current_password":"changer-password-1234","new_password":"changer-password-5678"}`
	request, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/me/password", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: "resso_session", Value: here.Token})
	request.Header.Set("X-CSRF-Token", here.CSRFToken)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	_ = json.NewDecoder(response.Body).Decode(&decoded)
	_ = response.Body.Close()
	restore()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 carrying what fell short", response.StatusCode)
	}
	// The other session really was ended; only its refresh tokens survived.
	var revoked bool
	if err := data.Pool.QueryRow(ctx,
		"SELECT revoked_at IS NOT NULL FROM sso_sessions WHERE id=$1", otherID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("the other session was not ended, so this is not measuring what it claims")
	}
	if decoded["other_sessions_ended"] != true {
		t.Errorf("the response says the other sessions were not ended, and they were: %v", decoded)
	}
	if decoded["refresh_tokens_revoked"] != false {
		t.Errorf("the response does not report the refresh tokens that survived: %v", decoded)
	}
	message, _ := decoded["message"].(string)
	if strings.Contains(message, "세션을 종료하지 못했습니다") {
		t.Errorf("the message sends the reader after sessions that are already gone: %q", message)
	}
	if !strings.Contains(message, "Refresh Token") {
		t.Errorf("the message does not name what survived: %q", message)
	}
}

// The two provider changes that sign people out report the change as done when
// only the sign-out falls short, and the response has to carry that — the audit
// entry alone is not somewhere the administrator making the change is looking.
func TestIntegrationAProviderChangeCarriesAnUnfinishedSignOut(t *testing.T) {
	// No directory is needed: what is under test is what happens after the
	// provider changes, and the accounts it owns are what drive that.
	const directory = "ldap://127.0.0.1:1"
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	credential := "adminpassword"
	input := store.LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: directory,
		BindDN: "cn=admin,dc=example,dc=test", BindCredential: &credential,
		UsersDN: "ou=people,dc=example,dc=test", UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "KEEP",
		EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn",
		ImportEnabled: true, Enabled: true,
	}
	provider, err := data.CreateLDAPFederation(ctx, realm.ID, input)
	if err != nil {
		t.Fatal(err)
	}

	// An account the provider owns, with a session and a refresh token: this is
	// what the sign-out has to reach.
	owned, err := data.CreateUser(ctx, realm.ID, store.CreateUserInput{
		Username: "owned", Password: "owned-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, "UPDATE users SET federation_id=$2 WHERE id=$1",
		owned.ID, provider.ID); err != nil {
		t.Fatal(err)
	}
	client, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "federation-rp", Name: "RP", Type: "confidential",
		RedirectURIs: []string{"https://rp.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	ownedSession, err := data.CreateSession(ctx, realm.ID, owned.ID, time.Hour, "127.0.0.1", "owned", "password")
	if err != nil {
		t.Fatal(err)
	}
	ownedSessionID := ownedSession.Session.ID
	if _, err := data.CreateRefreshToken(ctx, store.RefreshToken{RealmID: realm.ID, ClientID: client.Client.ID,
		UserID: &owned.ID, SessionID: &ownedSessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	admin, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "admin", "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx,
		"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at TO revoked_at_moved"); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if _, err := data.Pool.Exec(context.Background(),
			"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at_moved TO revoked_at"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(restore)

	call := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		request, requestErr := http.NewRequest(method, server.URL+path, reader)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: "resso_session", Value: admin.Token})
		request.Header.Set("X-CSRF-Token", admin.CSRFToken)
		response, doErr := server.Client().Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer func() { _ = response.Body.Close() }()
		decoded := map[string]any{}
		_ = json.NewDecoder(response.Body).Decode(&decoded)
		return response.StatusCode, decoded
	}

	base := "/api/admin/v1/realms/" + realm.ID.String() + "/user-federations/" + provider.ID.String()
	disable := `{"name":"corp","vendor":"OTHER","connection_url":"` + directory + `",` +
		`"bind_dn":"cn=admin,dc=example,dc=test","bind_credential":"adminpassword",` +
		`"users_dn":"ou=people,dc=example,dc=test","username_ldap_attribute":"uid","rdn_ldap_attribute":"uid",` +
		`"uuid_ldap_attribute":"entryUUID","user_object_classes":["inetOrgPerson"],"search_scope":"SUBTREE",` +
		`"batch_size":100,"edit_mode":"READ_ONLY","missing_user_action":"KEEP","email_ldap_attribute":"mail",` +
		`"display_name_ldap_attribute":"cn","import_enabled":true,"enabled":false}`
	status, body := call(http.MethodPut, base, disable)
	if status != http.StatusOK {
		t.Fatalf("disabling answered %d, want the change reported as done", status)
	}
	if body["enabled"] != false {
		t.Errorf("the response does not carry the provider it changed: %v", body["enabled"])
	}
	if body["message"] == nil || body["users_signed_out"] != false {
		t.Errorf("the response does not mention the sign-out that did not finish: %v", body)
	}

	status, body = call(http.MethodDelete, base+"?unlink_users=true", "")
	if status != http.StatusOK {
		t.Fatalf("deleting answered %d, want the deletion reported as done", status)
	}
	if body["deleted"] != true || body["message"] == nil {
		t.Errorf("the delete response does not say what happened: %v", body)
	}
	restore()
	if _, err := data.LDAPFederationByID(ctx, provider.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the provider survived a delete reported as done: %v", err)
	}
}

// The discovery document and the JWKS are the two things every relying party
// reads before it can do anything: one to configure itself, the other to
// verify what it is given. Neither had its content checked anywhere — only
// that discovery answers 200, and that it answers 404 for a suspended Realm.
//
// So the checks that matter are the ones tying the documents to reality: that
// the endpoints they advertise are served rather than merely spelled, that the
// signing algorithm they promise is the one tokens actually carry, and that the
// key set holds the fields a relying party needs to verify with.
func TestIntegrationDiscoveryAndJWKSDescribeWhatIsActuallyServed(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	response, err := server.Client().Get(server.URL + "/realms/master/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()

	// OpenID Connect Discovery 1.0 section 3 marks these REQUIRED. A relying
	// party missing any of them cannot configure itself at all.
	for _, required := range []string{
		"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
		"response_types_supported", "subject_types_supported",
		"id_token_signing_alg_values_supported",
	} {
		if document[required] == nil {
			t.Errorf("the discovery document omits %q, which the specification requires", required)
		}
	}

	// Every advertised endpoint has to be served. Spelling one wrong is
	// invisible here and fatal at the relying party.
	//
	// The router is asked rather than probed over HTTP. A wrong path under
	// this subtree answers 405, not 404, because the CORS preflight is
	// registered as a wildcard and matches the pattern while the method does
	// not — and 405 is also the honest answer for asking the token endpoint
	// for a GET. Probing could not tell those apart, so it passed for a
	// deliberately mis-spelled endpoint when this was written that way.
	routed := map[string]bool{}
	router, ok := New(data, logger, nil, nil).Handler().(*chi.Mux)
	if !ok {
		t.Fatal("handler is not a chi router")
	}
	if walkErr := chi.Walk(router, func(_, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routed[strings.Replace(strings.TrimSuffix(route, "/"), "{realm}", "master", 1)] = true
		return nil
	}); walkErr != nil {
		t.Fatal(walkErr)
	}
	for _, advertised := range []string{
		"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri",
		"end_session_endpoint", "introspection_endpoint", "revocation_endpoint",
	} {
		raw, _ := document[advertised].(string)
		parsed, parseErr := url.Parse(raw)
		if raw == "" || parseErr != nil {
			t.Errorf("%s is not a URL: %v", advertised, document[advertised])
			continue
		}
		if !routed[parsed.Path] {
			t.Errorf("%s advertises %s, which the router does not serve", advertised, parsed.Path)
		}
	}

	jwksURI, _ := document["jwks_uri"].(string)
	parsed, err := url.Parse(jwksURI)
	if err != nil {
		t.Fatal(err)
	}
	keysResponse, err := server.Client().Get(server.URL + parsed.Path)
	if err != nil {
		t.Fatal(err)
	}
	var keySet struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(keysResponse.Body).Decode(&keySet); err != nil {
		t.Fatal(err)
	}
	_ = keysResponse.Body.Close()
	if len(keySet.Keys) == 0 {
		t.Fatal("the key set is empty, so nothing this Realm issues can be verified")
	}
	for _, key := range keySet.Keys {
		for _, field := range []string{"kty", "kid", "use", "alg", "n", "e"} {
			if key[field] == nil || key[field] == "" {
				t.Errorf("a published key omits %q: %v", field, key)
			}
		}
		if key["kty"] != "RSA" || key["use"] != "sig" {
			t.Errorf("a published key is not an RSA signing key: %v", key)
		}
		// A private component reaching the JWKS would publish the Realm's
		// signing key to anyone who asks.
		for _, secret := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, present := key[secret]; present {
				t.Fatalf("the published key set carries the private component %q", secret)
			}
		}
	}

	// The algorithm the document promises has to be the one tokens carry.
	algorithms, _ := document["id_token_signing_alg_values_supported"].([]any)
	if len(algorithms) != 1 || algorithms[0] != "RS256" {
		t.Fatalf("advertised signing algorithms = %v", algorithms)
	}
	if key := keySet.Keys[0]; key["alg"] != "RS256" {
		t.Errorf("the published key advertises alg=%v while the document promises RS256", key["alg"])
	}
}

// Readiness decides whether an instance takes traffic: the rollout procedure
// in docs/operations.md replaces one instance and checks this endpoint before
// going on. Nothing tested it. An instance that answers ready while its
// database is unreachable is put into rotation and fails every request it is
// then given, and the check that was supposed to catch that is the one saying
// it is fine.
func TestIntegrationReadinessFollowsTheDatabase(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	statusOf := func(path string) int {
		t.Helper()
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return response.StatusCode
	}

	if status := statusOf("/health/ready"); status != http.StatusOK {
		t.Fatalf("a healthy instance answered %d", status)
	}
	if status := statusOf("/health/live"); status != http.StatusOK {
		t.Fatalf("liveness answered %d", status)
	}

	// The database goes away. Liveness is about the process and must not
	// change; readiness is about being able to serve and must.
	data.Pool.Close()
	if status := statusOf("/health/ready"); status != http.StatusServiceUnavailable {
		t.Errorf("readiness answered %d with no database, so a broken instance would be given traffic", status)
	}
	if status := statusOf("/health/live"); status != http.StatusOK {
		t.Errorf("liveness answered %d, which would have the process restarted rather than taken out of rotation", status)
	}
}

// An MCP client that is refused reads the challenge header to find out how to
// authenticate: it names a metadata document and the scope to ask for. Three
// things therefore have to agree — the path in the header has to be served,
// the document has to name an authorization server that exists, and the scope
// in the header has to be the one the endpoint actually requires. Nothing
// checked any of them, and a client cannot recover from a pointer that does
// not resolve; it simply cannot connect.
func TestIntegrationMCPChallengePointsSomewhereThatWorks(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	refused, err := server.Client().Post(server.URL+"/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = refused.Body.Close()
	if refused.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated MCP call answered %d", refused.StatusCode)
	}
	challenge := refused.Header.Get("WWW-Authenticate")
	if challenge == "" {
		t.Fatal("the refusal carries no challenge, so a client is told nothing about how to proceed")
	}
	metadata := regexp.MustCompile(`resource_metadata="([^"]+)"`).FindStringSubmatch(challenge)
	scope := regexp.MustCompile(`scope="([^"]+)"`).FindStringSubmatch(challenge)
	if metadata == nil || scope == nil {
		t.Fatalf("the challenge names no metadata document or scope: %q", challenge)
	}

	document, err := server.Client().Get(server.URL + metadata[1])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = document.Body.Close() }()
	if document.StatusCode != http.StatusOK {
		t.Fatalf("the challenge points at %s, which answers %d", metadata[1], document.StatusCode)
	}
	var described map[string]any
	if err := json.NewDecoder(document.Body).Decode(&described); err != nil {
		t.Fatal(err)
	}
	servers, _ := described["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != realm.IssuerURL {
		t.Errorf("authorization_servers = %v, want the master Realm's issuer %q", servers, realm.IssuerURL)
	}
	// The scope the client is told to ask for has to be one the document says
	// this resource accepts, or it asks for something it can never use.
	advertised, _ := described["scopes_supported"].([]any)
	found := false
	for _, value := range advertised {
		if value == scope[1] {
			found = true
		}
	}
	if !found {
		t.Errorf("the challenge asks for scope %q, which the metadata does not list: %v", scope[1], advertised)
	}
	// And that scope is the one the endpoint enforces: a key holding every
	// other advertised scope but not this one is still refused. The scope is
	// taken from the challenge rather than written here, or the check passes
	// whatever the challenge says — which is how the first version of it read.
	withheld := make([]string, 0, len(advertised))
	for _, value := range advertised {
		if name, ok := value.(string); ok && name != scope[1] {
			withheld = append(withheld, name)
		}
	}
	if len(withheld) == 0 {
		t.Fatal("the metadata advertises only the challenged scope, so this cannot be checked")
	}
	principal, err := data.CreatePersonalAPIKey(ctx, bootstrap.AdminUserID, "wrong-scope",
		withheld, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+principal.Secret)
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("a key without %s was accepted (%d), so the challenge asks for a scope that is not required",
			scope[1], response.StatusCode)
	}
}

// Every federation route takes a Realm and a provider in its path, and the two
// have to belong together. The middleware only checks that the caller may act
// on the Realm named, so the shape that matters is a coherent Realm paired with
// somebody else's provider — which is what an administrator of one tenant would
// send to reach another's directory configuration, bind DN and sync controls.
//
// Six routes carry that pair. Reading each one and finding a check is not the
// same as the check working, and a route added later is exactly the one that
// would be missed.
func TestIntegrationFederationRoutesRefuseAProviderFromAnotherRealm(t *testing.T) {
	directory := "ldap://127.0.0.1:1"
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	mine, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := data.CreateRealm(ctx, store.CreateRealmInput{
		Name: "other-tenant", DisplayName: "Other", IssuerURL: "https://other.example.test/realms/other-tenant"})
	if err != nil {
		t.Fatal(err)
	}
	credential := "adminpassword"
	provider, err := data.CreateLDAPFederation(ctx, theirs.ID, store.LDAPFederationInput{
		Name: "theirs", Vendor: "OTHER", ConnectionURL: directory,
		BindDN: "cn=admin,dc=example,dc=test", BindCredential: &credential,
		UsersDN: "ou=people,dc=example,dc=test", UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "KEEP",
		EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn", ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	admin, err := data.CreateSession(ctx, mine.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "admin", "password")
	if err != nil {
		t.Fatal(err)
	}

	// My Realm in the path, their provider as the identifier.
	base := "/api/admin/v1/realms/" + mine.ID.String() + "/user-federations/" + provider.ID.String()
	for _, attempt := range []struct{ method, path, body string }{
		{http.MethodGet, base, ""},
		{http.MethodPut, base, `{"name":"taken","vendor":"OTHER","connection_url":"ldap://127.0.0.1:1",` +
			`"bind_dn":"cn=admin,dc=example,dc=test","users_dn":"ou=people,dc=example,dc=test",` +
			`"username_ldap_attribute":"uid","rdn_ldap_attribute":"uid","uuid_ldap_attribute":"entryUUID",` +
			`"user_object_classes":["inetOrgPerson"],"search_scope":"SUBTREE","batch_size":100,` +
			`"edit_mode":"READ_ONLY","missing_user_action":"KEEP","enabled":true}`},
		{http.MethodDelete, base, ""},
		{http.MethodPost, base + "/test-connection", ""},
		{http.MethodPost, base + "/test-authentication", `{"username":"alice","password":"x"}`},
		{http.MethodPost, base + "/sync", ""},
	} {
		var body io.Reader
		if attempt.body != "" {
			body = strings.NewReader(attempt.body)
		}
		request, requestErr := http.NewRequest(attempt.method, server.URL+attempt.path, body)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: "resso_session", Value: admin.Token})
		request.Header.Set("X-CSRF-Token", admin.CSRFToken)
		response, doErr := server.Client().Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s answered %d for another Realm's provider, want 404",
				attempt.method, attempt.path, response.StatusCode)
		}
	}

	// The provider is untouched by any of it.
	after, err := data.LDAPFederationByID(ctx, provider.ID)
	if err != nil {
		t.Fatalf("the provider was removed by a request from another Realm: %v", err)
	}
	if after.Name != "theirs" || after.RealmID != theirs.ID {
		t.Errorf("the provider was modified from another Realm: %+v", after)
	}
}

// The tenant boundary for the rest of the administrative API, in the shape that
// can actually reach it: a Realm the caller may act on, paired with a resource
// belonging to another Realm. The middleware checks the first half only, so
// every one of these handlers has to check that the pair belongs together.
//
// Thirteen routes carry such a pair. Counting checks by reading them is what
// this replaces — the question is whether the resource is still untouched
// afterwards, which is asserted here for each kind.
func TestIntegrationAdminRoutesRefuseResourcesFromAnotherRealm(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	mine := bootstrap.RealmID
	theirs, err := data.CreateRealm(ctx, store.CreateRealmInput{
		Name: "tenant-b", DisplayName: "Tenant B", IssuerURL: "https://b.example.test/realms/tenant-b"})
	if err != nil {
		t.Fatal(err)
	}
	theirUser, err := data.CreateUser(ctx, theirs.ID, store.CreateUserInput{
		Username: "theirs", Password: "their-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	theirClient, err := data.CreateClient(ctx, theirs.ID, store.CreateClientInput{
		ClientID: "their-client", Name: "Theirs", Type: "confidential",
		RedirectURIs: []string{"https://b.example.test/cb"},
		GrantTypes:   []string{"authorization_code"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	theirRole, err := data.CreateRole(ctx, theirs.ID, "their-role", "")
	if err != nil {
		t.Fatal(err)
	}
	theirClientRole, err := data.CreateClientRole(ctx, theirs.ID, theirClient.Client.ID, "their-client-role", "")
	if err != nil {
		t.Fatal(err)
	}
	theirSession, err := data.CreateSession(ctx, theirs.ID, theirUser.ID, time.Hour, "127.0.0.1", "theirs", "password")
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	admin, err := data.CreateSession(ctx, mine, bootstrap.AdminUserID, time.Hour, "127.0.0.1", "admin", "password")
	if err != nil {
		t.Fatal(err)
	}

	base := "/api/admin/v1/realms/" + mine.String()
	user := base + "/users/" + theirUser.ID.String()
	client := base + "/clients/" + theirClient.Client.ID.String()
	for _, attempt := range []struct{ method, path, body string }{
		{http.MethodPut, user, `{"email":"","display_name":"taken","enabled":true,"email_verified":false}`},
		{http.MethodPut, user + "/password", `{"new_password":"taken-password-1234"}`},
		{http.MethodPost, user + "/unlock", ""},
		{http.MethodGet, user + "/role-mappings", ""},
		{http.MethodPut, user + "/role-mappings", `{"realm_role_ids":[],"client_role_ids":[]}`},
		{http.MethodPut, client, `{"name":"taken","redirect_uris":["https://b.example.test/cb"],` +
			`"grant_types":["authorization_code"],"default_scopes":["openid"],"require_pkce":true,` +
			`"enabled":true,"access_token_ttl_seconds":300,"refresh_token_ttl_seconds":1800}`},
		{http.MethodPost, client + "/rotate-secret", ""},
		{http.MethodGet, client + "/roles", ""},
		{http.MethodPost, client + "/roles", `{"name":"taken","description":""}`},
		{http.MethodDelete, client + "/roles/" + theirClientRole.ID.String(), ""},
		{http.MethodPut, base + "/roles/" + theirRole.ID.String(), `{"name":"taken","description":""}`},
		{http.MethodDelete, base + "/roles/" + theirRole.ID.String(), ""},
		{http.MethodDelete, base + "/sessions/" + theirSession.Session.ID.String(), ""},
	} {
		var body io.Reader
		if attempt.body != "" {
			body = strings.NewReader(attempt.body)
		}
		request, requestErr := http.NewRequest(attempt.method, server.URL+attempt.path, body)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: "resso_session", Value: admin.Token})
		request.Header.Set("X-CSRF-Token", admin.CSRFToken)
		response, doErr := server.Client().Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		_ = response.Body.Close()
		if response.StatusCode < 400 {
			t.Errorf("%s %s answered %d for another Realm's resource",
				attempt.method, attempt.path, response.StatusCode)
		}
	}

	// Nothing of theirs moved.
	if after, err := data.UserByID(ctx, theirUser.ID); err != nil || after.DisplayName == "taken" {
		t.Errorf("their account was changed: %+v (%v)", after, err)
	}
	if after, err := data.ClientByID(ctx, theirClient.Client.ID); err != nil || after.Name == "taken" {
		t.Errorf("their Client was changed: %+v (%v)", after, err)
	}
	roles, err := data.ListRoles(ctx, theirs.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, role := range roles {
		if role.Name == "their-role" {
			found = true
		}
	}
	if !found {
		t.Error("their Realm Role was removed or renamed")
	}
	clientRoles, err := data.ListClientRoles(ctx, theirs.ID, theirClient.Client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(clientRoles) != 1 || clientRoles[0].Name != "their-client-role" {
		t.Errorf("their Client Roles changed: %+v", clientRoles)
	}
	var revoked bool
	if err := data.Pool.QueryRow(ctx,
		"SELECT revoked_at IS NOT NULL FROM sso_sessions WHERE id=$1", theirSession.Session.ID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Error("their session was ended from another Realm")
	}
}

// The personal endpoints take a resource identifier from the path and the owner
// from the session, so the pairing question here is ownership rather than
// Realm: one person's identifier arriving with another person's session. For an
// API key that is a credential — rotating somebody else's would retire the key
// they are using and hand the caller a working one on their own account, which
// is a way to take an integration down and leave no sign of who did it.
func TestIntegrationPersonalRoutesRefuseSomebodyElsesKeyOrSession(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm := bootstrap.RealmID
	other, err := data.CreateUser(ctx, realm, store.CreateUserInput{
		Username: "other", Password: "other-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	theirKey, err := data.CreatePersonalAPIKey(ctx, other.ID, "theirs", []string{"api:read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	theirSession, err := data.CreateSession(ctx, realm, other.ID, time.Hour, "127.0.0.1", "theirs", "password")
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	mine, err := data.CreateSession(ctx, realm, bootstrap.AdminUserID, time.Hour, "127.0.0.1", "mine", "password")
	if err != nil {
		t.Fatal(err)
	}

	for _, attempt := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/me/api-keys/" + theirKey.Key.ID.String() + "/rotate"},
		{http.MethodDelete, "/api/v1/me/api-keys/" + theirKey.Key.ID.String()},
		{http.MethodDelete, "/api/v1/me/sessions/" + theirSession.Session.ID.String()},
	} {
		request, requestErr := http.NewRequest(attempt.method, server.URL+attempt.path, nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.AddCookie(&http.Cookie{Name: "resso_session", Value: mine.Token})
		request.Header.Set("X-CSRF-Token", mine.CSRFToken)
		response, doErr := server.Client().Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s answered %d for something belonging to somebody else",
				attempt.method, attempt.path, response.StatusCode)
		}
	}

	// Theirs still works, which is the half that matters: refusing loudly and
	// retiring the key anyway would be the same outcome for them.
	if _, err := data.AuthenticateAPIKey(ctx, theirKey.Secret); err != nil {
		t.Errorf("their API key stopped working: %v", err)
	}
	var revoked bool
	if err := data.Pool.QueryRow(ctx,
		"SELECT revoked_at IS NOT NULL FROM sso_sessions WHERE id=$1", theirSession.Session.ID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Error("their session was ended by somebody else's request")
	}
	// And no key was minted for the caller in the attempt.
	keys, err := data.ListPersonalAPIKeys(ctx, bootstrap.AdminUserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("the rotation attempt left %d key(s) on the caller's account", len(keys))
	}
}

// Only sentences the store wrote may reach a caller. This handler echoed
// whatever came back, so a write that failed on our side arrived as its
// SQLSTATE — "ERROR: ... (SQLSTATE P0001)" — under a 400 that blamed the
// request. The administrator reads that they sent something wrong and goes
// looking at what they typed.
//
// The collision paths were given this treatment already; this one was missed
// because its failures are rarer than a taken name.
func TestIntegrationRoleMappingFailuresDoNotLeakDatabaseText(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(ctx, bootstrap.RealmID, store.CreateUserInput{
		Username: "mapped", Password: "mapped-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	role, err := data.CreateRole(ctx, bootstrap.RealmID, "mappable", "")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	admin, err := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "admin", "password")
	if err != nil {
		t.Fatal(err)
	}
	put := func(body string) (int, map[string]any) {
		t.Helper()
		request, requestErr := http.NewRequest(http.MethodPut,
			server.URL+"/api/admin/v1/realms/"+bootstrap.RealmID.String()+"/users/"+user.ID.String()+"/role-mappings",
			strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: "resso_session", Value: admin.Token})
		request.Header.Set("X-CSRF-Token", admin.CSRFToken)
		response, doErr := server.Client().Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer func() { _ = response.Body.Close() }()
		decoded := map[string]any{}
		_ = json.NewDecoder(response.Body).Decode(&decoded)
		return response.StatusCode, decoded
	}

	// A Role from nowhere is the caller's mistake, and is told so in words.
	status, body := put(`{"realm_role_ids":["` + uuid.New().String() + `"],"client_role_ids":[]}`)
	if status != http.StatusBadRequest {
		t.Errorf("naming a Role that is not in the Realm answered %d", status)
	}
	message, _ := body["message"].(string)
	if !strings.Contains(message, "Realm") {
		t.Errorf("the refusal does not explain itself: %q", message)
	}

	// A write that fails is ours, and must not be described as a bad request
	// or quoted back.
	if _, err := data.Pool.Exec(ctx, `CREATE FUNCTION block_mapping() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'mapping blocked'; END $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `CREATE TRIGGER block_mapping BEFORE INSERT ON user_roles
		FOR EACH ROW EXECUTE FUNCTION block_mapping()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = data.Pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS block_mapping ON user_roles")
	})
	status, body = put(`{"realm_role_ids":["` + role.ID.String() + `"],"client_role_ids":[]}`)
	message, _ = body["message"].(string)
	for _, trace := range []string{"SQLSTATE", "ERROR:", "mapping blocked"} {
		if strings.Contains(message, trace) {
			t.Errorf("the response carries database text (%q): %q", trace, message)
		}
	}
	if status == http.StatusBadRequest {
		t.Errorf("a write that failed on our side was reported as a bad request: %d %v", status, body)
	}
}

// Every administrative write that can fail has two kinds of failure: what the
// caller sent, and what happened on our side. The first is theirs to fix and is
// said in words; the second is ours and must not arrive as database text under
// a status blaming them. This walks the writes that used to echo whatever came
// back and requires both halves of that.
func TestIntegrationAdminWriteFailuresExplainOrStayQuiet(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	admin, err := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "admin", "password")
	if err != nil {
		t.Fatal(err)
	}
	send := func(method, path, body string) (int, string) {
		t.Helper()
		request, requestErr := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: "resso_session", Value: admin.Token})
		request.Header.Set("X-CSRF-Token", admin.CSRFToken)
		response, doErr := server.Client().Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer func() { _ = response.Body.Close() }()
		decoded := map[string]any{}
		_ = json.NewDecoder(response.Body).Decode(&decoded)
		message, _ := decoded["message"].(string)
		return response.StatusCode, message
	}

	realm := "/api/admin/v1/realms/" + bootstrap.RealmID.String()
	for _, sent := range []struct{ what, method, path, body, expect string }{
		{"a Realm with no name", http.MethodPost, "/api/admin/v1/realms",
			`{"name":"","display_name":"","issuer_url":""}`, "필요"},
		{"a Realm with a plaintext issuer", http.MethodPost, "/api/admin/v1/realms",
			`{"name":"plain","display_name":"Plain","issuer_url":"http://plain.example.test/realms/plain"}`, "HTTPS"},
		{"a Client with no name", http.MethodPost, realm + "/clients",
			`{"client_id":"x","name":"","type":"public","redirect_uris":["https://x.example.test/cb"]}`, "필요"},
		{"a Role with no name", http.MethodPost, realm + "/roles", `{"name":"","description":""}`, "필요"},
		{"a user with no password", http.MethodPost, realm + "/users",
			`{"username":"nopass","email":"","display_name":"No Pass","password":"","enabled":true}`, "필요"},
	} {
		status, message := send(sent.method, sent.path, sent.body)
		if status != http.StatusBadRequest {
			t.Errorf("%s answered %d, want 400", sent.what, status)
		}
		if !strings.Contains(message, sent.expect) {
			t.Errorf("%s was refused with %q, which does not say what to fix", sent.what, message)
		}
	}

	// Now a failure on our side, on one of the same routes.
	if _, err := data.Pool.Exec(ctx, `CREATE FUNCTION block_role_create() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'role creation blocked'; END $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `CREATE TRIGGER block_role_create BEFORE INSERT ON roles
		FOR EACH ROW EXECUTE FUNCTION block_role_create()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = data.Pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS block_role_create ON roles")
	})
	status, message := send(http.MethodPost, realm+"/roles", `{"name":"blocked","description":""}`)
	for _, trace := range []string{"SQLSTATE", "ERROR:", "role creation blocked"} {
		if strings.Contains(message, trace) {
			t.Errorf("a failed write quoted the database (%q): %q", trace, message)
		}
	}
	if status == http.StatusBadRequest {
		t.Errorf("a write that failed on our side was reported as a bad request: %d %q", status, message)
	}
}

// The MCP federation tool copied the fields it returns one by one, and the
// copy fell behind the record: an agent asked to check on a sync was told its
// status but not why it failed, and never heard about the accounts the run
// deactivated — under the DISABLE policy the outcome that ends those people's
// sessions, and the one an administrator is sent to these fields to find.
//
// Nothing was being withheld by the copy. The record carries no credential to
// withhold: the bind password is represented by a boolean, and the REST
// listing behind the same admin:read hands the whole record to the console.
// So the list was duplication that could only drift, and did.
func TestIntegrationMCPFederationReportsWhatTheSyncDid(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := data.CreateLDAPFederation(ctx, bootstrap.RealmID, store.LDAPFederationInput{
		Name: "directory", Vendor: "OTHER", ConnectionURL: "ldap://127.0.0.1:1",
		UsersDN: "ou=people,dc=example,dc=test", UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "DISABLE",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx,
		`UPDATE user_federations SET last_sync_status='FAILURE', last_sync_error='bind failed',
		 last_sync_disabled=3, last_sync_group_memberships=7, last_sync_unknown_roles=ARRAY['auditor']
		 WHERE id=$1`, provider.ID); err != nil {
		t.Fatal(err)
	}
	key, err := data.CreatePersonalAPIKey(ctx, bootstrap.AdminUserID, "agent",
		[]string{"mcp:read", "admin:read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	body := callIntegrationMCP(t, server.Client(), server.URL, key.Secret,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"resso_list_user_federations","arguments":{}}}`)
	var envelope struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil || len(envelope.Result.Content) == 0 {
		t.Fatalf("federation listing did not answer with content: %s", body)
	}
	reported := envelope.Result.Content[0].Text
	var listed []struct {
		LastSyncError            string   `json:"last_sync_error"`
		LastSyncDisabled         int      `json:"last_sync_disabled"`
		LastSyncGroupMemberships int      `json:"last_sync_group_memberships"`
		LastSyncUnknownRoles     []string `json:"last_sync_unknown_roles"`
	}
	if err := json.Unmarshal([]byte(reported), &listed); err != nil || len(listed) != 1 {
		t.Fatalf("federation listing did not decode to one provider: %s", reported)
	}
	if listed[0].LastSyncError != "bind failed" {
		t.Errorf("last_sync_error = %q, want the reason the run failed", listed[0].LastSyncError)
	}
	if listed[0].LastSyncDisabled != 3 {
		t.Errorf("last_sync_disabled = %d, want 3", listed[0].LastSyncDisabled)
	}
	if listed[0].LastSyncGroupMemberships != 7 {
		t.Errorf("last_sync_group_memberships = %d, want 7", listed[0].LastSyncGroupMemberships)
	}
	if !slices.Contains(listed[0].LastSyncUnknownRoles, "auditor") {
		t.Errorf("last_sync_unknown_roles = %v, want the Role the mapping names", listed[0].LastSyncUnknownRoles)
	}
	// And it still withholds nothing it never held: the credential is a
	// boolean either way, so this is the whole record and not a wider one.
	if strings.Contains(reported, "bind_password") || strings.Contains(reported, "bind_credential_cipher") {
		t.Errorf("federation listing carried a credential: %s", reported)
	}
}

// CSRF is enforced in one place, by the middleware that resolves the browser
// session, so no handler can forget it — but a route registered outside that
// group never reaches the middleware at all, and nothing said so. The check is
// therefore about where routes are registered rather than what they do: every
// method under /api that changes something must refuse a request carrying a
// valid session and no token.
//
// Login is the one exception, and it is one by definition: there is no session
// to protect yet. Logout is not - it is behind a session, so it is covered
// here. Paths outside /api are bearer-token surfaces, which carry no ambient
// credential for another site to borrow.
func TestIntegrationEveryMutatingAPIRouteRequiresACSRFToken(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	if _, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123"); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(data, logger, nil, nil).Handler()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	signIn, err := server.Client().Post(server.URL+"/api/v1/auth/login", "application/json",
		strings.NewReader(`{"realm":"master","username":"admin","password":"bootstrap-password-123","request":""}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(signIn.Body)
	_ = signIn.Body.Close()
	if signIn.StatusCode != http.StatusOK {
		t.Fatalf("signing in for the probe failed: %d %s", signIn.StatusCode, body)
	}
	cookies := signIn.Cookies()

	router, ok := handler.(*chi.Mux)
	if !ok {
		t.Fatal("handler is not a chi router")
	}
	// Any placeholder, not a list of the names used today: a route with a new
	// parameter name would otherwise be requested with braces in its path and
	// quietly leave the set this covers.
	placeholder := regexp.MustCompile(`\{[^}]*\}|\*`)
	probed := 0
	walkErr := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			return nil
		}
		if !strings.HasPrefix(route, "/api/") || route == "/api/v1/auth/login" {
			return nil
		}
		path := placeholder.ReplaceAllString(route, "00000000-0000-0000-0000-000000000001")
		request, err := http.NewRequest(method, server.URL+path, strings.NewReader("{}"))
		if err != nil {
			t.Errorf("%s %s could not be requested: %v", method, route, err)
			return nil
		}
		request.Header.Set("Content-Type", "application/json")
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Errorf("%s %s: %v", method, route, err)
			return nil
		}
		answer, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		probed++
		if response.StatusCode != http.StatusForbidden || !strings.Contains(string(answer), "invalid_csrf") {
			t.Errorf("%s %s answered %d %.100s without a CSRF token: a request another site can "+
				"make with the operator's cookie changes state", method, route, response.StatusCode, answer)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if probed == 0 {
		t.Fatal("no mutating API route was probed, so nothing is being checked")
	}
	t.Logf("%d mutating API routes refuse a request without a CSRF token", probed)
}

// Every realm-scoped route carries the realm in its path, and each one decides
// for itself that the caller may act on that realm. One that forgets hands a
// realm administrator another tenant's directory, which is the whole boundary
// this product sells.
//
// The expectation is taken from behaviour rather than written down: the same
// session asks for the same routes twice, once naming its own realm and once
// naming another's. Every route the operator may reach on their own realm must
// be refused on the other. Written as a fixed list of "must answer 403" it
// would have proved almost nothing - most of these paths carry a sub-resource
// id too, and a made-up one answers 404 whichever realm is named, so the
// refusal would have been the id's doing and not the boundary's.
func TestIntegrationRealmScopedRoutesRefuseAnotherTenant(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := data.CreateRealm(ctx, store.CreateRealmInput{
		Name: "tenant", DisplayName: "Tenant", IssuerURL: "http://localhost:8080/realms/tenant"})
	if err != nil {
		t.Fatal(err)
	}
	operator, err := data.CreateUser(ctx, bootstrap.RealmID, store.CreateUserInput{
		Username: "realm-operator", Password: "operator-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_id)
        SELECT $1,id FROM roles WHERE realm_id=$2 AND name='realm-admin' ON CONFLICT DO NOTHING`,
		operator.ID, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(data, logger, nil, nil).Handler()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cookies, csrf := signInForBoundaryProbe(t, server, "realm-operator", "operator-password-1234")

	type call struct{ method, route string }
	routes := make([]call, 0)
	realmParam := regexp.MustCompile(`\{realmID\}`)
	otherParams := regexp.MustCompile(`\{[^}]*\}|\*`)
	if walkErr := chi.Walk(handler.(*chi.Mux), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.Contains(route, "{realmID}") && method != http.MethodOptions {
			routes = append(routes, call{method, route})
		}
		return nil
	}); walkErr != nil {
		t.Fatal(walkErr)
	}
	ask := func(one call, realmID string) int {
		t.Helper()
		path := otherParams.ReplaceAllString(realmParam.ReplaceAllString(one.route, realmID),
			"00000000-0000-0000-0000-000000000001")
		request, err := http.NewRequest(one.method, server.URL+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("%s %s could not be requested: %v", one.method, one.route, err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatalf("%s %s: %v", one.method, one.route, err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		return response.StatusCode
	}

	// Own realm first: these are the routes the boundary actually has to hold,
	// and the mutations they make land on the operator's own tenant.
	// Not merely "was not refused": a path carrying a made-up sub-resource id
	// answers 404 whichever realm is named, so counting those as reached would
	// let the id's doing stand in for the boundary's.
	reachable := make([]call, 0, len(routes))
	for _, one := range routes {
		switch ask(one, bootstrap.RealmID.String()) {
		case http.StatusForbidden, http.StatusNotFound:
		default:
			reachable = append(reachable, one)
		}
	}
	if len(reachable) == 0 {
		t.Fatal("the operator could reach none of their own realm's routes, so the comparison below " +
			"would pass without testing anything")
	}
	for _, one := range reachable {
		if status := ask(one, theirs.ID.String()); status != http.StatusForbidden {
			t.Errorf("%s %s answered %d for another tenant's realm while the operator administers "+
				"only their own", one.method, one.route, status)
		}
	}
	t.Logf("%d of %d realm-scoped routes act on the operator's own realm and are refused on another's",
		len(reachable), len(routes))
}

func signInForBoundaryProbe(t *testing.T, server *httptest.Server, username, password string) ([]*http.Cookie, string) {
	t.Helper()
	body := fmt.Sprintf(`{"realm":"master","username":%q,"password":%q,"request":""}`, username, password)
	response, err := server.Client().Post(server.URL+"/api/v1/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("signing in as %s failed: %d %s", username, response.StatusCode, raw)
	}
	var decoded struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.CSRF == "" {
		t.Fatalf("sign-in returned no CSRF token: %s", raw)
	}
	return response.Cookies(), decoded.CSRF
}

// Deleting a Role removes the row, and the audit event named it by the id of
// the row that is now gone and recorded nothing else. So the trail could not
// answer the one question it is kept for - which Role was deleted - and said
// nothing about the people who lost it, though the delete cascades their
// assignments away. Every other deletion here already records what it removed:
// LDAP_FEDERATION_DELETE carries the provider's name and how many accounts it
// unlinked, and revoking an API key leaves the row behind so its id still
// resolves.
func TestIntegrationDeletingARoleSaysWhichOneAndWhoHeldIt(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	role, err := data.CreateRole(ctx, bootstrap.RealmID, "auditor", "Reads the trail")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"holder-one", "holder-two"} {
		holder, err := data.CreateUser(ctx, bootstrap.RealmID, store.CreateUserInput{
			Username: name, Password: "holder-password-1234", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := data.Pool.Exec(ctx,
			"INSERT INTO user_roles(user_id,role_id) VALUES($1,$2)", holder.ID, role.ID); err != nil {
			t.Fatal(err)
		}
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(data, logger, nil, nil).Handler()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cookies, csrf := signInForBoundaryProbe(t, server, "admin", "bootstrap-password-123")

	request, err := http.NewRequest(http.MethodDelete,
		fmt.Sprintf("%s/api/admin/v1/realms/%s/roles/%s", server.URL, bootstrap.RealmID, role.ID), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-CSRF-Token", csrf)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("deleting the Role answered %d %s", response.StatusCode, body)
	}

	page, err := data.ListAudit(ctx, store.AuditFilter{
		RealmID: &bootstrap.RealmID, EventType: "ROLE_DELETE", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("ROLE_DELETE events = %d, want 1", len(page.Items))
	}
	var detail map[string]any
	if err := json.Unmarshal(page.Items[0].Detail, &detail); err != nil {
		t.Fatalf("the event carries no readable detail: %s", page.Items[0].Detail)
	}
	if detail["name"] != "auditor" {
		t.Errorf("the event does not name the Role it removed: %v — the id it carries points at a "+
			"row that no longer exists, so nothing can recover it", detail)
	}
	// json numbers decode as float64.
	if held, ok := detail["users_unassigned"].(float64); !ok || int(held) != 2 {
		t.Errorf("the event does not say how many people lost the Role: %v", detail)
	}

	// A Client Role is deleted the same way and was recorded the same way, so
	// fixing only the Realm Role would have left the pair disagreeing.
	client, err := data.CreateClient(ctx, bootstrap.RealmID, store.CreateClientInput{
		ClientID: "reporting", Name: "Reporting", Type: "confidential",
		GrantTypes: []string{"client_credentials"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	clientRole, err := data.CreateClientRole(ctx, bootstrap.RealmID, client.Client.ID, "reader", "Reads reports")
	if err != nil {
		t.Fatal(err)
	}
	holder, err := data.CreateUser(ctx, bootstrap.RealmID, store.CreateUserInput{
		Username: "client-role-holder", Password: "holder-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx,
		"INSERT INTO user_client_roles(user_id,client_role_id) VALUES($1,$2)", holder.ID, clientRole.ID); err != nil {
		t.Fatal(err)
	}
	clientRequest, err := http.NewRequest(http.MethodDelete,
		fmt.Sprintf("%s/api/admin/v1/realms/%s/clients/%s/roles/%s",
			server.URL, bootstrap.RealmID, client.Client.ID, clientRole.ID), nil)
	if err != nil {
		t.Fatal(err)
	}
	clientRequest.Header.Set("X-CSRF-Token", csrf)
	for _, cookie := range cookies {
		clientRequest.AddCookie(cookie)
	}
	clientResponse, err := server.Client().Do(clientRequest)
	if err != nil {
		t.Fatal(err)
	}
	clientBody, _ := io.ReadAll(clientResponse.Body)
	_ = clientResponse.Body.Close()
	if clientResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("deleting the Client Role answered %d %s", clientResponse.StatusCode, clientBody)
	}
	clientPage, err := data.ListAudit(ctx, store.AuditFilter{
		RealmID: &bootstrap.RealmID, EventType: "CLIENT_ROLE_DELETE", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(clientPage.Items) != 1 {
		t.Fatalf("CLIENT_ROLE_DELETE events = %d, want 1", len(clientPage.Items))
	}
	var clientDetail map[string]any
	if err := json.Unmarshal(clientPage.Items[0].Detail, &clientDetail); err != nil {
		t.Fatalf("the event carries no readable detail: %s", clientPage.Items[0].Detail)
	}
	if clientDetail["name"] != "reader" {
		t.Errorf("the event does not name the Client Role it removed: %v", clientDetail)
	}
	if held, ok := clientDetail["users_unassigned"].(float64); !ok || int(held) != 1 {
		t.Errorf("the event does not say how many people lost the Client Role: %v", clientDetail)
	}
}

// A refresh rotates the caller's token before the new pair is signed. When the
// signing fails the rotation is undone, and when undoing it also fails the
// caller is left holding a token the service already considers spent. Its next
// attempt is then read as a replay: the family is revoked and the trail records
// REFRESH_TOKEN_REUSE against the client — the strongest signal this service
// has that a token was taken, and the one the operations guide sends a reader
// to look for.
//
// So the trail names a theft for something the service did to itself. Left
// only in a log, the line that says what actually happened is gone by the time
// anyone reads that entry and takes it at its word.
func TestIntegrationARotationThatCouldNotBeUndoneIsRecorded(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	created, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "rollback-probe", Name: "Rollback Probe", Type: "public",
		RedirectURIs: []string{"https://probe.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "rollback-integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	userID := bootstrap.AdminUserID
	sessionID := session.Session.ID
	raw, err := data.CreateRefreshToken(ctx, store.RefreshToken{RealmID: realm.ID, ClientID: created.Client.ID,
		UserID: &userID, SessionID: &sessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	// Signing fails: the realm has no active key, which is the outage this
	// path exists for rather than a bad grant.
	if _, err := data.Pool.Exec(ctx,
		`UPDATE signing_keys SET status='RETIRED' WHERE realm_id=$1`, realm.ID); err != nil {
		t.Fatal(err)
	}
	// And undoing the rotation fails: the rollback deletes the successor it
	// just created, so refusing that delete is the smallest way to stand in
	// for a database that will not take it.
	if _, err := data.Pool.Exec(ctx, `CREATE FUNCTION refuse_delete() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'the test refuses this delete'; END; $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `CREATE TRIGGER refuse_refresh_delete BEFORE DELETE ON refresh_tokens
		FOR EACH ROW EXECUTE FUNCTION refuse_delete()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = data.Pool.Exec(cleanupCtx, "DROP TRIGGER IF EXISTS refuse_refresh_delete ON refresh_tokens")
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}, "client_id": {"rollback-probe"}}
	response, err := server.Client().PostForm(server.URL+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("a refresh with no signing key answered %d, want %d",
			response.StatusCode, http.StatusInternalServerError)
	}

	page, err := data.ListAudit(ctx, store.AuditFilter{
		RealmID: &realm.ID, EventType: "TOKEN_REFRESH", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("TOKEN_REFRESH events = %d, want 1: the caller was left holding a token the service "+
			"considers spent, and the trail says nothing until it reads the next attempt as a theft",
			len(page.Items))
	}
	event := page.Items[0]
	if event.Result != "PARTIAL" {
		t.Errorf("result = %q, want PARTIAL: the refresh was refused and something it left behind was not undone",
			event.Result)
	}
	var detail map[string]any
	if err := json.Unmarshal(event.Detail, &detail); err != nil {
		t.Fatalf("the event carries no readable detail: %s", event.Detail)
	}
	if detail["rotation_rolled_back"] != false {
		t.Errorf("the event does not say the rotation still stands: %v", detail)
	}
}

// Disabling an account is the emergency stop. The row is written first and the
// sessions are ended after, so when that second half fails the account is off
// and the sessions are live — and the request used to answer 500 with no audit
// entry at all, describing something that did happen as something that did not.
//
// The retry made it worse. The sweep was keyed on the transition from enabled
// to disabled, so a second attempt found the account already off, skipped the
// sweep entirely, and recorded a clean SUCCESS over sessions that were still
// running. The administrator's own way of checking their work confirmed a stop
// that had not happened.
func TestIntegrationDisablingAnAccountThatCouldNotBeSignedOutSaysSo(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	target, err := data.CreateUser(ctx, bootstrap.RealmID, store.CreateUserInput{
		Username: "leaver", Password: "leaver-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateSession(ctx, bootstrap.RealmID, target.ID, time.Hour,
		"127.0.0.1", "leaver-agent", "password"); err != nil {
		t.Fatal(err)
	}
	// Only the revocation is refused, so signing in as the administrator below
	// still works.
	if _, err := data.Pool.Exec(ctx, `CREATE FUNCTION refuse_revoke() RETURNS trigger AS $$
		BEGIN
			IF NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL THEN
				RAISE EXCEPTION 'the test refuses this revocation';
			END IF;
			RETURN NEW;
		END; $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `CREATE TRIGGER refuse_session_revoke BEFORE UPDATE ON sso_sessions
		FOR EACH ROW EXECUTE FUNCTION refuse_revoke()`); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(data, logger, nil, nil).Handler()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cookies, csrf := signInForBoundaryProbe(t, server, "admin", "bootstrap-password-123")

	disable := func() (int, []byte) {
		t.Helper()
		body := `{"email":"","display_name":"Leaver","enabled":false}`
		request, err := http.NewRequest(http.MethodPut,
			fmt.Sprintf("%s/api/admin/v1/realms/%s/users/%s", server.URL, bootstrap.RealmID, target.ID),
			strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		answer, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		return response.StatusCode, answer
	}

	status, answer := disable()
	if status != http.StatusOK {
		t.Fatalf("disabling answered %d %s; the account was disabled, so this is not a failed request",
			status, answer)
	}
	if !strings.Contains(string(answer), "sessions_ended") {
		t.Errorf("the answer does not mention what did not finish: %s", answer)
	}
	var enabled bool
	if err := data.Pool.QueryRow(ctx, "SELECT enabled FROM users WHERE id=$1", target.ID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("the account was not disabled, so this test is not about what it says it is")
	}
	page, err := data.ListAudit(ctx, store.AuditFilter{
		RealmID: &bootstrap.RealmID, EventType: "USER_UPDATE", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("USER_UPDATE events = %d, want 1: the account was disabled and the trail said nothing",
			len(page.Items))
	}
	if page.Items[0].Result != "PARTIAL" {
		t.Errorf("result = %q, want PARTIAL", page.Items[0].Result)
	}
	var detail map[string]any
	if err := json.Unmarshal(page.Items[0].Detail, &detail); err != nil {
		t.Fatalf("the event carries no readable detail: %s", page.Items[0].Detail)
	}
	if detail["users_signed_out"] != false {
		t.Errorf("the event does not say the sessions are still live: %v", detail)
	}

	// The body that came back is a shape a caller has to be told about, so the
	// document has to carry it. Checked against the answer rather than against
	// a name written here: a schema that describes a field the response does
	// not have, or a response with a field the schema never mentions, is the
	// drift worth catching.
	spec, err := server.Client().Get(server.URL + "/api/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	document, _ := io.ReadAll(spec.Body)
	_ = spec.Body.Close()
	var answered map[string]any
	if err := json.Unmarshal(answer, &answered); err != nil {
		t.Fatalf("the partial answer is not an object: %s", answer)
	}
	documented := documentedFieldsFor(t, document, "/api/admin/v1/realms/{realmID}/users/{userID}", "put")
	if len(documented) == 0 {
		t.Fatal("the document describes no 200 body for this operation, so nothing below is compared")
	}
	for _, field := range []string{"sessions_ended", "message"} {
		if _, carried := answered[field]; !carried {
			t.Errorf("the answer does not carry %s: %s", field, answer)
			continue
		}
		if !documented[field] {
			t.Errorf("the answer carries %s and this operation's 200 body does not describe it, so a "+
				"caller reading the contract cannot know this shape exists", field)
		}
	}

	// And the retry has to actually retry. The account is already disabled by
	// now, which is exactly the state that used to make the sweep be skipped.
	if _, err := data.Pool.Exec(ctx, "DROP TRIGGER refuse_session_revoke ON sso_sessions"); err != nil {
		t.Fatal(err)
	}
	if status, answer := disable(); status != http.StatusOK {
		t.Fatalf("the retry answered %d %s", status, answer)
	}
	var live int
	if err := data.Pool.QueryRow(ctx,
		"SELECT count(*) FROM sso_sessions WHERE user_id=$1 AND revoked_at IS NULL", target.ID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Errorf("%d session(s) of a disabled account are still live after a retry: the second attempt "+
			"found the account already off and swept nothing", live)
	}
}

// documentedFieldsFor names the properties an operation's 200 body can carry,
// following the $refs it is made of. Searching the whole document instead
// would find these names in some other schema and pass while this operation
// says nothing — which is what the first version of this check did.
func documentedFieldsFor(t *testing.T, document []byte, path, method string) map[string]bool {
	t.Helper()
	var spec struct {
		Paths      map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(document, &spec); err != nil {
		t.Fatalf("the OpenAPI document does not decode: %v", err)
	}
	operation, ok := spec.Paths[path][method].(map[string]any)
	if !ok {
		t.Fatalf("the document has no %s for %s", method, path)
	}
	responses, _ := operation["responses"].(map[string]any)
	ok200, _ := responses["200"].(map[string]any)
	content, _ := ok200["content"].(map[string]any)
	body, _ := content["application/json"].(map[string]any)
	schema, _ := body["schema"].(map[string]any)

	fields := map[string]bool{}
	var walk func(node map[string]any, depth int)
	walk = func(node map[string]any, depth int) {
		if node == nil || depth > 4 {
			return
		}
		if ref, isRef := node["$ref"].(string); isRef {
			name := ref[strings.LastIndex(ref, "/")+1:]
			if resolved, found := spec.Components.Schemas[name].(map[string]any); found {
				walk(resolved, depth+1)
			}
			return
		}
		if properties, has := node["properties"].(map[string]any); has {
			for name := range properties {
				fields[name] = true
			}
		}
		for _, key := range []string{"oneOf", "anyOf", "allOf"} {
			if list, has := node[key].([]any); has {
				for _, item := range list {
					if child, isObject := item.(map[string]any); isObject {
						walk(child, depth+1)
					}
				}
			}
		}
	}
	walk(schema, 0)
	return fields
}
