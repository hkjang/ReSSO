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
	"strconv"
	"strings"
	"testing"
	"time"

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
	result, detail := lastAudit()
	if result != "PARTIAL" {
		t.Errorf("the audit entry reads %s, want PARTIAL", result)
	}
	if detail["other_sessions_ended"] != false || detail["error"] == nil {
		t.Errorf("the audit entry does not record what failed: %v", detail)
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
