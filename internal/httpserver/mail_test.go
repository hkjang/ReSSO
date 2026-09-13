package httpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hkjang/ReSSO/internal/mail"
	"github.com/hkjang/ReSSO/internal/store"
)

// testRelay is an SMTP server that accepts everything and remembers who each
// message was for and what its subject was.
type testRelay struct {
	listener net.Listener
	mu       sync.Mutex
	messages []string // "recipient|subject-line"
}

func startTestRelay(t *testing.T) *testRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay := &testRelay{listener: listener}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go relay.handle(connection)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return relay
}

func (r *testRelay) hostPort() (string, int) {
	host, port, _ := net.SplitHostPort(r.listener.Addr().String())
	var number int
	_, _ = fmt.Sscanf(port, "%d", &number)
	return host, number
}

func (r *testRelay) handle(connection net.Conn) {
	defer func() { _ = connection.Close() }()
	reader := bufio.NewReader(connection)
	write := func(line string) { _, _ = connection.Write([]byte(line + "\r\n")) }
	write("220 relay.test ESMTP")
	recipient := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.TrimSpace(line)
		upper := strings.ToUpper(command)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			write("250-relay.test")
			write("250 SIZE 1000000")
		case strings.HasPrefix(upper, "RCPT TO"):
			recipient = strings.Trim(strings.TrimSpace(command[len("RCPT TO:"):]), "<>")
			write("250 Ok")
		case upper == "DATA":
			write("354 End data with <CR><LF>.<CR><LF>")
			subject := ""
			for {
				dataLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dataLine, "\r\n") == "." {
					break
				}
				if strings.HasPrefix(dataLine, "Subject: ") {
					subject = strings.TrimSpace(dataLine[len("Subject: "):])
				}
			}
			r.mu.Lock()
			r.messages = append(r.messages, recipient+"|"+subject)
			r.mu.Unlock()
			write("250 Ok: queued")
		case upper == "QUIT":
			write("221 Bye")
			return
		default:
			write("250 Ok")
		}
	}
}

// waitFor waits until the relay has taken the expected number of messages;
// deliveries are in the background, so a test cannot read the relay the
// moment the request returns.
func (r *testRelay) waitFor(t *testing.T, count int) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		r.mu.Lock()
		messages := append([]string(nil), r.messages...)
		r.mu.Unlock()
		if len(messages) >= count || time.Now().After(deadline) {
			return messages
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestIntegrationMailNotificationsLeaveThroughTheRelayInTheBackground(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, "UPDATE users SET email='admin@example.com' WHERE id=$1", bootstrap.AdminUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, "UPDATE realms SET approval_enabled=true WHERE id=$1", bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	hong, err := data.CreateUser(ctx, bootstrap.RealmID, store.CreateUserInput{Username: "hong", Email: "hong@example.com",
		DisplayName: "홍길동", Password: "hong-password-123", Enabled: true, ManagerID: &bootstrap.AdminUserID})
	if err != nil {
		t.Fatal(err)
	}
	role, err := data.CreateRole(ctx, bootstrap.RealmID, "ops", "")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(data, logger, nil, nil)
	server := httptest.NewServer(handler.Handler())
	t.Cleanup(server.Close)
	adminCookies, adminCSRF := signInForBoundaryProbe(t, server, "admin", "bootstrap-password-123")
	hongCookies, hongCSRF := signInForBoundaryProbe(t, server, "hong", "hong-password-123")

	call := func(cookies []*http.Cookie, csrf, method, path, body string) (*http.Response, []byte) {
		t.Helper()
		request, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
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
		raw, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		return response, raw
	}
	admin := func(method, path, body string) (*http.Response, []byte) {
		t.Helper()
		return call(adminCookies, adminCSRF, method, path, body)
	}
	relay := startTestRelay(t)
	host, port := relay.hostPort()

	// A fresh install: off, with the internal-relay defaults, and no password.
	response, raw := admin(http.MethodGet, "/api/admin/v1/mail", "")
	var view struct {
		Settings    map[string]any      `json:"settings"`
		PasswordSet bool                `json:"password_set"`
		Events      []mail.EventSetting `json:"events"`
	}
	if err := json.Unmarshal(raw, &view); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("initial settings: %d %s (%v)", response.StatusCode, raw, err)
	}
	if view.Settings[mail.KeyEnabled] != false || view.Settings[mail.KeyPort] != float64(25) || view.Settings[mail.KeySecurity] != "auto" ||
		view.PasswordSet || len(view.Events) != 4 {
		t.Fatalf("fresh settings = %+v", view)
	}
	if _, present := view.Settings[mail.KeyPassword]; present {
		t.Fatal("the view carries the password key")
	}

	// A test send while off is refused as such and nothing reaches the relay.
	response, raw = admin(http.MethodPost, "/api/admin/v1/mail/test", `{"recipient":"admin@example.com"}`)
	if response.StatusCode != http.StatusConflict || !strings.Contains(string(raw), "mail_disabled") {
		t.Fatalf("a test send while disabled answered %d %s", response.StatusCode, raw)
	}

	// Hong asks for a role while mail is off: the request is created, and no
	// mail leaves.
	hongRequest := func() string {
		t.Helper()
		response, raw := call(hongCookies, hongCSRF, http.MethodPost, "/api/v1/me/requests", `{"role_id":"`+role.ID.String()+`","reason":"급합니다"}`)
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("the approval request answered %d %s", response.StatusCode, raw)
		}
		var created struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &created)
		return created.ID
	}
	requestID := hongRequest()
	if messages := relay.waitFor(t, 1); len(messages) != 0 {
		t.Fatalf("mail was off and the relay received %v", messages)
	}

	// A port outside the range is refused as input, and nothing is saved.
	response, raw = admin(http.MethodPut, "/api/admin/v1/mail", `{"settings":{"mail.smtp_port":70000}}`)
	if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "invalid_input") {
		t.Fatalf("an impossible port answered %d %s", response.StatusCode, raw)
	}
	// Unknown keys are refused too: the names are the standard's.
	response, raw = admin(http.MethodPut, "/api/admin/v1/mail", `{"settings":{"smtp.host":"x"}}`)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unknown key answered %d %s", response.StatusCode, raw)
	}

	// Turn it on, pointing at the relay, with a password. The answer says a
	// password is set and does not say what it is.
	settings := fmt.Sprintf(`{"settings":{"mail.enabled":true,"mail.smtp_host":%q,"mail.smtp_port":%d,"mail.security":"none","mail.from_address":"resso@example.com","mail.base_url":"https://sso.example.com","mail.username":"relay-user"},"password":"relay-secret"}`, host, port)
	response, raw = admin(http.MethodPut, "/api/admin/v1/mail", settings)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("saving the settings answered %d %s", response.StatusCode, raw)
	}
	if strings.Contains(string(raw), "relay-secret") || !strings.Contains(string(raw), `"password_set":true`) {
		t.Fatalf("the saved view leaks or loses the password: %s", raw)
	}
	// The username was saved but the relay offers no AUTH, so the send says
	// so — and the outcome is in the record as a failure, not just a log line.
	response, raw = admin(http.MethodPost, "/api/admin/v1/mail/test", `{"recipient":"admin@example.com"}`)
	if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "사용자 이름을 비우고") {
		t.Fatalf("a relay without AUTH answered %d %s", response.StatusCode, raw)
	}
	// Saving without the password field leaves the stored one alone; clearing
	// the username makes the relay reachable.
	response, raw = admin(http.MethodPut, "/api/admin/v1/mail", `{"settings":{"mail.username":""}}`)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"password_set":true`) {
		t.Fatalf("saving without a password answered %d %s", response.StatusCode, raw)
	}
	response, raw = admin(http.MethodPost, "/api/admin/v1/mail/test", `{"recipient":"admin@example.com"}`)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"sent":true`) {
		t.Fatalf("the test send answered %d %s", response.StatusCode, raw)
	}
	if messages := relay.waitFor(t, 1); len(messages) != 1 || !strings.HasPrefix(messages[0], "admin@example.com|") {
		t.Fatalf("relay received %v after the test send", messages)
	}

	// The pending request decided: Hong is told, the deciding administrator
	// is not (they are the actor).
	response, raw = admin(http.MethodPost, "/api/admin/v1/approvals/"+requestID+"/decision", `{"decision":"approve","note":"환영합니다"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the decision answered %d %s", response.StatusCode, raw)
	}
	messages := relay.waitFor(t, 2)
	if len(messages) != 2 || !strings.HasPrefix(messages[1], "hong@example.com|") {
		t.Fatalf("relay received %v after the decision", messages)
	}

	// A second request reaches the reviewer — Hong's manager — and not Hong.
	hong2, err := data.CreateRole(ctx, bootstrap.RealmID, "audit", "")
	if err != nil {
		t.Fatal(err)
	}
	response, raw = call(hongCookies, hongCSRF, http.MethodPost, "/api/v1/me/requests", `{"role_id":"`+hong2.ID.String()+`"}`)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("the second request answered %d %s", response.StatusCode, raw)
	}
	messages = relay.waitFor(t, 3)
	if len(messages) != 3 || !strings.HasPrefix(messages[2], "admin@example.com|") {
		t.Fatalf("relay received %v after the second request", messages)
	}

	// Switching the request event off stops it and nothing else.
	response, raw = admin(http.MethodPut, "/api/admin/v1/mail", `{"settings":{"mail.notify_approval_request":false}}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("switching an event off answered %d %s", response.StatusCode, raw)
	}
	hong3, err := data.CreateRole(ctx, bootstrap.RealmID, "billing", "")
	if err != nil {
		t.Fatal(err)
	}
	response, raw = call(hongCookies, hongCSRF, http.MethodPost, "/api/v1/me/requests", `{"role_id":"`+hong3.ID.String()+`"}`)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("the third request answered %d %s", response.StatusCode, raw)
	}
	if messages := relay.waitFor(t, 4); len(messages) != 3 {
		t.Fatalf("relay received %v with the request event off", messages)
	}

	// The record has every attempt: the failed test, the successful test,
	// the decision, the request — and no body.
	response, raw = admin(http.MethodGet, "/api/admin/v1/mail/deliveries", "")
	var page struct {
		Items    []mail.Delivery `json:"items"`
		Total    int             `json:"total"`
		ByStatus map[string]int  `json:"by_status"`
	}
	if err := json.Unmarshal(raw, &page); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("deliveries: %d %s (%v)", response.StatusCode, raw, err)
	}
	if page.Total != 4 || page.ByStatus[mail.StatusFailed] != 1 || page.ByStatus[mail.StatusSent] != 3 {
		t.Fatalf("delivery summary = %+v", page)
	}
	if strings.Contains(string(raw), "급합니다") || strings.Contains(string(raw), "환영합니다") {
		t.Fatalf("the delivery record carries a body: %s", raw)
	}
	events := map[string]int{}
	for _, item := range page.Items {
		events[item.Event]++
		if item.Event == mail.EventApprovalDecided && (item.Recipient != "hong@example.com" || item.Reference != requestID || item.ActorID == nil || *item.ActorID != bootstrap.AdminUserID) {
			t.Fatalf("decision delivery = %+v", item)
		}
	}
	if events[mail.EventTest] != 2 || events[mail.EventApprovalDecided] != 1 || events[mail.EventApprovalRequested] != 1 {
		t.Fatalf("delivery events = %v", events)
	}

	// The relay gone: a request still succeeds, and the failure is recorded.
	_ = relay.listener.Close()
	hong4, err := data.CreateRole(ctx, bootstrap.RealmID, "finance", "")
	if err != nil {
		t.Fatal(err)
	}
	response, raw = admin(http.MethodPut, "/api/admin/v1/mail", `{"settings":{"mail.notify_approval_request":true,"mail.timeout_seconds":2}}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("switching the event back on answered %d %s", response.StatusCode, raw)
	}
	started := time.Now()
	response, raw = call(hongCookies, hongCSRF, http.MethodPost, "/api/v1/me/requests", `{"role_id":"`+hong4.ID.String()+`"}`)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("a request with the relay down answered %d %s", response.StatusCode, raw)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatalf("a request with the relay down took %s", time.Since(started))
	}
	handler.Mail().Wait(15 * time.Second)
	response, raw = admin(http.MethodGet, "/api/admin/v1/mail/deliveries?status=failed", "")
	if err := json.Unmarshal(raw, &page); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("failed deliveries: %d %s (%v)", response.StatusCode, raw, err)
	}
	if page.ByStatus[mail.StatusFailed] != 2 || len(page.Items) != 2 || page.Items[0].Attempts != 2 || !strings.Contains(page.Items[0].ErrorMessage, "SMTP 연결 실패") {
		t.Fatalf("after the relay went away: %+v", page)
	}

	// Realm administrators cannot reach any of it.
	realmAdmin := hong
	if _, err := data.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_id) SELECT $1,id FROM roles WHERE realm_id=$2 AND name='realm-admin'`,
		realmAdmin.ID, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	hongCookies, hongCSRF = signInForBoundaryProbe(t, server, "hong", "hong-password-123")
	for _, probe := range []struct{ method, path string }{{http.MethodGet, "/api/admin/v1/mail"}, {http.MethodPut, "/api/admin/v1/mail"},
		{http.MethodPost, "/api/admin/v1/mail/test"}, {http.MethodGet, "/api/admin/v1/mail/deliveries"}} {
		response, raw := call(hongCookies, hongCSRF, probe.method, probe.path, `{}`)
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s by a Realm administrator answered %d %s", probe.method, probe.path, response.StatusCode, raw)
		}
	}
}
