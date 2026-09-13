package mail

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeRelay is the smallest SMTP server that can take a message. It records
// the conversation so a test can see what was actually said to it.
type fakeRelay struct {
	address   string
	offerAuth bool
	listener  net.Listener
	mu        sync.Mutex
	commands  []string
	body      string
}

func startRelay(t *testing.T, offerAuth bool) *fakeRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay := &fakeRelay{address: listener.Addr().String(), offerAuth: offerAuth, listener: listener}
	go relay.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return relay
}

func (f *fakeRelay) config() Config {
	host, port, _ := net.SplitHostPort(f.address)
	var number int
	_, _ = fmt.Sscanf(port, "%d", &number)
	return Config{Enabled: true, Host: host, Port: number, Security: SecurityAuto, FromAddress: "resso@example.com",
		FromName: "ReSSO", Timeout: 5 * time.Second, Events: map[string]bool{}}
}

func (f *fakeRelay) transcript() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

func (f *fakeRelay) received() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.body
}

func (f *fakeRelay) serve() {
	for {
		connection, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.handle(connection)
	}
}

func (f *fakeRelay) handle(connection net.Conn) {
	defer func() { _ = connection.Close() }()
	reader := bufio.NewReader(connection)
	write := func(line string) { _, _ = connection.Write([]byte(line + "\r\n")) }
	write("220 relay.internal ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.TrimSpace(line)
		f.mu.Lock()
		f.commands = append(f.commands, command)
		f.mu.Unlock()
		upper := strings.ToUpper(command)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			write("250-relay.internal")
			if f.offerAuth {
				write("250-AUTH PLAIN LOGIN")
			}
			write("250 SIZE 35882577")
		case strings.HasPrefix(upper, "AUTH"):
			write("235 2.7.0 Authentication successful")
		case strings.HasPrefix(upper, "MAIL FROM"), strings.HasPrefix(upper, "RCPT TO"):
			write("250 2.1.0 Ok")
		case upper == "DATA":
			write("354 End data with <CR><LF>.<CR><LF>")
			var body strings.Builder
			for {
				dataLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dataLine, "\r\n") == "." {
					break
				}
				body.WriteString(dataLine)
			}
			f.mu.Lock()
			f.body = body.String()
			f.mu.Unlock()
			write("250 2.0.0 Ok: queued")
		case upper == "QUIT":
			write("221 2.0.0 Bye")
			return
		default:
			write("250 Ok")
		}
	}
}

// The common internal relay: port 25, no credentials, no TLS. The message
// must go through without an AUTH or STARTTLS exchange, and arrive with the
// headers a mail client needs to show a Korean subject.
func TestDeliverReachesAnUnauthenticatedRelay(t *testing.T) {
	relay := startRelay(t, false)
	config := relay.config()
	err := Deliver(context.Background(), config, Message{To: "hong@example.com", Subject: "승인 요청", Body: "첫 줄\n.둘째 줄"})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	transcript := strings.Join(relay.transcript(), "\n")
	if strings.Contains(transcript, "AUTH") || strings.Contains(transcript, "STARTTLS") {
		t.Fatalf("an unauthenticated relay was offered credentials or TLS:\n%s", transcript)
	}
	if !strings.Contains(transcript, "EHLO example.com") || !strings.Contains(transcript, "MAIL FROM:<resso@example.com>") ||
		!strings.Contains(transcript, "RCPT TO:<hong@example.com>") {
		t.Fatalf("transcript = \n%s", transcript)
	}
	body := relay.received()
	if !strings.Contains(body, "Subject: =?utf-8?q?") || !strings.Contains(body, "From: ReSSO <resso@example.com>") ||
		!strings.Contains(body, "Auto-Submitted: auto-generated") || !strings.Contains(body, "\r\n..둘째 줄") {
		t.Fatalf("message = %q", body)
	}
}

// Credentials are used only when both a username is configured and the relay
// says it takes them.
func TestDeliverAuthenticatesOnlyWhenAsked(t *testing.T) {
	relay := startRelay(t, true)
	config := relay.config()
	config.Username, config.Password = "resso", "secret"
	if err := Deliver(context.Background(), config, Message{To: "hong@example.com", Subject: "x", Body: "y"}); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if transcript := strings.Join(relay.transcript(), "\n"); !strings.Contains(transcript, "AUTH PLAIN") {
		t.Fatalf("credentials were configured and offered but not used:\n%s", transcript)
	}
	silent := startRelay(t, false)
	config = silent.config()
	config.Username = "resso"
	err := Deliver(context.Background(), config, Message{To: "hong@example.com", Subject: "x", Body: "y"})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "사용자 이름을 비우고") {
		t.Fatalf("a relay without AUTH answered %v; want the advice to clear the username", err)
	}
}

// A relay that is not there fails the send, and nothing else: the error is
// answered quickly rather than hanging on the timeout.
func TestDeliverFailsFastWhenTheRelayIsDown(t *testing.T) {
	relay := startRelay(t, false)
	config := relay.config()
	_ = relay.listener.Close()
	started := time.Now()
	err := Deliver(context.Background(), config, Message{To: "hong@example.com", Subject: "x", Body: "y"})
	if err == nil || !strings.Contains(err.Error(), "SMTP 연결 실패") {
		t.Fatalf("a closed relay answered %v", err)
	}
	if time.Since(started) > config.Timeout {
		t.Fatalf("a refused connection took %s", time.Since(started))
	}
}

func TestValidateNamesTheMissingSetting(t *testing.T) {
	config := Read(map[string]any{})
	if err := config.Validate(); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), KeyHost) {
		t.Fatalf("an empty configuration validated as %v", err)
	}
	config = Read(map[string]any{KeyHost: "relay", KeySecurity: "ssl"})
	if err := config.ValidateShape(); err == nil || !strings.Contains(err.Error(), KeySecurity) {
		t.Fatalf("an unknown security mode validated as %v", err)
	}
}

// fakeBackend stands in for the store: settings, an address book, and the
// delivery record.
type fakeBackend struct {
	settings   map[string]any
	addresses  map[uuid.UUID]string
	mu         sync.Mutex
	deliveries map[uuid.UUID]Delivery
}

func (f *fakeBackend) MailSettings(context.Context) (map[string]any, error) { return f.settings, nil }
func (f *fakeBackend) MailAddresses(_ context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	found := map[uuid.UUID]string{}
	for _, id := range ids {
		if address, ok := f.addresses[id]; ok {
			found[id] = address
		}
	}
	return found, nil
}
func (f *fakeBackend) RecordMailDelivery(_ context.Context, delivery Delivery) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deliveries[delivery.ID] = delivery
	return nil
}
func (f *fakeBackend) CompleteMailDelivery(_ context.Context, id uuid.UUID, status string, attempts int, message string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delivery := f.deliveries[id]
	delivery.Status, delivery.Attempts, delivery.ErrorMessage = status, attempts, message
	f.deliveries[id] = delivery
	return nil
}
func (f *fakeBackend) list() []Delivery {
	f.mu.Lock()
	defer f.mu.Unlock()
	items := make([]Delivery, 0, len(f.deliveries))
	for _, delivery := range f.deliveries {
		items = append(items, delivery)
	}
	return items
}

type sentMail struct {
	To, Subject, Body string
}

func newTestService(backend *fakeBackend, fail error) (*Service, *[]sentMail) {
	var mu sync.Mutex
	sent := []sentMail{}
	service := NewService(backend, slog.New(slog.NewTextHandler(io.Discard, nil)))
	service.SetSender(func(_ context.Context, _ Config, message Message) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, sentMail(message))
		return fail
	})
	return service, &sent
}

var (
	actor    = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	reviewer = uuid.MustParse("00000000-0000-0000-0000-000000000002")
	noEmail  = uuid.MustParse("00000000-0000-0000-0000-000000000003")
)

func enabledSettings() map[string]any {
	return map[string]any{KeyEnabled: true, KeyHost: "relay.internal", KeyFromAddress: "resso@example.com", KeyBaseURL: "https://sso.example.com/"}
}

func newBackend(settings map[string]any) *fakeBackend {
	return &fakeBackend{settings: settings, deliveries: map[uuid.UUID]Delivery{},
		addresses: map[uuid.UUID]string{actor: "actor@example.com", reviewer: "reviewer@example.com"}}
}

// Off is the default, and off means nothing leaves — not even a record.
func TestNotifySendsNothingWhileDisabled(t *testing.T) {
	backend := newBackend(map[string]any{KeyHost: "relay.internal"})
	service, sent := newTestService(backend, nil)
	service.Notify(context.Background(), ApprovalRequested("hong", "corp", "ops", "", "r1"), actor, []uuid.UUID{reviewer})
	service.Wait(time.Second)
	if len(*sent) != 0 || len(backend.list()) != 0 {
		t.Fatalf("disabled mail sent %d and recorded %d", len(*sent), len(backend.list()))
	}
	if err := service.SendNow(context.Background(), TestMessage(), actor, "x@example.com"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("a test send while disabled answered %v", err)
	}
}

// The actor is never told about their own action, an account without an
// address is skipped, and what was sent is recorded with the outcome — but
// without the body.
func TestNotifySkipsTheActorAndRecordsTheAttempt(t *testing.T) {
	backend := newBackend(enabledSettings())
	service, sent := newTestService(backend, nil)
	service.Notify(context.Background(), ApprovalRequested("hong", "corp", "ops", "급해요", "r1"), actor,
		[]uuid.UUID{actor, reviewer, reviewer, noEmail})
	service.Wait(time.Second)
	if len(*sent) != 1 || (*sent)[0].To != "reviewer@example.com" {
		t.Fatalf("sent = %+v; want one mail to the reviewer only", *sent)
	}
	if body := (*sent)[0].Body; !strings.Contains(body, "https://sso.example.com/personal/requests") || !strings.Contains(body, "> 급해요") {
		t.Fatalf("body = %q", body)
	}
	deliveries := backend.list()
	if len(deliveries) != 1 || deliveries[0].Status != StatusSent || deliveries[0].Attempts != 1 ||
		deliveries[0].Recipient != "reviewer@example.com" || deliveries[0].Reference != "r1" || *deliveries[0].ActorID != actor {
		t.Fatalf("deliveries = %+v", deliveries)
	}
}

// A relay that is down fails the delivery, which is recorded as such after
// the retry — and the caller was never waiting on any of it.
func TestNotifyRecordsAFailedDelivery(t *testing.T) {
	backend := newBackend(enabledSettings())
	service, sent := newTestService(backend, errors.New("SMTP 연결 실패: connection refused"))
	started := time.Now()
	service.Notify(context.Background(), ApprovalDecided("corp", "ops", "APPROVED", "", "r1"), actor, []uuid.UUID{reviewer})
	if time.Since(started) > 500*time.Millisecond {
		t.Fatalf("Notify held the caller for %s", time.Since(started))
	}
	service.Wait(5 * time.Second)
	deliveries := backend.list()
	if len(deliveries) != 1 || deliveries[0].Status != StatusFailed || deliveries[0].Attempts != 2 ||
		!strings.Contains(deliveries[0].ErrorMessage, "connection refused") {
		t.Fatalf("deliveries = %+v", deliveries)
	}
	if len(*sent) != 2 {
		t.Fatalf("a failing relay was tried %d times; want 2", len(*sent))
	}
}

// Switching one event off stops that event and nothing else.
func TestEventSwitchStopsOnlyItsEvent(t *testing.T) {
	settings := enabledSettings()
	settings["mail.notify_approval_request"] = false
	backend := newBackend(settings)
	service, sent := newTestService(backend, nil)
	service.Notify(context.Background(), ApprovalRequested("hong", "corp", "ops", "", "r1"), actor, []uuid.UUID{reviewer})
	service.Notify(context.Background(), ApprovalDecided("corp", "ops", "REJECTED", "", "r1"), actor, []uuid.UUID{reviewer})
	service.Wait(time.Second)
	if len(*sent) != 1 || (*sent)[0].Subject != "[ReSSO] 'ops' Role 요청이 처리되었습니다" {
		t.Fatalf("sent = %+v; want only the decision", *sent)
	}
}

// The password goes in and never comes back out.
func TestViewDoesNotReturnThePassword(t *testing.T) {
	values := enabledSettings()
	values[KeyPassword] = "hunter2"
	values[KeyUsername] = "resso"
	view := View(values)
	if _, present := view[KeyPassword]; present {
		t.Fatalf("view carries the password: %v", view)
	}
	if view[KeyUsername] != "resso" || view[KeyPort] != DefaultPort || view[KeySecurity] != SecurityAuto ||
		view[KeyTimeout] != 10 || view["mail.notify_approval_request"] != true {
		t.Fatalf("view = %v", view)
	}
	for key := range view {
		if _, known := indexOf(Keys(), key); !known {
			t.Fatalf("view carries a key the screen may not write: %s", key)
		}
	}
	if Read(map[string]any{KeyPort: float64(465)}).Security != SecurityTLS {
		t.Fatal("port 465 did not select implicit TLS")
	}
}

func indexOf(list []string, value string) (int, bool) {
	for index, item := range list {
		if item == value {
			return index, true
		}
	}
	return 0, false
}

// Several keys expiring for one person are one mail.
func TestAPIKeysExpiringBundlesOnePersonsKeys(t *testing.T) {
	when := time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)
	notification := APIKeysExpiring([]ExpiringKey{{ID: "k1", Name: "ci", Prefix: "rk_a", ExpiresAt: when}, {ID: "k2", Name: "backup", Prefix: "rk_b", ExpiresAt: when}})
	body := notification.Render(Config{})
	if !strings.Contains(body, "- ci (rk_a…)") || !strings.Contains(body, "- backup (rk_b…)") || notification.Reference != "k1,k2" {
		t.Fatalf("notification = %+v\n%s", notification, body)
	}
	if strings.Contains(body, "바로 열기") {
		t.Fatal("a link was rendered without a base URL")
	}
}
