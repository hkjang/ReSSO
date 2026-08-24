package backchannel

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/store"
)

func TestNotifierDropsWorkWhenTheQueueIsFull(t *testing.T) {
	notifier := New(context.Background(), nil, nil, slog.New(slog.DiscardHandler), nil)
	// Fill every slot so the next notification has nowhere to go. A full queue
	// must be dropped with a warning rather than growing without bound.
	for range maximumQueueDepth {
		notifier.slots <- struct{}{}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		notifier.SessionRevoked(store.RevokedSession{RealmID: uuid.New(), SessionID: uuid.New(), UserID: uuid.New()})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SessionRevoked blocked instead of dropping the notification")
	}
}

func TestPostDeliversFormEncodedLogoutToken(t *testing.T) {
	type received struct {
		contentType string
		token       string
	}
	results := make(chan received, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(body))
		results <- received{contentType: r.Header.Get("Content-Type"), token: values.Get("logout_token")}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := New(context.Background(), nil, nil, slog.New(slog.DiscardHandler), nil)
	notifier.post(context.Background(), "master", "rp", server.URL, "signed.logout.token")

	select {
	case got := <-results:
		if got.token != "signed.logout.token" {
			t.Fatalf("logout_token = %q", got.token)
		}
		if !strings.HasPrefix(got.contentType, "application/x-www-form-urlencoded") {
			t.Fatalf("Content-Type = %q", got.contentType)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the relying party never received the logout token")
	}
}

func TestPostDoesNotFollowRedirects(t *testing.T) {
	reached := make(chan string, 2)
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- "final"
		w.WriteHeader(http.StatusOK)
	}))
	defer final.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- "redirector"
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer redirector.Close()

	notifier := New(context.Background(), nil, nil, slog.New(slog.DiscardHandler), nil)
	notifier.post(context.Background(), "master", "rp", redirector.URL, "signed.logout.token")

	close(reached)
	var visited []string
	for value := range reached {
		visited = append(visited, value)
	}
	// Following the redirect would forward a signed token to an address the
	// client never registered.
	if len(visited) != 1 || visited[0] != "redirector" {
		t.Fatalf("notifier followed a redirect: visited %v", visited)
	}
}

// shortenBackoff keeps the retry tests from spending the real waits, which
// would add ten seconds to every run for no extra coverage.
func shortenBackoff(t *testing.T) {
	t.Helper()
	original := retryBackoff
	retryBackoff = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { retryBackoff = original })
}

func TestPostRetriesWhenTheRelyingPartyIsMomentarilyDown(t *testing.T) {
	shortenBackoff(t)
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A relying party in the middle of a restart answers 503 before it
		// starts accepting again. One attempt used to lose the logout, leaving
		// a session open there that the user had already ended.
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := New(context.Background(), nil, nil, slog.New(slog.DiscardHandler), nil)
	notifier.post(context.Background(), "master", "rp", server.URL, "signed.logout.token")
	if got := attempts.Load(); got != 3 {
		t.Fatalf("delivery was attempted %d times, want 3", got)
	}
}

func TestPostDoesNotRetryARefusal(t *testing.T) {
	shortenBackoff(t)
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		// The relying party understood and declined; repeating changes nothing.
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	notifier := New(context.Background(), nil, nil, slog.New(slog.DiscardHandler), nil)
	notifier.post(context.Background(), "master", "rp", server.URL, "signed.logout.token")
	if got := attempts.Load(); got != 1 {
		t.Fatalf("a refusal was retried %d times", got)
	}
}

func TestPostStopsRetryingWhenTheContextEnds(t *testing.T) {
	shortenBackoff(t)
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	notifier := New(ctx, nil, nil, slog.New(slog.DiscardHandler), nil)
	cancel()
	// Shutdown must not be held up by a relying party that keeps failing.
	done := make(chan struct{})
	go func() { defer close(done); notifier.post(ctx, "master", "rp", server.URL, "signed.logout.token") }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("delivery kept retrying after its context ended")
	}
}

// A logout already on its way when the process is asked to stop must still
// arrive. Shutdown cancels the base context immediately, and deriving the
// request from it meant the delivery was abandoned mid-flight: the user had
// logged out, ReSSO had ended the session, and the relying party kept them
// signed in. Wait was written to give these a bounded moment and was waiting
// on work that had already been cancelled.
func TestDeliveryInFlightSurvivesShutdown(t *testing.T) {
	var delivered atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	base, cancel := context.WithCancel(context.Background())
	notifier := New(base, nil, nil, slog.New(slog.DiscardHandler), nil)
	cancel() // the signal arrives while a notification is in hand

	ctx, done := notifier.deliveryContext()
	defer done()
	notifier.post(ctx, "master", "rp", server.URL, "logout-token")

	if got := delivered.Load(); got != 1 {
		t.Errorf("deliveries that reached the relying party = %d, want 1", got)
	}
}

// Finishing the attempt in hand is not the same as starting new ones. A
// relying party that is down when the process is stopping must not hold the
// shutdown open for the length of the backoff.
func TestShutdownStopsFurtherRetries(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	base, cancel := context.WithCancel(context.Background())
	notifier := New(base, nil, nil, slog.New(slog.DiscardHandler), nil)
	cancel()

	ctx, done := notifier.deliveryContext()
	defer done()
	started := time.Now()
	notifier.post(ctx, "master", "rp", server.URL, "logout-token")

	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts during shutdown = %d, want 1", got)
	}
	if elapsed := time.Since(started); elapsed > retryBackoff[0] {
		t.Errorf("shutdown waited out a backoff: %s", elapsed)
	}
}

// A relying party in the middle of a restart usually accepts the connection and
// then says nothing, so the attempt ends on its timeout rather than a refusal.
// That is precisely the case the retry policy exists for, and it was the case
// the policy could not serve: one number was both the per-attempt timeout and
// the budget for the whole sequence, so a first attempt that stalled spent
// every retry it had coming and the logout was lost.
func TestAStalledFirstAttemptStillGetsItsRetries(t *testing.T) {
	shortenBackoff(t)
	originalTimeout := attemptTimeout
	attemptTimeout = 150 * time.Millisecond
	t.Cleanup(func() { attemptTimeout = originalTimeout })

	var attempts atomic.Int32
	released := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			select {
			case <-released:
			case <-r.Context().Done():
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer func() { close(released); server.Close() }()

	notifier := New(context.Background(), nil, nil, slog.New(slog.DiscardHandler), nil)
	notifier.client.Timeout = 0 // the per-attempt context is what has to bound this
	ctx, cancel := notifier.deliveryContext()
	defer cancel()
	notifier.post(ctx, "master", "rp", server.URL, "signed.logout.token")

	if got := attempts.Load(); got != 2 {
		t.Fatalf("delivery was attempted %d times, want 2: a stalled attempt must not consume the retries", got)
	}
}

// The budget for one notification has to be read off the retry policy. Fixing a
// number here and changing the policy there is how the two came apart before.
func TestDeliveryBudgetCoversEveryAttemptAndWait(t *testing.T) {
	required := time.Duration(len(retryBackoff)+1) * attemptTimeout
	for _, wait := range retryBackoff {
		required += wait
	}
	notifier := New(context.Background(), nil, nil, slog.New(slog.DiscardHandler), nil)
	ctx, cancel := notifier.deliveryContext()
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("a delivery context carries no deadline")
	}
	// The deadline is already ticking by the time it is read, so a moment of
	// slack keeps this measuring the policy rather than the clock.
	if granted := time.Until(deadline); granted < required-time.Second {
		t.Fatalf("a delivery is granted %s, want at least %s (%d attempts of %s plus the waits)",
			granted.Round(time.Second), required, len(retryBackoff)+1, attemptTimeout)
	}
}
