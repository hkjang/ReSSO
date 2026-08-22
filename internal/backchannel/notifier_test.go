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
