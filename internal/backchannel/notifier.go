// Package backchannel delivers OpenID Connect Back-Channel Logout 1.0
// notifications to relying parties.
//
// Until now clients could register a back-channel logout URI in the
// administration console and it was stored but never used, so administrators
// believed relying parties were told about logouts when they were not. This
// package closes that gap. It lives outside internal/store so that the data
// layer performs no outbound requests and no token signing.
package backchannel

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hkjang/ReSSO/internal/observability"
	"github.com/hkjang/ReSSO/internal/oidc"
	"github.com/hkjang/ReSSO/internal/store"
)

// MetricName is the counter this package reports delivery outcomes on. It is
// registered by the HTTP layer, which owns the registry.
const MetricName = "resso_backchannel_logout_total"

const (
	deliveryTimeout    = 10 * time.Second
	maximumConcurrency = 8
	// A revocation burst (an administrator disabling an account with many
	// sessions) must not queue unbounded work. Excess notifications are
	// dropped with a warning rather than growing the heap without limit.
	maximumQueueDepth = 512
)

// Notifier posts logout tokens to the relying parties that took part in a
// session. Delivery is best effort: a relying party that is unreachable is
// logged, never retried indefinitely, and never allowed to delay the user's
// own logout response.
type Notifier struct {
	store   *store.Store
	oidc    *oidc.Service
	logger  *slog.Logger
	client  *http.Client
	base    context.Context
	slots   chan struct{}
	pending sync.WaitGroup
	metrics *observability.Registry
}

// New returns a Notifier whose in-flight deliveries are cancelled when ctx is
// done, so shutdown does not wait on an unresponsive relying party.
func New(ctx context.Context, data *store.Store, service *oidc.Service, logger *slog.Logger,
	metrics *observability.Registry) *Notifier {
	return &Notifier{
		store:  data,
		oidc:   service,
		logger: logger,
		client: &http.Client{
			Timeout: deliveryTimeout,
			// Logout endpoints answer directly; following a redirect would
			// forward a signed token to an address the client never registered.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		base:    ctx,
		slots:   make(chan struct{}, maximumQueueDepth),
		metrics: metrics,
	}
}

func (n *Notifier) record(result string) {
	if n.metrics != nil {
		n.metrics.Add(MetricName, 1, result)
	}
}

// SessionRevoked implements store.SessionRevocationHook. It returns
// immediately; delivery continues in the background.
func (n *Notifier) SessionRevoked(revoked store.RevokedSession) {
	select {
	case n.slots <- struct{}{}:
	default:
		n.logger.Warn("back-channel logout notification dropped: queue is full",
			"realm_id", revoked.RealmID, "session_id", revoked.SessionID)
		n.record("dropped")
		return
	}
	n.pending.Add(1)
	go func() {
		defer n.pending.Done()
		defer func() { <-n.slots }()
		n.deliver(revoked)
	}()
}

// Wait blocks until in-flight deliveries finish or the deadline passes. It is
// called during shutdown so that a logout in progress is not lost silently.
func (n *Notifier) Wait(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		n.pending.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		n.logger.Warn("back-channel logout deliveries did not finish before shutdown")
	}
}

func (n *Notifier) deliver(revoked store.RevokedSession) {
	ctx, cancel := context.WithTimeout(n.base, deliveryTimeout)
	defer cancel()
	realm, err := n.store.RealmByID(ctx, revoked.RealmID)
	if err != nil {
		n.logger.Warn("back-channel logout skipped: Realm is unavailable",
			"realm_id", revoked.RealmID, "error", err)
		return
	}
	targets, err := n.store.BackchannelLogoutTargets(ctx, revoked.RealmID, revoked.SessionID)
	if err != nil {
		n.logger.Warn("back-channel logout target lookup failed",
			"realm_id", revoked.RealmID, "session_id", revoked.SessionID, "error", err)
		return
	}
	if len(targets) == 0 {
		return
	}
	gate := make(chan struct{}, maximumConcurrency)
	var group sync.WaitGroup
	for _, client := range targets {
		token, tokenErr := n.oidc.IssueLogoutToken(ctx, realm, client, revoked.SessionID, revoked.UserID)
		if tokenErr != nil {
			n.logger.Error("back-channel logout token could not be signed",
				"realm", realm.Name, "client", client.ClientID, "error", tokenErr)
			continue
		}
		group.Add(1)
		gate <- struct{}{}
		go func() {
			defer group.Done()
			defer func() { <-gate }()
			n.post(ctx, realm.Name, client.ClientID, client.BackchannelLogoutURI, token)
		}()
	}
	group.Wait()
}

// deliveryAttempts and retryBackoff bound how hard a single notification
// tries. One attempt lost the notification whenever the relying party happened
// to be restarting, leaving a session open there that the user had ended here.
// Retrying is only useful for failures that can clear on their own, so a
// refusal by the relying party is taken at its word.
var retryBackoff = []time.Duration{2 * time.Second, 8 * time.Second}

func (n *Notifier) post(ctx context.Context, realmName, clientID, endpoint, token string) {
	for attempt := 0; ; attempt++ {
		outcome, retryable := n.attempt(ctx, realmName, clientID, endpoint, token)
		if !retryable || attempt >= len(retryBackoff) {
			n.record(outcome)
			if outcome != "delivered" {
				n.logger.Warn("back-channel logout was not delivered",
					"realm", realmName, "client", clientID, "outcome", outcome, "attempts", attempt+1)
			}
			return
		}
		timer := time.NewTimer(retryBackoff[attempt])
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			n.record(outcome)
			return
		}
		timer.Stop()
	}
}

// attempt performs one delivery and reports its outcome and whether another
// try could plausibly succeed.
func (n *Notifier) attempt(ctx context.Context, realmName, clientID, endpoint, token string) (string, bool) {
	body := strings.NewReader(url.Values{"logout_token": {token}}.Encode())
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		n.logger.Error("back-channel logout request could not be built",
			"realm", realmName, "client", clientID, "error", err)
		return "failed", false
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Cache-Control", "no-store")
	response, err := n.client.Do(request)
	if err != nil {
		// Unreachable, refused or timed out: the relying party may be
		// restarting, so another attempt is worth making.
		n.logger.Warn("back-channel logout delivery failed",
			"realm", realmName, "client", clientID, "error", err)
		return "failed", ctx.Err() == nil
	}
	defer func() { _ = response.Body.Close() }()
	switch {
	case response.StatusCode >= 200 && response.StatusCode <= 299:
		n.logger.Info("back-channel logout delivered", "realm", realmName, "client", clientID)
		return "delivered", false
	case response.StatusCode >= 500 || response.StatusCode == http.StatusTooManyRequests:
		n.logger.Warn("back-channel logout was refused for now",
			"realm", realmName, "client", clientID, "status", response.StatusCode)
		return "failed", ctx.Err() == nil
	default:
		// The relying party understood and declined; repeating it changes
		// nothing.
		n.logger.Warn("back-channel logout was rejected by the relying party",
			"realm", realmName, "client", clientID, "status", response.StatusCode)
		return "rejected", false
	}
}
