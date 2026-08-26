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
			Timeout: attemptTimeout,
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
		// Nothing was even attempted here, which is the version of this worth
		// hearing about most. Recorded on its own goroutine because this
		// function must return without waiting on anything — a logout response
		// is on the other end of it — and tracked so shutdown does not drop
		// the record of the drop.
		n.pending.Add(1)
		go func() {
			defer n.pending.Done()
			n.recordNotDelivered(revoked, "", "session", revoked.SessionID.String(), "dropped", 0)
		}()
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

// deliveryBudget is what one notification may spend in total: every attempt at
// its full timeout, plus the waits between them.
//
// Sizing it from the retry policy rather than picking a number is the point.
// One number used to serve as both the per-attempt timeout and the budget for
// the whole sequence, so the retries the policy describes could not all run:
// two attempts and the second backoff exactly exhausted it, the third never
// happened, and the last eight seconds were spent waiting for a retry that had
// already been ruled out. A relying party that accepts the connection and then
// stalls — which is what restarting usually looks like — spent the entire
// budget on the first attempt and got no retry at all, the very case the retry
// was written for.
func deliveryBudget() time.Duration {
	total := time.Duration(len(retryBackoff)+1) * attemptTimeout
	for _, wait := range retryBackoff {
		total += wait
	}
	return total
}

// deliveryContext bounds one notification.
//
// It deliberately outlives cancellation of the base context. Shutdown cancels
// that the instant the signal arrives, which meant a delivery already under
// way was abandoned mid-request — the user had logged out, ReSSO had ended the
// session, and the relying party was never told, leaving them signed in there.
// Wait exists to give exactly these deliveries a bounded moment to finish, and
// it was waiting on work that had already given up. Shutdown still stops the
// sequence after the attempt in hand, so what Wait actually has to cover is one
// attempt — not this whole budget.
func (n *Notifier) deliveryContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(n.base), deliveryBudget())
}

func (n *Notifier) deliver(revoked store.RevokedSession) {
	ctx, cancel := n.deliveryContext()
	defer cancel()
	// The lookups are not deliveries and get one attempt's worth of time; a
	// database that is slow to answer must not spend the budget the relying
	// parties are waiting on.
	lookupCtx, cancelLookup := context.WithTimeout(ctx, attemptTimeout)
	defer cancelLookup()
	realm, err := n.store.RealmByID(lookupCtx, revoked.RealmID)
	if err != nil {
		n.logger.Warn("back-channel logout skipped: Realm is unavailable",
			"realm_id", revoked.RealmID, "error", err)
		n.recordNotDelivered(revoked, "", "session", revoked.SessionID.String(), "realm_unavailable", 0)
		return
	}
	targets, err := n.store.BackchannelLogoutTargets(lookupCtx, revoked.RealmID, revoked.SessionID)
	if err != nil {
		n.logger.Warn("back-channel logout target lookup failed",
			"realm_id", revoked.RealmID, "session_id", revoked.SessionID, "error", err)
		n.recordNotDelivered(revoked, realm.Name, "session", revoked.SessionID.String(), "targets_unknown", 0)
		return
	}
	if len(targets) == 0 {
		return
	}
	cancelLookup()
	gate := make(chan struct{}, maximumConcurrency)
	var group sync.WaitGroup
	for _, client := range targets {
		token, tokenErr := n.oidc.IssueLogoutToken(ctx, realm, client, revoked.SessionID, revoked.UserID)
		if tokenErr != nil {
			n.logger.Error("back-channel logout token could not be signed",
				"realm", realm.Name, "client", client.ClientID, "error", tokenErr)
			n.recordNotDelivered(revoked, realm.Name, "client", client.ClientID, "token_unsigned", 0)
			continue
		}
		group.Add(1)
		gate <- struct{}{}
		go func() {
			defer group.Done()
			defer func() { <-gate }()
			n.post(ctx, revoked, realm.Name, client.ClientID, client.BackchannelLogoutURI, token)
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

// attemptTimeout bounds one delivery attempt. It is a variable so the tests can
// drive the same knob the retry policy is sized from.
var attemptTimeout = 10 * time.Second

func (n *Notifier) post(ctx context.Context, revoked store.RevokedSession, realmName, clientID, endpoint, token string) {
	for attempt := 0; ; attempt++ {
		outcome, retryable := n.attempt(ctx, realmName, clientID, endpoint, token)
		if !retryable || attempt >= len(retryBackoff) {
			n.record(outcome)
			if outcome != "delivered" {
				n.logger.Warn("back-channel logout was not delivered",
					"realm", realmName, "client", clientID, "outcome", outcome, "attempts", attempt+1)
				n.recordNotDelivered(revoked, realmName, "client", clientID, outcome, attempt+1)
			}
			return
		}
		timer := time.NewTimer(retryBackoff[attempt])
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			n.record(outcome)
			n.recordNotDelivered(revoked, realmName, "client", clientID, outcome, attempt+1)
			return
		case <-n.base.Done():
			// Shutting down: the attempt in hand was allowed to finish, but
			// waiting out a backoff would outlast the process.
			timer.Stop()
			n.record(outcome)
			n.recordNotDelivered(revoked, realmName, "client", clientID, outcome, attempt+1)
			return
		}
		timer.Stop()
	}
}

// recordNotDelivered puts a delivery that never landed in the audit trail.
//
// The console reports the session ended the moment the row is revoked, and
// this runs afterwards, so its failure is visible nowhere the operator is
// looking. What is left open is a session at a relying party that the user
// believes they closed — and "was that session actually ended everywhere" is
// asked long after a log line has rotated away. Audit events are kept for the
// retention period, which is the same reason the federation sync records its
// outcome there rather than only in the log.
//
// Only failures are written. A delivery that worked is the ordinary case and
// recording every one would bury the ones worth reading.
func (n *Notifier) recordNotDelivered(revoked store.RevokedSession, realmName, targetType, targetID, outcome string, attempts int) {
	if n.store == nil {
		return
	}
	// The delivery's own budget is spent by now, and at shutdown the base
	// context is going away: this write has to outlive both or the record it
	// exists to leave would be the thing that goes missing.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(n.base), attemptTimeout)
	defer cancel()
	realmID := revoked.RealmID
	// The actor is this service, not the person whose session ended - they
	// asked for the logout and it is the delivery that fell short. Naming them
	// as the actor would also tie the record to a users row, and an event kept
	// to answer a question years later should not depend on one.
	if err := n.store.WriteAudit(ctx, store.AuditEvent{
		RealmID: &realmID, ActorName: "system",
		EventType: "BACKCHANNEL_LOGOUT", Result: "FAILURE",
		TargetType: targetType, TargetID: targetID,
		Detail: map[string]any{"session_id": revoked.SessionID.String(),
			"user_id": revoked.UserID.String(), "outcome": outcome, "attempts": attempts},
	}); err != nil {
		n.logger.Error("back-channel logout failure could not be recorded",
			"realm", realmName, "target", targetID, "error", err)
	}
}

// attempt performs one delivery and reports its outcome and whether another
// try could plausibly succeed.
func (n *Notifier) attempt(ctx context.Context, realmName, clientID, endpoint, token string) (string, bool) {
	// Each attempt gets its own deadline. Sharing the sequence's deadline let a
	// single stalled relying party consume every retry it had coming.
	attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	body := strings.NewReader(url.Values{"logout_token": {token}}.Encode())
	request, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, endpoint, body)
	if err != nil {
		n.logger.Error("back-channel logout request could not be built",
			"realm", realmName, "client", clientID, "error", err)
		return "failed", false
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Cache-Control", "no-store")
	// Retryability is decided by the sequence's context, not this attempt's:
	// an attempt that ran out of time is exactly the case worth repeating.
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
