package mail

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Delivery is one attempt to send one mail to one person. It carries no body.
type Delivery struct {
	ID           uuid.UUID  `json:"id"`
	Event        string     `json:"event"`
	Recipient    string     `json:"recipient"`
	Subject      string     `json:"subject"`
	Reference    string     `json:"reference,omitempty"`
	ActorID      *uuid.UUID `json:"actor_id,omitempty"`
	Status       string     `json:"status"`
	Attempts     int        `json:"attempts"`
	ErrorMessage string     `json:"error_message,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Delivery statuses.
const (
	StatusQueued = "queued"
	StatusSent   = "sent"
	StatusFailed = "failed"
)

// Backend is what the service needs from storage: the settings, the one
// lookup that turns account identifiers into addresses — the account table
// this service already keeps, not a second one — and the delivery record.
type Backend interface {
	MailSettings(ctx context.Context) (map[string]any, error)
	MailAddresses(ctx context.Context, userIDs []uuid.UUID) (map[uuid.UUID]string, error)
	RecordMailDelivery(ctx context.Context, delivery Delivery) error
	CompleteMailDelivery(ctx context.Context, id uuid.UUID, status string, attempts int, errorMessage string) error
}

// Service sends notifications without holding the request that caused them.
type Service struct {
	backend Backend
	logger  *slog.Logger
	send    func(context.Context, Config, Message) error
	pending sync.WaitGroup
}

func NewService(backend Backend, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{backend: backend, logger: logger, send: Deliver}
}

// SetSender replaces the transport, which lets tests drive the service
// without a relay.
func (s *Service) SetSender(sender func(context.Context, Config, Message) error) { s.send = sender }

// Config reads the current configuration from the settings.
func (s *Service) Config(ctx context.Context) (Config, error) {
	values, err := s.backend.MailSettings(ctx)
	if err != nil {
		return Config{}, err
	}
	return Read(values), nil
}

// Notify sends one event to the accounts named, in the background. The actor
// is left out — nobody is told about their own action — and accounts without
// an address are skipped. Nothing here can fail the caller's request: a
// relay that is down, a settings table that cannot be read, all of it ends
// in the log and the delivery record.
func (s *Service) Notify(ctx context.Context, notification Notification, actorID uuid.UUID, recipients []uuid.UUID) {
	config, err := s.Config(ctx)
	if err != nil {
		s.logger.Warn("mail settings could not be read; notification not sent", "event", notification.Event, "error", err)
		return
	}
	if !config.Enabled || !config.Allows(notification.Event) {
		return
	}
	addresses := s.resolve(ctx, recipients, actorID)
	if len(addresses) == 0 {
		return
	}
	body := notification.Render(config)
	var actor *uuid.UUID
	if actorID != uuid.Nil {
		actor = &actorID
	}
	for _, address := range addresses {
		delivery := s.record(ctx, notification, address, actor)
		s.pending.Add(1)
		go func(delivery Delivery, message Message) {
			defer s.pending.Done()
			s.deliver(delivery, config, message)
		}(delivery, Message{To: address, Subject: notification.Subject, Body: body})
	}
}

// SendNow delivers immediately and reports the outcome, which is what the
// administrator's test button needs. The attempt is recorded like any other.
func (s *Service) SendNow(ctx context.Context, notification Notification, actorID uuid.UUID, recipient string) error {
	config, err := s.Config(ctx)
	if err != nil {
		return err
	}
	if !config.Enabled {
		return ErrDisabled
	}
	var actor *uuid.UUID
	if actorID != uuid.Nil {
		actor = &actorID
	}
	delivery := s.record(ctx, notification, recipient, actor)
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), config.Timeout+5*time.Second)
	defer cancel()
	err = s.send(sendCtx, config, Message{To: recipient, Subject: notification.Subject, Body: notification.Render(config)})
	s.complete(sendCtx, delivery, 1, err)
	return err
}

// Wait blocks until every background delivery has finished or the timeout
// passes, so a restart does not lose the mail it had just queued.
func (s *Service) Wait(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.pending.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// deliver retries once: a relay that briefly refuses a connection is common,
// and losing the notification is worse than a short wait.
func (s *Service) deliver(delivery Delivery, config Config, message Message) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*config.Timeout+15*time.Second)
	defer cancel()
	var err error
	attempts := 0
	for attempts < 2 {
		attempts++
		if err = s.send(ctx, config, message); err == nil {
			break
		}
		if attempts == 1 {
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}
	s.complete(ctx, delivery, attempts, err)
}

func (s *Service) record(ctx context.Context, notification Notification, recipient string, actor *uuid.UUID) Delivery {
	now := time.Now().UTC()
	delivery := Delivery{ID: uuid.New(), Event: notification.Event, Recipient: recipient, Subject: trim(notification.Subject, 300),
		Reference: notification.Reference, ActorID: actor, Status: StatusQueued, CreatedAt: now, UpdatedAt: now}
	if err := s.backend.RecordMailDelivery(ctx, delivery); err != nil {
		s.logger.Warn("mail delivery was not recorded", "event", delivery.Event, "recipient", delivery.Recipient, "error", err)
	}
	return delivery
}

func (s *Service) complete(ctx context.Context, delivery Delivery, attempts int, cause error) {
	status, message := StatusSent, ""
	if cause != nil {
		status, message = StatusFailed, trim(cause.Error(), 1000)
		s.logger.Warn("notification mail failed", "event", delivery.Event, "recipient", delivery.Recipient, "attempts", attempts, "error", cause)
	}
	if err := s.backend.CompleteMailDelivery(ctx, delivery.ID, status, attempts, message); err != nil {
		s.logger.Warn("mail delivery outcome was not recorded", "event", delivery.Event, "recipient", delivery.Recipient, "error", err)
	}
}

// resolve turns account identifiers into unique addresses, dropping the actor.
func (s *Service) resolve(ctx context.Context, recipients []uuid.UUID, actorID uuid.UUID) []string {
	wanted := make([]uuid.UUID, 0, len(recipients))
	seenID := map[uuid.UUID]struct{}{}
	for _, recipient := range recipients {
		if recipient == uuid.Nil || recipient == actorID {
			continue
		}
		if _, duplicate := seenID[recipient]; duplicate {
			continue
		}
		seenID[recipient] = struct{}{}
		wanted = append(wanted, recipient)
	}
	if len(wanted) == 0 {
		return nil
	}
	emails, err := s.backend.MailAddresses(ctx, wanted)
	if err != nil {
		s.logger.Warn("mail recipients were not resolved", "error", err)
		return nil
	}
	seen, addresses := map[string]struct{}{}, make([]string, 0, len(wanted))
	for _, recipient := range wanted {
		address := strings.TrimSpace(emails[recipient])
		if address == "" {
			continue
		}
		key := strings.ToLower(address)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		addresses = append(addresses, address)
	}
	return addresses
}

func trim(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
