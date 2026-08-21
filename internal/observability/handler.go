// Package observability mirrors structured logs into PostgreSQL for the
// administration console and exposes ReSSO's Prometheus metrics.
package observability

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/hkjang/ReSSO/internal/store"
)

const (
	queueDepth    = 2048
	batchSize     = 128
	flushInterval = 200 * time.Millisecond
	writeTimeout  = 5 * time.Second
)

// DBHandler mirrors structured logs to a bounded asynchronous queue. When
// PostgreSQL is unavailable, console logging remains functional and request
// processing never blocks on the administration log viewer.
type DBHandler struct {
	next      slog.Handler
	store     *store.Store
	queue     chan store.SystemLogEntry
	attrs     []slog.Attr
	groups    []string
	component string
	once      *sync.Once
}

func NewDBHandler(next slog.Handler, data *store.Store, component string) *DBHandler {
	h := &DBHandler{next: next, store: data, queue: make(chan store.SystemLogEntry, queueDepth),
		component: component, once: &sync.Once{}}
	h.once.Do(func() { go h.run() })
	return h
}

func (h *DBHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *DBHandler) Handle(ctx context.Context, record slog.Record) error {
	err := h.next.Handle(ctx, record)
	attrs := make(map[string]any, len(h.attrs)+record.NumAttrs())
	for _, attr := range h.attrs {
		h.addAttr(attrs, attr)
	}
	record.Attrs(func(attr slog.Attr) bool { h.addAttr(attrs, attr); return true })
	traceID, _ := attrs["trace_id"].(string)
	delete(attrs, "trace_id")
	occurredAt := record.Time
	if occurredAt.IsZero() {
		occurredAt = time.Now()
	}
	item := store.SystemLogEntry{OccurredAt: occurredAt.UTC(), Level: strings.ToUpper(record.Level.String()),
		Component: h.component, Message: record.Message, TraceID: traceID, Attributes: attrs}
	select {
	case h.queue <- item:
	default:
	}
	return err
}

func (h *DBHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &clone
}

func (h *DBHandler) WithGroup(name string) slog.Handler {
	clone := *h
	clone.groups = append(append([]string{}, h.groups...), name)
	return &clone
}

func (h *DBHandler) addAttr(target map[string]any, attr slog.Attr) {
	attr.Value = attr.Value.Resolve()
	key := strings.Join(append(h.groups, attr.Key), ".")
	lower := strings.ToLower(key)
	if strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "authorization") {
		target[key] = "[REDACTED]"
		return
	}
	if attr.Value.Kind() == slog.KindGroup {
		for _, child := range attr.Value.Group() {
			h.addAttr(target, child)
		}
		return
	}
	target[key] = attr.Value.Any()
}

// run drains the queue in batches. Each HTTP request produces a log record, so
// a statement per record made the administration log the busiest writer in the
// database; a batch turns a burst into one round trip. The timestamp travels
// with the record, so buffering does not distort the recorded order.
func (h *DBHandler) run() {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	batch := make([]store.SystemLogEntry, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		_ = h.store.WriteSystemLogs(ctx, batch)
		cancel()
		batch = batch[:0]
	}
	for {
		select {
		case item, ok := <-h.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, item)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
