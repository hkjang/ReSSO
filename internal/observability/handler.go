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

// MetricLogRecords counts what became of each record the mirror accepted.
// Both loss paths were silent: a full queue dropped records and a failed
// write discarded a whole batch, so the administration log simply had gaps
// with nothing to say why.
const MetricLogRecords = "resso_system_log_records_total"

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
	metrics   *Registry
	done      chan struct{}
	// closing is signalled instead of closing the queue. Records can still
	// arrive while the process unwinds — background workers finishing, the
	// final line from the main goroutine — and a send on a closed channel
	// panics no matter what the sender does about it.
	closing   chan struct{}
	closeOnce *sync.Once
}

// NewDBHandler mirrors records into PostgreSQL. The registry is optional; when
// present the handler reports what happened to each record.
func NewDBHandler(next slog.Handler, data *store.Store, component string, metrics *Registry) *DBHandler {
	if metrics != nil {
		metrics.Counter(MetricLogRecords, "Structured log records mirrored to the database, by outcome.", "result")
	}
	h := &DBHandler{next: next, store: data, queue: make(chan store.SystemLogEntry, queueDepth),
		component: component, once: &sync.Once{}, metrics: metrics, done: make(chan struct{}),
		closing: make(chan struct{}), closeOnce: &sync.Once{}}
	h.once.Do(func() { go h.run() })
	return h
}

func (h *DBHandler) record(result string, count int) {
	if h.metrics != nil && count > 0 {
		h.metrics.Add(MetricLogRecords, int64(count), result)
	}
}

// Close stops accepting records and waits for the buffered ones to be written,
// so a shutdown does not discard the last few seconds of the log.
func (h *DBHandler) Close(timeout time.Duration) {
	h.closeOnce.Do(func() { close(h.closing) })
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-h.done:
	case <-timer.C:
	}
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
	case <-h.closing:
		// The writer has finished; console logging still carries this line.
		h.record("dropped", 1)
	case h.queue <- item:
	default:
		// The database cannot keep up. Console logging is unaffected, but the
		// administration log will have a gap, so say so in the metrics.
		h.record("dropped", 1)
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
	defer close(h.done)
	batch := make([]store.SystemLogEntry, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		err := h.store.WriteSystemLogs(ctx, batch)
		cancel()
		if err != nil {
			h.record("failed", len(batch))
		} else {
			h.record("written", len(batch))
		}
		batch = batch[:0]
	}
	for {
		select {
		case item := <-h.queue:
			batch = append(batch, item)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-h.closing:
			// Take whatever is already queued, then stop. Anything arriving
			// after this point is counted as dropped by the sender.
			for {
				select {
				case item := <-h.queue:
					batch = append(batch, item)
					if len(batch) >= batchSize {
						flush()
					}
					continue
				default:
				}
				break
			}
			flush()
			return
		}
	}
}
