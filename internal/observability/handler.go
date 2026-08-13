package observability

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/hkjang/ReSSO/internal/store"
)

type logItem struct {
	level, component, message, traceID string
	attributes                         map[string]any
}

// DBHandler mirrors structured logs to a bounded asynchronous queue. When
// PostgreSQL is unavailable, console logging remains functional and request
// processing never blocks on the administration log viewer.
type DBHandler struct {
	next      slog.Handler
	store     *store.Store
	queue     chan logItem
	attrs     []slog.Attr
	groups    []string
	component string
	once      *sync.Once
}

func NewDBHandler(next slog.Handler, data *store.Store, component string) *DBHandler {
	h := &DBHandler{next: next, store: data, queue: make(chan logItem, 2048), component: component, once: &sync.Once{}}
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
	item := logItem{level: strings.ToUpper(record.Level.String()), component: h.component,
		message: record.Message, traceID: traceID, attributes: attrs}
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

func (h *DBHandler) run() {
	for item := range h.queue {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = h.store.WriteSystemLog(ctx, item.level, item.component, item.message, item.traceID, item.attributes)
		cancel()
	}
}
