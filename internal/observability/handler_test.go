package observability

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// A handler that has been closed must still tolerate a record arriving.
//
// Shutdown is concurrent: the HTTP server stops, background workers are still
// unwinding, and the final "stopped" line is written from the main goroutine.
// Any of those can log after the mirror has been told to finish, and closing
// the queue underneath them turned an ordinary shutdown into a panic — one
// whose stack trace points at the logger rather than at anything the operator
// did. Nothing is guaranteed to be recorded at that point; not crashing is.
func TestHandlerToleratesRecordsAfterClose(t *testing.T) {
	metrics := NewRegistry()
	handler := NewDBHandler(slog.NewTextHandler(io.Discard, nil), nil, "test", metrics)
	handler.Close(time.Second)

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("logging after shutdown panicked: %v", recovered)
		}
	}()
	logger := slog.New(handler)
	for range 3 {
		logger.Info("emitted while shutting down")
	}

	// The records are counted as lost rather than silently disappearing.
	var exported strings.Builder
	metrics.WritePrometheus(&exported)
	if !strings.Contains(exported.String(), MetricLogRecords) {
		t.Errorf("no %s series was exported: %s", MetricLogRecords, exported.String())
	}
	if handler.Enabled(context.Background(), slog.LevelInfo) != true {
		t.Error("the handler stopped delegating Enabled after Close")
	}
}
