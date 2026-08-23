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

// The mirror keeps thirty days of records that a platform administrator reads
// from the console, so what it declines to write down is a security control
// with no other enforcement. It had no test, and two things were wrong.
//
// The words it looked for did not include what this service calls its own
// secrets: bind_credential is the LDAP password it encrypts at rest and
// api_key is what it issues to people, and an attribute named after either was
// mirrored in full. Nothing logs one today — the point of a redactor is the
// line somebody adds tomorrow.
func TestMirrorWithholdsAnythingNamedLikeACredential(t *testing.T) {
	handler := &DBHandler{}
	for _, name := range []string{
		"password", "current_password", "client_secret", "refresh_token",
		"Authorization", "api_key", "key", "bind_credential", "CREDENTIAL",
	} {
		target := map[string]any{}
		handler.addAttr(target, slog.String(name, "the value itself"))
		if target[name] != "[REDACTED]" {
			t.Errorf("an attribute named %q was written down as %v", name, target[name])
		}
	}
	// And it has to keep writing down everything else, or the log is useless.
	for _, name := range []string{"trace_id", "realm", "client", "user_id", "read", "failed"} {
		target := map[string]any{}
		handler.addAttr(target, slog.String(name, "ordinary"))
		if target[name] != "ordinary" {
			t.Errorf("an attribute named %q was withheld: %v", name, target[name])
		}
	}
}

// A group's children were recorded under their own key alone, so two groups
// with a child of the same name wrote to the same place and the second
// silently replaced the first — a record accepted and then partly discarded.
func TestMirrorKeepsGroupedAttributesApart(t *testing.T) {
	handler := &DBHandler{}
	target := map[string]any{}
	handler.addAttr(target, slog.Group("before", slog.String("value", "old")))
	handler.addAttr(target, slog.Group("after", slog.String("value", "new")))
	if target["before.value"] != "old" || target["after.value"] != "new" {
		t.Errorf("grouped attributes did not survive alongside each other: %v", target)
	}

	// A group named for a secret is withheld whole, without descending into it.
	withheld := map[string]any{}
	handler.addAttr(withheld, slog.Group("secret", slog.String("value", "material")))
	if withheld["secret"] != "[REDACTED]" || len(withheld) != 1 {
		t.Errorf("a group named for a secret was not withheld whole: %v", withheld)
	}

	// And a sensitive name nested under an ordinary group is caught by its path.
	nested := map[string]any{}
	handler.addAttr(nested, slog.Group("request", slog.String("api_key", "ak_live")))
	if nested["request.api_key"] != "[REDACTED]" {
		t.Errorf("a nested credential was written down: %v", nested)
	}
}
