package httpserver

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hkjang/ReSSO/internal/observability"
)

// The operations guide's table of signals tells an operator which audit events
// to filter for. A name in it that the service never writes returns an empty
// list, and during an investigation an empty list reads as "it did not happen"
// rather than "you asked for something that does not exist". That had already
// happened once: the guide named USER_PASSWORD_RESET where the service writes
// PASSWORD_RESET.
//
// So the table is checked against the literals the handlers actually pass. The
// direction is deliberately one-way — the table is a selection of what is worth
// watching, not a catalogue, so an event the service writes and the guide
// leaves out is not a fault.
func TestOperationsGuideNamesEventsTheServiceWrites(t *testing.T) {
	root := filepath.Join("..", "..")
	guide, err := os.ReadFile(filepath.Join(root, "docs", "operations.md"))
	if err != nil {
		t.Fatal(err)
	}
	table := signalsTable(string(guide))
	if table == "" {
		t.Fatal("the operations guide no longer has a table of audit signals to check")
	}
	documented := documentedEventNames(table)
	if len(documented) == 0 {
		t.Fatal("no event names were found in the signals table")
	}

	written := auditEventLiterals(t, root)
	for _, name := range documented {
		if !written[name] {
			t.Errorf("the operations guide tells an operator to filter for %q, "+
				"which nothing in the service writes", name)
		}
	}
}

// documentedEventNames reads the event named by each row, which is the first
// backticked value in its first cell. The rest of a row is prose and mentions
// policy values and results in the same style — and a row keyed on a result
// rather than an event, like `result=PARTIAL`, names no event at all.
func documentedEventNames(table string) []string {
	pattern := regexp.MustCompile("`([A-Z][A-Z_]{4,})`")
	names := make([]string, 0)
	for _, line := range strings.Split(table, "\n") {
		cells := strings.Split(strings.Trim(line, "| "), "|")
		if len(cells) < 2 {
			continue
		}
		if match := pattern.FindStringSubmatch(cells[0]); match != nil {
			names = append(names, match[1])
		}
	}
	return names
}

// signalsTable returns the markdown table that follows the sentence
// introducing the audit signals, and nothing else in the document.
func signalsTable(guide string) string {
	const heading = "| 이벤트 | 의미 |"
	start := strings.Index(guide, heading)
	if start < 0 {
		return ""
	}
	rest := guide[start:]
	if end := strings.Index(rest, "\n\n"); end >= 0 {
		return rest[:end]
	}
	return rest
}

// auditEventLiterals collects the event names the service writes. There are
// two ways it writes one — the Server.audit helper, where the name is the fifth
// argument, and a store.AuditEvent built directly — and both have to be read,
// because a pattern that only knew the first missed LDAP_FEDERATION_SYNC and
// one that also demanded a literal result missed MCP_TOOL_CALL, whose outcome
// is a variable.
func auditEventLiterals(t *testing.T, root string) map[string]bool {
	t.Helper()
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`s\.audit\((?:[^,()]*,){4}\s*"([A-Z][A-Z_]{4,})"`),
		regexp.MustCompile(`EventType:\s*"([A-Z][A-Z_]{4,})"`),
	}
	events := map[string]bool{}
	for _, dir := range []string{"internal", "cmd"} {
		walkErr := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			source, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			for _, pattern := range patterns {
				for _, match := range pattern.FindAllStringSubmatch(string(source), -1) {
					events[match[1]] = true
				}
			}
			return nil
		})
		if walkErr != nil {
			t.Fatal(walkErr)
		}
	}
	if len(events) == 0 {
		t.Fatal("no audit event literals were found; the patterns no longer match how they are written")
	}
	return events
}

// The README publishes the metric list as what an operator points Prometheus
// at, and an entry that no longer exists is a dashboard panel that stays empty
// while looking configured. The check runs both ways here, unlike the audit
// table above: that one is a selection of signals worth watching, this one
// claims to be the list.
func TestReadmeListsTheMetricsTheServiceExposes(t *testing.T) {
	root := filepath.Join("..", "..")
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, match := range regexp.MustCompile("`(resso_[a-z_]+)`").FindAllStringSubmatch(string(readme), -1) {
		documented[match[1]] = true
	}
	if len(documented) == 0 {
		t.Fatal("the README no longer names any metric")
	}

	// The registry a running instance serves from, including the series the
	// log mirror registers — it is created in main with this same registry, so
	// leaving it out would understate what /metrics carries.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := New(nil, logger, nil, nil)
	observability.NewDBHandler(slog.NewTextHandler(io.Discard, nil), nil, "resso", server.metrics)
	var exposition strings.Builder
	server.metrics.WritePrometheus(&exposition)
	exposed := map[string]bool{}
	for _, line := range strings.Split(exposition.String(), "\n") {
		if after, found := strings.CutPrefix(line, "# TYPE "); found {
			exposed[strings.Fields(after)[0]] = true
		}
	}

	for name := range exposed {
		if !documented[name] {
			t.Errorf("/metrics serves %s, which the README does not list", name)
		}
	}
	for name := range documented {
		if !exposed[name] {
			t.Errorf("the README lists %s, which nothing serves", name)
		}
	}
}
