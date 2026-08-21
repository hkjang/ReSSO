package observability

import (
	"strings"
	"sync"
	"testing"
)

func render(t *testing.T, registry *Registry) string {
	t.Helper()
	var builder strings.Builder
	registry.WritePrometheus(&builder)
	return builder.String()
}

func TestRegistryRendersCountersWithLabels(t *testing.T) {
	registry := NewRegistry()
	registry.Counter("resso_http_requests_total", "Requests.", "method", "status")
	registry.Add("resso_http_requests_total", 1, "GET", "200")
	registry.Add("resso_http_requests_total", 2, "GET", "200")
	registry.Add("resso_http_requests_total", 1, "POST", "401")

	output := render(t, registry)
	for _, want := range []string{
		"# TYPE resso_http_requests_total counter",
		`resso_http_requests_total{method="GET",status="200"} 3`,
		`resso_http_requests_total{method="POST",status="401"} 1`,
		"resso_uptime_seconds ",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestRegistryRendersCumulativeHistogramBuckets(t *testing.T) {
	registry := NewRegistry()
	registry.Histogram("resso_latency_seconds", "Latency.", []float64{0.1, 1}, "route")
	registry.Observe("resso_latency_seconds", 0.05, "token")
	registry.Observe("resso_latency_seconds", 0.5, "token")
	registry.Observe("resso_latency_seconds", 5, "token")

	output := render(t, registry)
	for _, want := range []string{
		"# TYPE resso_latency_seconds histogram",
		`resso_latency_seconds_bucket{route="token",le="0.1"} 1`,
		`resso_latency_seconds_bucket{route="token",le="1"} 2`,
		`resso_latency_seconds_bucket{route="token",le="+Inf"} 3`,
		`resso_latency_seconds_count{route="token"} 3`,
		`resso_latency_seconds_sum{route="token"} 5.55`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestRegistryIgnoresUnregisteredSeries(t *testing.T) {
	registry := NewRegistry()
	// A missing registration must never panic on a request path.
	registry.Add("resso_absent_total", 1, "value")
	registry.Observe("resso_absent_seconds", 1, "value")
	if output := render(t, registry); strings.Contains(output, "resso_absent") {
		t.Fatalf("unregistered series were rendered:\n%s", output)
	}
}

func TestRegistryEscapesLabelValues(t *testing.T) {
	registry := NewRegistry()
	registry.Counter("resso_escaped_total", "Escaping.", "path")
	registry.Add("resso_escaped_total", 1, `a"b\c`)
	if want := `resso_escaped_total{path="a\"b\\c"} 1`; !strings.Contains(render(t, registry), want) {
		t.Fatalf("output missing %q:\n%s", want, render(t, registry))
	}
}

func TestRegistryIsSafeForConcurrentUse(t *testing.T) {
	registry := NewRegistry()
	registry.Counter("resso_concurrent_total", "Concurrent.", "worker")
	registry.Histogram("resso_concurrent_seconds", "Concurrent.", DefaultLatencyBounds, "worker")
	var wait sync.WaitGroup
	for worker := range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			label := string(rune('a' + worker))
			for range 200 {
				registry.Add("resso_concurrent_total", 1, label)
				registry.Observe("resso_concurrent_seconds", 0.01, label)
			}
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		for range 50 {
			render(t, registry)
		}
	}()
	wait.Wait()

	output := render(t, registry)
	for worker := range 8 {
		want := `resso_concurrent_total{worker="` + string(rune('a'+worker)) + `"} 200`
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
