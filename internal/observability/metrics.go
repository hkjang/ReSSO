package observability

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Registry is a minimal Prometheus text-format exposition.
//
// ReSSO ships as a single offline binary, so this deliberately avoids pulling
// in a client library for the handful of series that matter operationally:
// request rate and latency, token issuance, authentication outcomes and
// federation sync results. Without it the only window into a running service
// was the administration log viewer, which cannot answer "is the login failure
// rate rising" or "how long is token issuance taking".
type Registry struct {
	mu         sync.RWMutex
	counters   map[string]*counter
	histograms map[string]*histogram
	start      time.Time
}

type counter struct {
	help   string
	series map[string]*atomic.Int64
	labels []string
}

type histogram struct {
	help    string
	bounds  []float64
	series  map[string]*histogramSeries
	labels  []string
	seriesM sync.Mutex
}

type histogramSeries struct {
	buckets []atomic.Int64
	sum     sync.Mutex
	total   float64
	count   atomic.Int64
}

// DefaultLatencyBounds covers the range a healthy SSO request should sit in,
// from a cached JWKS read to a full Argon2 login.
var DefaultLatencyBounds = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

func NewRegistry() *Registry {
	return &Registry{counters: map[string]*counter{}, histograms: map[string]*histogram{}, start: time.Now()}
}

// Counter registers a monotonically increasing series. Registering the same
// name twice returns the existing series so callers need no ordering.
func (r *Registry) Counter(name, help string, labels ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.counters[name]; exists {
		return
	}
	r.counters[name] = &counter{help: help, series: map[string]*atomic.Int64{}, labels: labels}
}

// Histogram registers a latency series with the given bucket upper bounds.
func (r *Registry) Histogram(name, help string, bounds []float64, labels ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.histograms[name]; exists {
		return
	}
	sorted := slices.Clone(bounds)
	sort.Float64s(sorted)
	r.histograms[name] = &histogram{help: help, bounds: sorted,
		series: map[string]*histogramSeries{}, labels: labels}
}

// Add increments a counter series. Unknown names are ignored so that a missing
// registration can never take down a request path.
func (r *Registry) Add(name string, delta int64, labelValues ...string) {
	r.mu.RLock()
	target, ok := r.counters[name]
	r.mu.RUnlock()
	if !ok {
		return
	}
	key := strings.Join(labelValues, "\x00")
	r.mu.Lock()
	value, exists := target.series[key]
	if !exists {
		value = &atomic.Int64{}
		target.series[key] = value
	}
	r.mu.Unlock()
	value.Add(delta)
}

// Observe records one latency sample in seconds.
func (r *Registry) Observe(name string, seconds float64, labelValues ...string) {
	r.mu.RLock()
	target, ok := r.histograms[name]
	r.mu.RUnlock()
	if !ok {
		return
	}
	key := strings.Join(labelValues, "\x00")
	target.seriesM.Lock()
	series, exists := target.series[key]
	if !exists {
		series = &histogramSeries{buckets: make([]atomic.Int64, len(target.bounds))}
		target.series[key] = series
	}
	target.seriesM.Unlock()
	for index, bound := range target.bounds {
		if seconds <= bound {
			series.buckets[index].Add(1)
		}
	}
	series.count.Add(1)
	series.sum.Lock()
	series.total += seconds
	series.sum.Unlock()
}

// WritePrometheus renders the registry in the Prometheus text exposition format.
func (r *Registry) WritePrometheus(w io.Writer) {
	r.mu.RLock()
	counterNames := slices.Sorted(maps.Keys(r.counters))
	histogramNames := slices.Sorted(maps.Keys(r.histograms))
	r.mu.RUnlock()

	for _, name := range counterNames {
		r.mu.RLock()
		target := r.counters[name]
		keys := slices.Sorted(maps.Keys(target.series))
		values := make(map[string]int64, len(keys))
		for _, key := range keys {
			values[key] = target.series[key].Load()
		}
		r.mu.RUnlock()
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, target.help, name)
		for _, key := range keys {
			_, _ = fmt.Fprintf(w, "%s%s %d\n", name, formatLabels(target.labels, key), values[key])
		}
	}

	for _, name := range histogramNames {
		r.mu.RLock()
		target := r.histograms[name]
		r.mu.RUnlock()
		target.seriesM.Lock()
		keys := slices.Sorted(maps.Keys(target.series))
		target.seriesM.Unlock()
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, target.help, name)
		for _, key := range keys {
			target.seriesM.Lock()
			series := target.series[key]
			target.seriesM.Unlock()
			labels := formatLabels(target.labels, key)
			for index, bound := range target.bounds {
				_, _ = fmt.Fprintf(w, "%s_bucket%s %d\n", name,
					withExtraLabel(labels, "le", strconv.FormatFloat(bound, 'g', -1, 64)),
					series.buckets[index].Load())
			}
			count := series.count.Load()
			series.sum.Lock()
			total := series.total
			series.sum.Unlock()
			_, _ = fmt.Fprintf(w, "%s_bucket%s %d\n", name, withExtraLabel(labels, "le", "+Inf"), count)
			_, _ = fmt.Fprintf(w, "%s_sum%s %g\n", name, labels, total)
			_, _ = fmt.Fprintf(w, "%s_count%s %d\n", name, labels, count)
		}
	}

	_, _ = fmt.Fprintf(w, "# HELP resso_uptime_seconds Seconds since this instance started.\n"+
		"# TYPE resso_uptime_seconds gauge\nresso_uptime_seconds %g\n", time.Since(r.start).Seconds())
}

func formatLabels(names []string, key string) string {
	if len(names) == 0 {
		return ""
	}
	values := strings.Split(key, "\x00")
	pairs := make([]string, 0, len(names))
	for index, name := range names {
		value := ""
		if index < len(values) {
			value = values[index]
		}
		pairs = append(pairs, name+`="`+escapeLabelValue(value)+`"`)
	}
	return "{" + strings.Join(pairs, ",") + "}"
}

func withExtraLabel(existing, name, value string) string {
	pair := name + `="` + escapeLabelValue(value) + `"`
	if existing == "" {
		return "{" + pair + "}"
	}
	return existing[:len(existing)-1] + "," + pair + "}"
}

func escapeLabelValue(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return replacer.Replace(value)
}
