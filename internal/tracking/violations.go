package tracking

import (
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// MaxViolations bounds the recorder. A blocked request repeats on every page
// view, so what matters is which origins are blocked, not how often — a
// small set of distinct origins is enough to fix a snippet.
const MaxViolations = 100

// Violation is one origin the content security policy refused, kept with the
// directive that refused it so the console can say what to allow.
type Violation struct {
	Origin    string    `json:"origin"`
	Directive string    `json:"directive"`
	Page      string    `json:"page"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Allowed marks an origin the current configuration already permits, so
	// a report that arrived before the fix stops reading as a live problem.
	Allowed bool `json:"allowed"`
}

// Recorder collects the policy violations browsers report. It is deliberately
// in memory and per instance: the reports are a live troubleshooting aid for
// the person pasting a snippet, not an audit record, and keeping them out of
// the database means an unauthenticated endpoint cannot grow storage.
type Recorder struct {
	mutex      sync.Mutex
	violations map[string]*Violation
	now        func() time.Time
}

func NewRecorder() *Recorder {
	return &Recorder{violations: make(map[string]*Violation), now: time.Now}
}

// Record notes one blocked request. Anything that is not an http origin — a
// browser extension, a data: URL, the bare "inline" the browser reports for
// an inline script without a nonce — is kept under that name, because it is
// exactly what somebody debugging a snippet needs to see.
func (r *Recorder) Record(blockedURI, directive, page string) {
	origin := originOf(blockedURI)
	if origin == "" || !strings.HasPrefix(origin, "http") {
		origin = strings.TrimSpace(strings.ToLower(blockedURI))
		if origin != "inline" && origin != "eval" {
			return
		}
	}
	directive = strings.TrimSpace(strings.ToLower(directive))
	if index := strings.IndexByte(directive, ' '); index > 0 {
		directive = directive[:index]
	}
	if directive == "" {
		directive = "connect-src"
	}
	if len(page) > 512 {
		page = page[:512]
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	key := directive + " " + origin
	if existing, found := r.violations[key]; found {
		existing.Count++
		existing.LastSeen = r.now()
		existing.Page = page
		return
	}
	if len(r.violations) >= MaxViolations {
		r.evictOldest()
	}
	moment := r.now()
	r.violations[key] = &Violation{Origin: origin, Directive: directive, Page: page, Count: 1, FirstSeen: moment, LastSeen: moment}
}

func (r *Recorder) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for key, violation := range r.violations {
		if oldestKey == "" || violation.LastSeen.Before(oldest) {
			oldestKey, oldest = key, violation.LastSeen
		}
	}
	delete(r.violations, oldestKey)
}

// List returns the blocked origins, most recent first, marking the ones the
// configuration already allows.
func (r *Recorder) List(config Config) []Violation {
	allowed := make(map[string]struct{})
	scripts, connects, images := config.PolicySources()
	for _, group := range [][]string{scripts, connects, images} {
		for _, origin := range group {
			allowed[strings.ToLower(strings.TrimSuffix(origin, "/"))] = struct{}{}
		}
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	items := make([]Violation, 0, len(r.violations))
	for _, violation := range r.violations {
		copied := *violation
		_, known := allowed[strings.ToLower(copied.Origin)]
		copied.Allowed = known || matchesWildcard(copied.Origin, allowed)
		items = append(items, copied)
	}
	sort.Slice(items, func(first, second int) bool {
		if items[first].LastSeen.Equal(items[second].LastSeen) {
			return items[first].Origin < items[second].Origin
		}
		return items[first].LastSeen.After(items[second].LastSeen)
	})
	return items
}

// Forget drops the recorded violations, which is what an administrator does
// after fixing a snippet to see whether anything is still blocked.
func (r *Recorder) Forget() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.violations = make(map[string]*Violation)
}

// matchesWildcard covers policy entries such as https://*.google-analytics.com.
func matchesWildcard(origin string, allowed map[string]struct{}) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	lowered := strings.ToLower(origin)
	for pattern := range allowed {
		star := strings.Index(pattern, "*.")
		if star < 0 {
			continue
		}
		if strings.HasPrefix(lowered, pattern[:star]) && strings.HasSuffix(strings.ToLower(parsed.Host), pattern[star+1:]) {
			return true
		}
	}
	return false
}
