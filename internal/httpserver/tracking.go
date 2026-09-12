package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hkjang/ReSSO/internal/cryptoutil"
	"github.com/hkjang/ReSSO/internal/tracking"
)

// basePolicy is the content security policy every answer carries. Scripts are
// left to default-src on purpose: the console loads its own bundle and nothing
// else, and a policy that names script-src is one somebody widened.
const basePolicy = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

// cspReportPath is where browsers post the requests the policy refused. It is
// unauthenticated because the browser sends the report without credentials,
// and it keeps nothing but a bounded list of origins in memory.
const cspReportPath = "/api/v1/tracking/csp-report"

// maxReportBytes keeps an unauthenticated endpoint from being handed large
// bodies.
const maxReportBytes = 8 * 1024

// trackingCacheTTL bounds how long an instance serves the configuration it
// last read. The document handler and the collector proxy would otherwise
// query the database on every page view and every event batch; a change made
// in the console reaches every instance within this window.
const trackingCacheTTL = 5 * time.Second

// trackingState is the per-instance view of the tracking configuration and
// the policy reports that arrived while it was on.
type trackingState struct {
	mutex      sync.Mutex
	config     tracking.Config
	readAt     time.Time
	violations *tracking.Recorder
	transport  http.RoundTripper
}

func newTrackingState() *trackingState {
	return &trackingState{violations: tracking.NewRecorder(), transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
	}}
}

// trackingConfig reads the configuration, from the cache when it is fresh.
// A read that fails is treated as "no tracking" so a database outage never
// takes the console document down with it — the page is what a person needs
// in order to see that anything is wrong.
func (s *Server) trackingConfig(ctx context.Context) tracking.Config {
	if s.store == nil || s.tracking == nil {
		return tracking.Default()
	}
	s.tracking.mutex.Lock()
	defer s.tracking.mutex.Unlock()
	if time.Since(s.tracking.readAt) < trackingCacheTTL {
		return s.tracking.config
	}
	config, err := s.store.TrackingConfig(ctx)
	if err != nil {
		s.logger.Warn("the tracking configuration could not be read; serving the console without a snippet",
			"trace_id", traceIDFrom(ctx), "error", err)
		return tracking.Default()
	}
	s.tracking.config, s.tracking.readAt = config, time.Now()
	return config
}

// forgetTrackingConfig drops the cached copy after a change, so the instance
// that took the change serves it on the next request rather than after the
// window.
func (s *Server) forgetTrackingConfig() {
	if s.tracking == nil {
		return
	}
	s.tracking.mutex.Lock()
	defer s.tracking.mutex.Unlock()
	s.tracking.readAt = time.Time{}
}

// policyFor keeps the strict policy and adds only what the configured snippet
// needs on the document it is injected into: a nonce for its inline part,
// the origins it loads from and reports to, and while tracking is on, where
// the browser should say what it refused. Everything else — every API path,
// and the console document while tracking is off — gets the base policy
// verbatim, so turning tracking off narrows the policy back to what it was.
func policyFor(config tracking.Config, path, nonce string) string {
	if !config.Active(path) {
		return basePolicy
	}
	extraScripts, extraConnects, extraImages := config.PolicySources()
	scripts := append([]string{"'self'", "'nonce-" + nonce + "'"}, extraScripts...)
	connects := append([]string{"'self'"}, extraConnects...)
	images := append([]string{"'self'", "data:"}, extraImages...)
	return "default-src 'self'; script-src " + strings.Join(scripts, " ") +
		"; img-src " + strings.Join(images, " ") +
		"; style-src 'self' 'unsafe-inline'; font-src 'self' data:" +
		"; connect-src " + strings.Join(connects, " ") +
		"; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" +
		"; report-uri " + cspReportPath
}

// serveConsoleDocument answers a console route with the document, carrying
// the tracking snippet and the policy that lets it run when tracking is on
// for that path. The nonce is made here so the header and the markup agree.
func (s *Server) serveConsoleDocument(w http.ResponseWriter, r *http.Request, page []byte) {
	config := s.trackingConfig(r.Context())
	if config.Active(r.URL.Path) {
		nonce, err := cryptoutil.RandomToken(16)
		if err != nil {
			// Without a nonce the snippet cannot run under the strict policy,
			// and widening the policy is the one thing this must never do.
			s.logger.Error("the script nonce could not be generated; serving the console without a snippet",
				"trace_id", traceIDFrom(r.Context()), "error", err)
		} else {
			page = injectSnippet(page, config.Snippet(nonce), config.Placement)
			w.Header().Set("Content-Security-Policy", policyFor(config, r.URL.Path, nonce))
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page)
}

// injectSnippet places the markup just before the closing tag it belongs to,
// falling back to the end of the document when the tag is missing.
func injectSnippet(page []byte, snippet, placement string) []byte {
	if snippet == "" {
		return page
	}
	marker := "</head>"
	if placement == tracking.PlacementBody {
		marker = "</body>"
	}
	text := string(page)
	index := strings.LastIndex(strings.ToLower(text), marker)
	if index < 0 {
		return []byte(text + "\n" + snippet + "\n")
	}
	return []byte(text[:index] + snippet + "\n" + text[index:])
}

type cspReport struct {
	Report struct {
		BlockedURI         string `json:"blocked-uri"`
		ViolatedDirective  string `json:"violated-directive"`
		EffectiveDirective string `json:"effective-directive"`
		DocumentURI        string `json:"document-uri"`
	} `json:"csp-report"`
}

// receiveCSPReport records what a browser refused to load. Reports are always
// answered 204: the page that sent one is already in trouble, and an error
// from here would be one more thing in its console.
func (s *Server) receiveCSPReport(w http.ResponseWriter, r *http.Request) {
	defer w.WriteHeader(http.StatusNoContent)
	if s.tracking == nil {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxReportBytes))
	if err != nil || len(body) == 0 {
		return
	}
	var report cspReport
	if json.Unmarshal(body, &report) != nil {
		return
	}
	directive := report.Report.EffectiveDirective
	if directive == "" {
		directive = report.Report.ViolatedDirective
	}
	s.tracking.violations.Record(report.Report.BlockedURI, directive, report.Report.DocumentURI)
}

// trackingView is what the console reads and writes back: the configuration
// and, derived from it, the policy the document will carry so an
// administrator can see what a snippet needs before turning it on.
func (s *Server) trackingView(config tracking.Config) map[string]any {
	// Whichever path the snippet is active on; the policy differs only by
	// which paths carry it, not by what it allows.
	path := "/"
	if config.IncludeAdmin {
		path = "/admin"
	}
	return map[string]any{
		"config":     config,
		"policy":     policyFor(config, path, "…"),
		"proxy_path": tracking.MomentoProxyPath,
	}
}

func (s *Server) adminGetTracking(w http.ResponseWriter, r *http.Request) {
	config, err := s.store.TrackingConfig(r.Context())
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.trackingView(config))
}

func (s *Server) adminUpdateTracking(w http.ResponseWriter, r *http.Request) {
	var input tracking.Config
	if !decodeJSON(w, r, &input) {
		return
	}
	principal, _ := principalFrom(r.Context())
	config, err := s.store.SaveTrackingConfig(r.Context(), input, &principal.UserID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.forgetTrackingConfig()
	s.audit(r, nil, &principal.UserID, principal.Username, "TRACKING_UPDATE", "SUCCESS", "platform_setting", "tracking",
		map[string]any{"enabled": config.Enabled, "provider": config.Provider, "momento_proxy": config.MomentoProxy, "include_admin": config.IncludeAdmin})
	writeJSON(w, http.StatusOK, s.trackingView(config))
}

// adminListTrackingViolations shows which addresses the policy is blocking,
// so a snippet can be fixed without reading a browser console. The list is
// this instance's: reports are kept in memory, and behind a load balancer
// the instance that received a report is not always the one asked.
func (s *Server) adminListTrackingViolations(w http.ResponseWriter, r *http.Request) {
	items := []tracking.Violation{}
	if s.tracking != nil {
		items = s.tracking.violations.List(s.trackingConfig(r.Context()))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminClearTrackingViolations(w http.ResponseWriter, _ *http.Request) {
	if s.tracking != nil {
		s.tracking.violations.Forget()
	}
	w.WriteHeader(http.StatusNoContent)
}

// adminAllowTrackingHost adds one blocked origin to the allow list — the
// one-click fix for the reports listed above.
func (s *Server) adminAllowTrackingHost(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Origin string `json:"origin"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	origin := strings.TrimSpace(input.Origin)
	if origin == "" || !strings.HasPrefix(strings.ToLower(origin), "http") {
		writeError(w, r, http.StatusBadRequest, "invalid_origin", "허용할 출처는 https://host 형태여야 합니다.")
		return
	}
	current, err := s.store.TrackingConfig(r.Context())
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	current.AllowedHosts = tracking.AddAllowedHost(current.AllowedHosts, origin)
	principal, _ := principalFrom(r.Context())
	config, err := s.store.SaveTrackingConfig(r.Context(), current, &principal.UserID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.forgetTrackingConfig()
	s.audit(r, nil, &principal.UserID, principal.Username, "TRACKING_UPDATE", "SUCCESS", "platform_setting", "tracking",
		map[string]any{"allowed_host": origin})
	writeJSON(w, http.StatusOK, s.trackingView(config))
}

// momentoProxy forwards /momento/* to the Momento collector so that the
// tracker script and its events are same-origin as far as the browser's
// policy is concerned. It answers only while the Momento provider is on and
// asked to be proxied; otherwise the path does not exist, so turning
// tracking off stops the forwarding too.
//
// The browser sends the console's cookies with these requests because they
// are same-origin, and the collector must not receive them: the session
// cookie is the person's login. Nothing the collector answers may set a
// cookie on this origin either.
func (s *Server) momentoProxy(w http.ResponseWriter, r *http.Request) {
	config := s.trackingConfig(r.Context())
	if !config.ProxiesMomento() {
		writeError(w, r, http.StatusNotFound, "not_found", "요청한 경로가 없습니다.")
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions:
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "이 경로는 해당 HTTP 메서드를 받지 않습니다.")
		return
	}
	target, err := url.Parse(config.MomentoURL)
	if err != nil || target.Host == "" {
		writeError(w, r, http.StatusBadGateway, "upstream_unavailable", "Momento 수집기 주소가 올바르지 않습니다.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	proxy := &httputil.ReverseProxy{
		Transport: s.tracking.transport,
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
			request.Out.URL.Path = strings.TrimSuffix(target.Path, "/") + strings.TrimPrefix(request.In.URL.Path, tracking.MomentoProxyPath)
			request.Out.URL.RawPath = ""
			request.SetXForwarded()
			request.Out.Header.Del("Cookie")
			request.Out.Header.Del("Authorization")
		},
		ModifyResponse: func(response *http.Response) error {
			response.Header.Del("Set-Cookie")
			// The document's policy is this service's to state; a header from
			// the collector would be appended to it.
			response.Header.Del("Content-Security-Policy")
			response.Header.Del("Strict-Transport-Security")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.logger.Warn("the momento collector could not be reached", "trace_id", traceIDFrom(r.Context()),
				"path", r.URL.Path, "error", err)
			writeError(w, r, http.StatusBadGateway, "upstream_unavailable", "Momento 수집기에 연결하지 못했습니다.")
		},
	}
	proxy.ServeHTTP(w, r)
}
