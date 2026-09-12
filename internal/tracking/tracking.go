// Package tracking injects a visitor tracking snippet into the console
// document.
//
// The content security policy the console ships with allows scripts from its
// own origin only, so a pasted snippet is refused without a word to whoever
// pasted it. This package produces both halves of the answer: the markup to
// inject and the policy sources it needs, with a per-request nonce so the
// inline part runs without loosening the policy for everything else.
package tracking

import (
	"fmt"
	"html"
	"net/url"
	"strings"
)

const (
	ProviderNone    = "none"
	ProviderMomento = "momento"
	ProviderGA4     = "ga4"
	ProviderGTM     = "gtm"
	ProviderMatomo  = "matomo"
	ProviderCustom  = "custom"

	PlacementHead = "head"
	PlacementBody = "body"

	// MaxSnippetBytes bounds a pasted snippet. A tracker loader is a few
	// hundred bytes; anything larger is a page, not a snippet.
	MaxSnippetBytes = 8 * 1024

	// MomentoProxyPath is where this service forwards to the Momento collector
	// when the same-origin proxy is on, so that neither the tracker script nor
	// its events leave the console's own origin as far as the policy is
	// concerned.
	MomentoProxyPath = "/momento"
)

// Providers lists the accepted provider names in the order the console shows
// them. Momento comes first because it is the one option whose data stays
// inside the network.
var Providers = []string{ProviderNone, ProviderMomento, ProviderGA4, ProviderGTM, ProviderMatomo, ProviderCustom}

// Config is the tracking configuration an administrator edits in the console.
// It lives in the database rather than the environment: the collector's
// address differs per installation and changes while the service runs, and a
// setting that needs a redeploy to change stays off.
type Config struct {
	Enabled       bool   `json:"enabled"`
	Provider      string `json:"provider"`
	MomentoURL    string `json:"momento_url"`
	MomentoSiteID string `json:"momento_site_id"`
	// MomentoProxy forwards /momento/* to the collector so the policy never
	// names an external origin. It is the default because it is the one setup
	// that cannot be blocked by the policy.
	MomentoProxy  bool   `json:"momento_proxy"`
	MeasurementID string `json:"measurement_id"`
	MatomoURL     string `json:"matomo_url"`
	MatomoSiteID  string `json:"matomo_site_id"`
	CustomSnippet string `json:"custom_snippet"`
	// AllowedHosts is where an administrator adds an origin the snippet did
	// not name itself, one per line or comma.
	AllowedHosts string `json:"allowed_hosts"`
	IncludeAdmin bool   `json:"include_admin"`
	Placement    string `json:"placement"`
}

// Default is the configuration of an installation nobody has touched: off.
func Default() Config {
	return Config{Provider: ProviderNone, MomentoProxy: true, Placement: PlacementHead}
}

// Normalized trims and lowercases what the console sent, so that a provider
// typed as "Momento" and a placement left empty still mean what they look like.
func (c Config) Normalized() Config {
	c.Provider = strings.ToLower(strings.TrimSpace(c.Provider))
	if c.Provider == "" {
		c.Provider = ProviderNone
	}
	c.Placement = strings.ToLower(strings.TrimSpace(c.Placement))
	if c.Placement != PlacementBody {
		c.Placement = PlacementHead
	}
	c.MomentoURL = strings.TrimRight(strings.TrimSpace(c.MomentoURL), "/")
	c.MomentoSiteID = strings.TrimSpace(c.MomentoSiteID)
	c.MeasurementID = strings.TrimSpace(c.MeasurementID)
	c.MatomoURL = strings.TrimRight(strings.TrimSpace(c.MatomoURL), "/")
	c.MatomoSiteID = strings.TrimSpace(c.MatomoSiteID)
	c.CustomSnippet = strings.TrimSpace(c.CustomSnippet)
	c.AllowedHosts = strings.TrimSpace(c.AllowedHosts)
	return c
}

// Validate says what is missing for the chosen provider. The limits apply
// whether or not tracking is on, so that what is saved while off does not
// become a refusal at the moment somebody turns it on.
func (c Config) Validate() error {
	switch c.Provider {
	case ProviderNone:
	case ProviderMomento:
		if c.MomentoURL == "" || c.MomentoSiteID == "" {
			return fmt.Errorf("momento 수집기 주소와 사이트 ID가 필요합니다")
		}
		if err := validateHTTPURL(c.MomentoURL, "Momento 수집기 주소"); err != nil {
			return err
		}
	case ProviderGA4, ProviderGTM:
		if c.MeasurementID == "" {
			return fmt.Errorf("측정 ID가 필요합니다")
		}
	case ProviderMatomo:
		if c.MatomoURL == "" || c.MatomoSiteID == "" {
			return fmt.Errorf("matomo 주소와 사이트 ID가 필요합니다")
		}
		if err := validateHTTPURL(c.MatomoURL, "Matomo 주소"); err != nil {
			return err
		}
	case ProviderCustom:
		if c.CustomSnippet == "" {
			return fmt.Errorf("붙여 넣은 추적 코드가 비어 있습니다")
		}
	default:
		return fmt.Errorf("provider는 %s 중 하나여야 합니다", strings.Join(Providers, ", "))
	}
	if len(c.CustomSnippet) > MaxSnippetBytes {
		return fmt.Errorf("추적 코드는 %d바이트를 넘을 수 없습니다", MaxSnippetBytes)
	}
	for _, host := range splitHosts(c.AllowedHosts) {
		if originOf(host) == "" || !strings.HasPrefix(strings.ToLower(host), "http") {
			return fmt.Errorf("허용 출처 %q는 https://host 형태여야 합니다", host)
		}
	}
	return nil
}

func validateHTTPURL(raw, label string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("%s는 http(s)://host 형태의 주소여야 합니다", label)
	}
	return nil
}

// Active reports whether the document served for path should carry the
// snippet. The console's administrative screens are left out unless asked
// for: what an administrator does in the console is rarely the visitor data
// anybody wanted to measure.
func (c Config) Active(path string) bool {
	if !c.Enabled || c.Provider == ProviderNone || c.Provider == "" {
		return false
	}
	if !c.IncludeAdmin && (path == "/admin" || strings.HasPrefix(path, "/admin/")) {
		return false
	}
	return strings.TrimSpace(c.Snippet("")) != ""
}

// ProxiesMomento reports whether /momento/* should be forwarded to the
// collector — only while the Momento provider is on and asked to be proxied,
// so an installation that turned tracking off is not left forwarding traffic.
func (c Config) ProxiesMomento() bool {
	return c.Enabled && c.Provider == ProviderMomento && c.MomentoProxy && c.MomentoURL != ""
}

// Snippet renders the markup to inject, with the nonce on every script tag
// so the policy can stay strict.
func (c Config) Snippet(nonce string) string {
	switch c.Provider {
	case ProviderMomento:
		site := html.EscapeString(c.MomentoSiteID)
		if c.MomentoURL == "" || site == "" {
			return ""
		}
		if c.MomentoProxy {
			// Both the script and its events go through this service, so the
			// policy's 'self' covers them and no external origin is named.
			return withNonce(fmt.Sprintf(`<script async src="%s/tracker.js" data-site-id="%s" data-environment="prd" data-contract-version="1" data-endpoint="%s"></script>`,
				MomentoProxyPath, site, MomentoProxyPath), nonce)
		}
		return withNonce(fmt.Sprintf(`<script async src="%s/tracker.js" data-site-id="%s" data-environment="prd" data-contract-version="1"></script>`,
			html.EscapeString(c.MomentoURL), site), nonce)
	case ProviderGA4:
		id := html.EscapeString(c.MeasurementID)
		if id == "" {
			return ""
		}
		return withNonce(fmt.Sprintf(`<script async src="https://www.googletagmanager.com/gtag/js?id=%s"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','%s');</script>`, id, id), nonce)
	case ProviderGTM:
		id := html.EscapeString(c.MeasurementID)
		if id == "" {
			return ""
		}
		return withNonce(fmt.Sprintf(`<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src='https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);})(window,document,'script','dataLayer','%s');</script>`, id), nonce)
	case ProviderMatomo:
		site := html.EscapeString(c.MatomoSiteID)
		if c.MatomoURL == "" || site == "" {
			return ""
		}
		return withNonce(fmt.Sprintf(`<script>var _paq=window._paq=window._paq||[];_paq.push(['trackPageView']);_paq.push(['enableLinkTracking']);(function(){var u="%s/";_paq.push(['setTrackerUrl',u+'matomo.php']);_paq.push(['setSiteId','%s']);var d=document,g=d.createElement('script'),s=d.getElementsByTagName('script')[0];g.async=true;g.src=u+'matomo.js';s.parentNode.insertBefore(g,s);})();</script>`, html.EscapeString(c.MatomoURL), site), nonce)
	case ProviderCustom:
		return withNonce(c.CustomSnippet, nonce)
	}
	return ""
}

// withNonce adds the nonce to every script tag that does not already carry
// one, which is what lets a pasted snippet run under a strict policy unchanged.
func withNonce(snippet, nonce string) string {
	if nonce == "" || snippet == "" {
		return snippet
	}
	var builder strings.Builder
	remaining := snippet
	for {
		index := strings.Index(strings.ToLower(remaining), "<script")
		if index < 0 {
			builder.WriteString(remaining)
			return builder.String()
		}
		end := index + len("<script")
		builder.WriteString(remaining[:end])
		tag := remaining[end:]
		if closing := strings.Index(tag, ">"); closing >= 0 {
			tag = tag[:closing]
		}
		if !strings.Contains(strings.ToLower(tag), "nonce=") {
			builder.WriteString(` nonce="` + html.EscapeString(nonce) + `"`)
		}
		remaining = remaining[end:]
	}
}

// PolicySources lists the extra origins the snippet needs, derived from the
// provider so the common setups need no policy knowledge at all. The
// proxied Momento setup needs none: everything it loads is 'self'.
func (c Config) PolicySources() (scripts, connects, images []string) {
	add := func(origin string) {
		scripts = append(scripts, origin)
		connects = append(connects, origin)
		images = append(images, origin)
	}
	switch c.Provider {
	case ProviderMomento:
		if !c.MomentoProxy {
			if origin := originOf(c.MomentoURL); origin != "" {
				add(origin)
			}
		}
	case ProviderGA4, ProviderGTM:
		scripts = append(scripts, "https://www.googletagmanager.com")
		connects = append(connects, "https://www.google-analytics.com", "https://analytics.google.com", "https://*.google-analytics.com")
		images = append(images, "https://www.google-analytics.com", "https://www.googletagmanager.com")
	case ProviderMatomo:
		if origin := originOf(c.MatomoURL); origin != "" {
			add(origin)
		}
	}
	// A pasted snippet names the addresses it loads and reports to, so those
	// origins are allowed without anybody reading a policy error first.
	for _, origin := range SnippetOrigins(c.CustomSnippet) {
		add(origin)
	}
	for _, host := range splitHosts(c.AllowedHosts) {
		add(host)
	}
	return scripts, connects, images
}

// SnippetOrigins lists every http(s) origin written into a snippet: the
// script it loads, the endpoint it posts to, the pixel it requests. A tracker
// almost always writes its own address into its loader, so reading them here
// is what keeps a pasted snippet working without the administrator
// translating a policy error into a host name.
func SnippetOrigins(snippet string) []string {
	origins := make([]string, 0, 2)
	seen := make(map[string]struct{}, 2)
	lowered := strings.ToLower(snippet)
	for index := 0; index < len(snippet); {
		start := strings.Index(lowered[index:], "http")
		if start < 0 {
			break
		}
		start += index
		end := start
		for end < len(snippet) && !isURLBoundary(snippet[end]) {
			end++
		}
		index = end
		origin := originOf(snippet[start:end])
		if origin == "" || !strings.HasPrefix(strings.ToLower(origin), "http") {
			continue
		}
		if _, duplicate := seen[origin]; duplicate {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}
	return origins
}

// isURLBoundary reports the characters that cannot appear in a URL written
// inside HTML or JavaScript, which is where each address ends.
func isURLBoundary(letter byte) bool {
	switch letter {
	case '"', '\'', '`', '<', '>', ' ', '\t', '\n', '\r', ')', ',', ';', '\\', '+':
		return true
	}
	return false
}

// originOf reduces an address to scheme://host, which is the unit a policy
// allows. Anything without a host, such as a relative path, is nothing.
func originOf(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return ""
	}
	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + parsed.Host
}

func splitHosts(list string) []string {
	fields := strings.FieldsFunc(list, func(letter rune) bool {
		return letter == ',' || letter == ' ' || letter == '\n' || letter == '\r' || letter == '\t'
	})
	hosts := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSuffix(strings.TrimSpace(field), "/"); trimmed != "" {
			hosts = append(hosts, trimmed)
		}
	}
	return hosts
}

// AddAllowedHost appends an origin to the allow list, leaving the existing
// entries and their order alone.
func AddAllowedHost(existing, origin string) string {
	origin = strings.TrimSpace(strings.TrimSuffix(origin, "/"))
	if origin == "" {
		return existing
	}
	for _, host := range splitHosts(existing) {
		if strings.EqualFold(host, origin) {
			return existing
		}
	}
	if strings.TrimSpace(existing) == "" {
		return origin
	}
	return strings.TrimSpace(existing) + ", " + origin
}
