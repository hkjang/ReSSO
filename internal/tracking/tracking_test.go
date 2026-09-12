package tracking

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDefaultIsOffAndInjectsNothing(t *testing.T) {
	config := Default()
	if config.Enabled || config.Provider != ProviderNone {
		t.Fatalf("default = %+v, want off", config)
	}
	for _, path := range []string{"/", "/login", "/personal", "/admin", "/admin/users"} {
		if config.Active(path) {
			t.Errorf("default configuration is active on %s", path)
		}
	}
	if config.Snippet("n") != "" {
		t.Error("default configuration renders a snippet")
	}
	if err := config.Validate(); err != nil {
		t.Errorf("default configuration does not validate: %v", err)
	}
}

// Momento is the provider whose data stays inside the network, and through
// the proxy nothing in the policy names an external origin at all.
func TestMomentoThroughTheProxyNamesNoExternalOrigin(t *testing.T) {
	config := Config{Enabled: true, Provider: ProviderMomento, MomentoURL: "https://momento.corp.example/",
		MomentoSiteID: "SITE_1", MomentoProxy: true}.Normalized()
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	snippet := config.Snippet("abc")
	for _, want := range []string{`src="/momento/tracker.js"`, `data-endpoint="/momento"`, `data-site-id="SITE_1"`, `nonce="abc"`} {
		if !strings.Contains(snippet, want) {
			t.Errorf("snippet lacks %s: %s", want, snippet)
		}
	}
	if strings.Contains(snippet, "momento.corp.example") {
		t.Errorf("the proxied snippet names the collector: %s", snippet)
	}
	scripts, connects, images := config.PolicySources()
	if len(scripts)+len(connects)+len(images) != 0 {
		t.Errorf("the proxied setup needs policy sources: %v %v %v", scripts, connects, images)
	}
	if !config.ProxiesMomento() {
		t.Error("the proxy is not on")
	}

	direct := config
	direct.MomentoProxy = false
	snippet = direct.Snippet("abc")
	if !strings.Contains(snippet, `src="https://momento.corp.example/tracker.js"`) || strings.Contains(snippet, "data-endpoint") {
		t.Errorf("the direct snippet = %s", snippet)
	}
	scripts, connects, _ = direct.PolicySources()
	if !slices.Contains(scripts, "https://momento.corp.example") || !slices.Contains(connects, "https://momento.corp.example") {
		t.Errorf("the direct setup does not allow the collector: %v %v", scripts, connects)
	}
	if direct.ProxiesMomento() {
		t.Error("the proxy is on for a direct setup")
	}
}

// Turning tracking off must also turn the proxy off, or an installation
// keeps forwarding traffic to a collector nobody asked for any more.
func TestTheProxyFollowsTheSwitch(t *testing.T) {
	config := Config{Enabled: false, Provider: ProviderMomento, MomentoURL: "https://momento.corp.example",
		MomentoSiteID: "SITE_1", MomentoProxy: true}.Normalized()
	if config.ProxiesMomento() {
		t.Error("the proxy is on while tracking is off")
	}
}

func TestAdministrativeScreensAreLeftOutUnlessAsked(t *testing.T) {
	config := Config{Enabled: true, Provider: ProviderGA4, MeasurementID: "G-1"}.Normalized()
	for path, want := range map[string]bool{"/": true, "/login": true, "/personal/sessions": true,
		"/admin": false, "/admin/users": false, "/administrator": true} {
		if got := config.Active(path); got != want {
			t.Errorf("Active(%s) = %v, want %v", path, got, want)
		}
	}
	config.IncludeAdmin = true
	if !config.Active("/admin/users") {
		t.Error("include_admin did not include the console")
	}
}

func TestEveryScriptTagGetsTheNonce(t *testing.T) {
	config := Config{Enabled: true, Provider: ProviderCustom,
		CustomSnippet: `<script src="https://t.example/a.js"></script>
<SCRIPT>window.t=1</SCRIPT>
<script nonce="theirs">x()</script>`}.Normalized()
	snippet := config.Snippet("n0nce")
	if got := strings.Count(snippet, `nonce="n0nce"`); got != 2 {
		t.Errorf("nonce applied %d times, want 2: %s", got, snippet)
	}
	if !strings.Contains(snippet, `nonce="theirs"`) {
		t.Errorf("a tag that carried its own nonce was rewritten: %s", snippet)
	}
	if strings.Contains(config.Snippet(""), "nonce=\"\"") {
		t.Error("an empty nonce was written")
	}
}

func TestOriginsAreReadOutOfThePastedSnippet(t *testing.T) {
	snippet := `<script src="https://momento.corp.example/tracker.js"></script>
<script>window.__t={endpoint:"https://momento.corp.example/collect/v1/events",pixel:'http://pixel.corp.example:8080/p.gif?id=1'};</script>`
	origins := SnippetOrigins(snippet)
	want := []string{"https://momento.corp.example", "http://pixel.corp.example:8080"}
	if !slices.Equal(origins, want) {
		t.Errorf("origins = %v, want %v", origins, want)
	}
	config := Config{Enabled: true, Provider: ProviderCustom, CustomSnippet: snippet,
		AllowedHosts: "https://extra.example/, https://momento.corp.example\nhttps://other.example"}.Normalized()
	scripts, _, _ := config.PolicySources()
	for _, origin := range []string{"https://momento.corp.example", "http://pixel.corp.example:8080", "https://extra.example", "https://other.example"} {
		if !slices.Contains(scripts, origin) {
			t.Errorf("script-src lacks %s: %v", origin, scripts)
		}
	}
}

func TestValidationNamesWhatIsMissing(t *testing.T) {
	cases := map[string]Config{
		"momento without a site":    {Provider: ProviderMomento, MomentoURL: "https://m.example"},
		"momento with a bad url":    {Provider: ProviderMomento, MomentoURL: "m.example", MomentoSiteID: "S"},
		"ga4 without an id":         {Provider: ProviderGA4},
		"matomo without a site":     {Provider: ProviderMatomo, MatomoURL: "https://m.example"},
		"custom without a snippet":  {Provider: ProviderCustom},
		"an unknown provider":       {Provider: "piwik"},
		"a snippet over the limit":  {Provider: ProviderCustom, CustomSnippet: "<script>" + strings.Repeat("x", MaxSnippetBytes) + "</script>"},
		"an allowed host without a": {Provider: ProviderNone, AllowedHosts: "momento.corp.example"},
	}
	for name, config := range cases {
		if err := config.Normalized().Validate(); err == nil {
			t.Errorf("%s validated", name)
		}
	}
	// The limit holds while tracking is off too: what is saved off must not
	// become a refusal at the moment somebody turns it on.
	off := Config{Enabled: false, Provider: ProviderCustom, CustomSnippet: strings.Repeat("x", MaxSnippetBytes+1)}
	if err := off.Normalized().Validate(); err == nil {
		t.Error("an oversized snippet was accepted because tracking was off")
	}
	good := Config{Enabled: true, Provider: "Momento", MomentoURL: " https://m.example/ ", MomentoSiteID: "S", Placement: "BODY"}.Normalized()
	if err := good.Validate(); err != nil {
		t.Errorf("a normalized configuration was refused: %v", err)
	}
	if good.Provider != ProviderMomento || good.MomentoURL != "https://m.example" || good.Placement != PlacementBody {
		t.Errorf("normalized = %+v", good)
	}
}

func TestRecorderKeepsDistinctOriginsNotCounts(t *testing.T) {
	recorder := NewRecorder()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { return now }
	for range 5 {
		recorder.Record("https://momento.corp.example/collect/v1/events", "connect-src https://x", "https://sso.example/login")
	}
	recorder.Record("inline", "script-src-elem", "https://sso.example/login")
	recorder.Record("chrome-extension://abc/x.js", "script-src", "https://sso.example/")
	recorder.Record("", "img-src", "https://sso.example/")
	items := recorder.List(Config{})
	if len(items) != 2 {
		t.Fatalf("items = %+v, want the origin and the inline report only", items)
	}
	byOrigin := map[string]Violation{}
	for _, item := range items {
		byOrigin[item.Origin] = item
	}
	momento := byOrigin["https://momento.corp.example"]
	if momento.Count != 5 || momento.Directive != "connect-src" || momento.Allowed {
		t.Errorf("momento = %+v", momento)
	}
	if _, ok := byOrigin["inline"]; !ok {
		t.Errorf("the inline report was dropped: %+v", items)
	}

	// Once the configuration allows the origin, the report stops nagging.
	allowed := Config{Provider: ProviderCustom, CustomSnippet: "<script></script>", AllowedHosts: "https://momento.corp.example"}
	for _, item := range recorder.List(allowed) {
		if item.Origin == "https://momento.corp.example" && !item.Allowed {
			t.Errorf("an allowed origin is still reported as blocked: %+v", item)
		}
	}
	wildcard := Config{Provider: ProviderGA4, MeasurementID: "G-1"}
	recorder.Record("https://region1.google-analytics.com/g/collect", "connect-src", "/")
	for _, item := range recorder.List(wildcard) {
		if item.Origin == "https://region1.google-analytics.com" && !item.Allowed {
			t.Errorf("a wildcard-covered origin is still reported as blocked: %+v", item)
		}
	}

	recorder.Forget()
	if len(recorder.List(Config{})) != 0 {
		t.Error("Forget left reports behind")
	}
}

func TestRecorderIsBounded(t *testing.T) {
	recorder := NewRecorder()
	tick := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { tick = tick.Add(time.Second); return tick }
	for index := range MaxViolations + 20 {
		recorder.Record("https://host-"+strings.Repeat("a", index%7)+"-"+string(rune('a'+index%26))+".example:"+itoa(index), "connect-src", "/")
	}
	items := recorder.List(Config{})
	if len(items) != MaxViolations {
		t.Fatalf("recorder holds %d, want %d", len(items), MaxViolations)
	}
	// The oldest went first, so the last one recorded is still there.
	if items[0].Origin != "https://host-"+strings.Repeat("a", (MaxViolations+19)%7)+"-"+string(rune('a'+(MaxViolations+19)%26))+".example:"+itoa(MaxViolations+19) {
		t.Errorf("most recent = %s", items[0].Origin)
	}
}

func itoa(value int) string {
	digits := []byte{}
	if value == 0 {
		return "0"
	}
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

func TestAddAllowedHostKeepsTheExistingList(t *testing.T) {
	if got := AddAllowedHost("", "https://a.example/"); got != "https://a.example" {
		t.Errorf("got %q", got)
	}
	if got := AddAllowedHost("https://a.example", "https://b.example"); got != "https://a.example, https://b.example" {
		t.Errorf("got %q", got)
	}
	if got := AddAllowedHost("https://a.example", "https://A.example"); got != "https://a.example" {
		t.Errorf("got %q", got)
	}
}
