package store

import (
	"testing"

	"github.com/hkjang/ReSSO/internal/domain"
)

// A browser omits the port when it is the scheme's default, so that is the only
// spelling an Origin header ever carries. Keeping the port meant an origin
// registered as https://app.example.com:443 was accepted, displayed as saved,
// and matched nothing: every cross-origin request from the application it was
// registered for was refused, with nothing anywhere to say why.
func TestWebOriginsCanonicalizeTheDefaultPort(t *testing.T) {
	for _, canonical := range []struct {
		registered string
		want       string
	}{
		{"https://app.example.com:443", "https://app.example.com"},
		{"https://app.example.com", "https://app.example.com"},
		{"http://localhost:80", "http://localhost"},
		{"http://localhost:3000", "http://localhost:3000"},
		{"https://app.example.com:8443", "https://app.example.com:8443"},
		{"https://APP.Example.com/", "https://app.example.com"},
	} {
		normalized, err := normalizeWebOrigins([]string{canonical.registered})
		if err != nil {
			t.Errorf("normalizeWebOrigins(%q) = %v", canonical.registered, err)
			continue
		}
		if normalized[0] != canonical.want {
			t.Errorf("normalizeWebOrigins(%q) = %q, want %q",
				canonical.registered, normalized[0], canonical.want)
		}
	}
	// The two spellings are the same origin, so they must collapse rather than
	// both be stored — otherwise the list grows entries that duplicate a
	// permission already granted.
	normalized, err := normalizeWebOrigins([]string{"https://app.example.com", "https://app.example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized) != 1 {
		t.Errorf("the same origin spelled two ways stored %d entries: %v", len(normalized), normalized)
	}
}

// What a registered redirect URI matches is the whole of what stops an
// authorization code being delivered somewhere else, and it is exact string
// equality on purpose. Nothing tested that, so a later change to be more
// accommodating — a prefix, a wildcard, ignoring a trailing slash — would look
// like a convenience and pass everything.
func TestRedirectMatchingIsExactAndNothingElse(t *testing.T) {
	client := domain.Client{
		RedirectURIs:           []string{"https://rp.example.com/callback"},
		PostLogoutRedirectURIs: []string{"https://rp.example.com/signed-out"},
	}
	if !RedirectURIAllowed(client, "https://rp.example.com/callback") {
		t.Fatal("the registered redirect URI was refused")
	}
	if !PostLogoutURIAllowed(client, "https://rp.example.com/signed-out") {
		t.Fatal("the registered post-logout URI was refused")
	}
	for _, attempt := range []string{
		"https://rp.example.com/callback/",          // a trailing slash is a different path
		"https://rp.example.com/callback2",          // a prefix of the registered value
		"https://rp.example.com/callback?next=x",    // an added query
		"https://rp.example.com/callback#x",         // an added fragment
		"https://rp.example.com/CALLBACK",           // paths are case sensitive
		"https://rp.example.com.evil.test/callback", // a suffix on the host
		"https://evil.test/callback",                // another host entirely
		"http://rp.example.com/callback",            // a downgraded scheme
		"https://rp.example.com/signed-out",         // the other list's value
		"//rp.example.com/callback",                 // a scheme-relative form
		"",
	} {
		if RedirectURIAllowed(client, attempt) {
			t.Errorf("RedirectURIAllowed accepted %q", attempt)
		}
	}
	for _, attempt := range []string{
		"https://rp.example.com/signed-out/",
		"https://rp.example.com/callback",
		"https://evil.test/signed-out",
		"",
	} {
		if PostLogoutURIAllowed(client, attempt) {
			t.Errorf("PostLogoutURIAllowed accepted %q", attempt)
		}
	}
}
