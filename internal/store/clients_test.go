package store

import (
	"slices"
	"testing"
)

func TestNormalizeWebOrigins(t *testing.T) {
	got, err := normalizeWebOrigins([]string{" HTTPS://Example.COM/ ", "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"https://example.com"}) {
		t.Fatalf("normalizeWebOrigins() = %#v", got)
	}
	for _, invalid := range []string{"http://example.com", "https://example.com/path", "https://user@example.com", "*"} {
		if _, err := normalizeWebOrigins([]string{invalid}); err == nil {
			t.Fatalf("invalid origin %q was accepted", invalid)
		}
	}
}

// client_id is text, so an identifier carrying a byte that column cannot hold
// matches no row — but PostgreSQL does not say so, it refuses the parameter
// (SQLSTATE 22021) and that refusal is the store error an unreadable clients
// table returns. Every caller of ClientByIdentifier takes the identifier from
// an unauthenticated request and treats such an error as a fault on this side:
// the token endpoint's undecided-authentication alarm, the authorization
// endpoint's 500, logout's client_unavailable. So a caller choosing these bytes
// could report an outage that was not happening, which is why they are settled
// as absent before the query rather than asked about.
func TestStorableIdentifierRejectsWhatNoRowCanHold(t *testing.T) {
	for _, unstorable := range []string{"bad-\xff\xfe-utf8", "bad-\x00-nul", "\xc3", "\x00"} {
		if storableIdentifier(unstorable) {
			t.Errorf("storableIdentifier(%q) = true, but no client_id can hold those bytes", unstorable)
		}
	}
	// Everything a Client can actually be registered under still reaches the
	// table, including the non-ASCII identifiers that are perfectly storable.
	for _, storable := range []string{"", "web-app", "클라이언트", "a.b-c_d~e+f/g", "ünïcode"} {
		if !storableIdentifier(storable) {
			t.Errorf("storableIdentifier(%q) = false, but that is a registrable identifier", storable)
		}
	}
}

func TestValidateURIsAllowsIPv6Loopback(t *testing.T) {
	if err := validateURIs([]string{"http://[::1]:8080/callback"}, false); err != nil {
		t.Fatalf("IPv6 loopback URI rejected: %v", err)
	}
}

// What a redirect URI is allowed to be is a security rule, not a formatting
// one: an authorization code is delivered to it, so permitting plaintext http
// off the loopback interface would put codes on the wire in the clear. There
// was a test that IPv6 loopback is accepted and none for anything refused, so
// relaxing the rule — which reads like a convenience when somebody's
// development environment is not on localhost — would have passed.
func TestValidateURIsRefusesAnythingACodeShouldNotBeSentTo(t *testing.T) {
	for _, allowed := range []string{
		"https://rp.example.com/callback",
		"https://rp.example.com:8443/callback",
		"http://localhost:3000/callback",
		"http://127.0.0.1:3000/callback",
		"http://[::1]:8080/callback",
	} {
		if err := validateURIs([]string{allowed}, false); err != nil {
			t.Errorf("validateURIs(%q) = %v, want it accepted", allowed, err)
		}
	}
	for _, refused := range []string{
		"http://rp.example.com/callback", // plaintext off the loopback interface
		"http://192.168.1.10/callback",   // a private address is not a loopback one
		"https://rp.example.com/cb#part", // a fragment, which OAuth forbids here
		"javascript:alert(1)",            // no host, and not somewhere to send a code
		"data:text/html,<b>x",            //
		"file:///etc/passwd",             //
		"/callback",                      // relative: nothing says where it goes
		"rp.example.com/callback",        // no scheme
		"com.example.app://callback",     // a custom scheme, refused today
		"",
	} {
		if err := validateURIs([]string{refused}, false); err == nil {
			t.Errorf("validateURIs(%q) accepted it", refused)
		}
	}
	// One bad entry among good ones still refuses the whole list, or a client
	// keeps whatever slipped through alongside the ones that were checked.
	if err := validateURIs([]string{"https://rp.example.com/a", "http://rp.example.com/b"}, false); err == nil {
		t.Error("a list containing a plaintext URI was accepted")
	}
}
