package httpserver

import (
	"net"
	"net/http/httptest"
	"testing"
)

func mustCIDR(t *testing.T, value string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatal(err)
	}
	return network
}

func TestClientIPUsesOnlyTrustedProxyChain(t *testing.T) {
	server := &Server{trustedProxyCIDRs: []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}}
	request := httptest.NewRequest("GET", "http://resso.test/", nil)
	request.RemoteAddr = "10.0.0.2:12345"
	request.Header.Set("X-Forwarded-For", "198.51.100.24, 10.0.0.1")
	if got := server.clientIP(request); got != "198.51.100.24" {
		t.Fatalf("clientIP() = %q", got)
	}

	request.RemoteAddr = "203.0.113.9:12345"
	request.Header.Set("X-Forwarded-For", "198.51.100.99")
	if got := server.clientIP(request); got != "203.0.113.9" {
		t.Fatalf("untrusted forwarded address was accepted: %q", got)
	}
}

func TestClientIPFallsBackToTrustedProxyRealIP(t *testing.T) {
	server := &Server{trustedProxyCIDRs: []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}}
	request := httptest.NewRequest("GET", "http://resso.test/", nil)
	request.RemoteAddr = "10.0.0.2:12345"
	request.Header.Set("X-Real-IP", "198.51.100.24")
	if got := server.clientIP(request); got != "198.51.100.24" {
		t.Fatalf("clientIP() = %q", got)
	}
}

func TestRequestIsSecureTrustsConfiguredProxyOnly(t *testing.T) {
	server := &Server{trustedProxyCIDRs: []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}}
	request := httptest.NewRequest("GET", "http://resso.test/", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.RemoteAddr = "203.0.113.9:12345"
	if server.requestIsSecure(request) {
		t.Fatal("untrusted proxy marked request secure")
	}
	request.RemoteAddr = "10.1.2.3:12345"
	if !server.requestIsSecure(request) {
		t.Fatal("trusted proxy HTTPS marker was ignored")
	}
}
