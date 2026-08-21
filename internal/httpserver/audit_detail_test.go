package httpserver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hkjang/ReSSO/internal/domain"
)

func TestUserAuditDetailDoesNotExposeEmail(t *testing.T) {
	before := domain.User{Email: "Alice@Example.COM", EmailVerified: true, Enabled: true}
	after := domain.User{Email: "alice@example.com", EmailVerified: false, Enabled: false}
	detail := userAuditDetail(before, after)

	if detail["email_changed"] != false || detail["email_verified_before"] != true ||
		detail["email_verified_after"] != false || detail["enabled_before"] != true || detail["enabled_after"] != false {
		t.Fatalf("unexpected audit detail: %#v", detail)
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "alice@example.com") {
		t.Fatalf("audit detail leaked email: %s", encoded)
	}

	after.Email = "other@example.com"
	if changed := userAuditDetail(before, after)["email_changed"]; changed != true {
		t.Fatalf("email_changed = %v; want true", changed)
	}
}
