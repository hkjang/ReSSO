package federation

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/domain"
)

func providerFixture() domain.LDAPFederation {
	return domain.LDAPFederation{ID: uuid.New(), ConnectionURL: "ldaps://directory.example.com:636",
		UsersDN: "ou=people,dc=example,dc=com", BindDN: "cn=service,dc=example,dc=com",
		UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid", UUIDLDAPAttribute: "entryUUID",
		UserObjectClasses: []string{"inetOrgPerson"}, SearchScope: "SUBTREE", BatchSize: 500,
		EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn", MemberOfLDAPAttribute: "memberOf"}
}

func TestQuotedUTF16LEPreservesSupplementaryCharacters(t *testing.T) {
	encoded := []byte(quotedUTF16LE("Pass🔐word"))
	if len(encoded)%2 != 0 {
		t.Fatal("UTF-16LE password has an odd byte length")
	}
	units := make([]uint16, len(encoded)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(encoded[index*2:])
	}
	if value := string(utf16.Decode(units)); value != `"Pass🔐word"` {
		t.Fatalf("password changed during UTF-16LE encoding: %q", value)
	}
}

func TestValidateRejectsUnsafeURLAndFilter(t *testing.T) {
	provider := providerFixture()
	provider.ConnectionURL = "https://directory.example.com"
	if err := Validate(provider, "secret", true); err == nil {
		t.Fatal("accepted non-LDAP URL")
	}
	provider = providerFixture()
	provider.UserLDAPFilter = "(department=IT"
	if err := Validate(provider, "secret", true); err == nil {
		t.Fatal("accepted invalid LDAP filter")
	}
}

func TestUserFilterEscapesUsername(t *testing.T) {
	provider := providerFixture()
	filter := userFilter(provider, `alice*)(uid=*)`)
	if strings.Contains(filter, "(uid=*)") || !strings.Contains(filter, `\2a`) {
		t.Fatalf("username was not safely escaped: %s", filter)
	}
}

func TestMappedRolesSupportsDNAndCommonName(t *testing.T) {
	provider := providerFixture()
	provider.GroupRoleMappings = map[string]string{
		"cn=admins,ou=groups,dc=example,dc=com": "realm-admin",
		"developers":                            "developer",
	}
	roles := MappedRoles(provider, []string{"CN=Admins,OU=Groups,DC=example,DC=com", "CN=Developers,OU=Groups,DC=example,DC=com"})
	if strings.Join(roles, ",") != "developer,realm-admin" {
		t.Fatalf("unexpected mapped roles: %v", roles)
	}
}

func TestUserModifyRequestDeletesEmptyEmailAttribute(t *testing.T) {
	request := userModifyRequest(providerFixture(), "uid=alice,ou=people,dc=example,dc=com", "", "Alice")
	if len(request.Changes) != 2 {
		t.Fatalf("changes = %d, want 2", len(request.Changes))
	}
	emailChange := request.Changes[0]
	if emailChange.Operation != ldap.DeleteAttribute || emailChange.Modification.Type != "mail" ||
		len(emailChange.Modification.Vals) != 0 {
		t.Fatalf("empty email change = %+v, want whole-attribute delete", emailChange)
	}
}

func TestUserModifyRequestReplacesNonEmptyAttributes(t *testing.T) {
	request := userModifyRequest(providerFixture(), "uid=alice,ou=people,dc=example,dc=com",
		"alice@example.com", "Alice Example")
	if len(request.Changes) != 2 {
		t.Fatalf("changes = %d, want 2", len(request.Changes))
	}
	for index, expected := range []struct {
		attribute string
		value     string
	}{
		{attribute: "mail", value: "alice@example.com"},
		{attribute: "cn", value: "Alice Example"},
	} {
		change := request.Changes[index]
		if change.Operation != ldap.ReplaceAttribute || change.Modification.Type != expected.attribute ||
			len(change.Modification.Vals) != 1 || change.Modification.Vals[0] != expected.value {
			t.Fatalf("change %d = %+v, want replace %s=%q", index, change, expected.attribute, expected.value)
		}
	}
}
