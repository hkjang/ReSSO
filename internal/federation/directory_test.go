package federation

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/domain"
)

// These exercise the code that talks to a real directory. Everything in this
// file was covered only by reading until now: connecting, searching, turning
// an entry into a user, and checking a password by binding as that user. It is
// the part of the service that reaches outside the process, so the failures it
// can have — a wrong base, an attribute that is missing, a bind that should be
// refused — are the ones a fixture cannot rehearse.
//
// Set RESSO_TEST_LDAP_URL to run these; without it there is nothing to talk to.
func directoryConfig(t *testing.T) RuntimeConfig {
	t.Helper()
	url := strings.TrimSpace(os.Getenv("RESSO_TEST_LDAP_URL"))
	if url == "" {
		t.Skip("set RESSO_TEST_LDAP_URL to run directory integration tests")
	}
	return RuntimeConfig{
		Provider: domain.LDAPFederation{
			ID: uuid.New(), Vendor: "OTHER", ConnectionURL: url,
			UsersDN: "ou=people,dc=example,dc=test", BindDN: "cn=admin,dc=example,dc=test",
			UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid", UUIDLDAPAttribute: "entryUUID",
			UserObjectClasses: []string{"inetOrgPerson"}, SearchScope: "SUBTREE", BatchSize: 100,
			EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn",
			FirstNameLDAPAttribute: "givenName", LastNameLDAPAttribute: "sn",
			MemberOfLDAPAttribute: "memberOf",
		},
		BindCredential: "adminpassword",
	}
}

func TestDirectoryConnectionReachesTheConfiguredBase(t *testing.T) {
	config := directoryConfig(t)
	if err := TestConnection(context.Background(), config); err != nil {
		t.Fatalf("connecting to the configured base failed: %v", err)
	}

	// A base that does not exist has to be reported, because this is the check
	// an administrator runs to find out whether they typed it correctly.
	wrong := config
	wrong.Provider.UsersDN = "ou=nobody,dc=example,dc=test"
	if err := TestConnection(context.Background(), wrong); err == nil {
		t.Error("a users DN that does not exist was reported as reachable")
	}

	// Wrong credentials must fail rather than fall back to an anonymous bind,
	// which would make the check pass while nothing else worked.
	badBind := config
	badBind.BindCredential = "not-the-password"
	if err := TestConnection(context.Background(), badBind); err == nil {
		t.Error("an incorrect bind credential was accepted")
	}
}

func TestDirectoryFetchReadsTheAttributesTheProviderNames(t *testing.T) {
	config := directoryConfig(t)
	users, err := FetchUsers(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]User{}
	for _, user := range users {
		found[user.Username] = user
	}
	alice, ok := found["alice"]
	if !ok {
		t.Fatalf("alice was not among %d users read", len(users))
	}
	if alice.Email != "alice@example.test" {
		t.Errorf("email = %q", alice.Email)
	}
	if alice.DisplayName != "Alice Kim" {
		t.Errorf("display name = %q", alice.DisplayName)
	}
	if alice.FirstName != "Alice" || alice.LastName != "Kim" {
		t.Errorf("name parts = %q %q", alice.FirstName, alice.LastName)
	}
	if !strings.HasPrefix(alice.DN, "uid=alice,") {
		t.Errorf("dn = %q", alice.DN)
	}
	// The external identifier is what links a directory entry to a local
	// account across renames, so it has to be present and stable.
	if alice.ExternalID == "" {
		t.Error("no external identifier was read")
	}
	if second, err := FetchUsers(context.Background(), config); err != nil {
		t.Fatal(err)
	} else {
		for _, user := range second {
			if user.Username == "alice" && user.ExternalID != alice.ExternalID {
				t.Errorf("external identifier changed between reads: %q then %q", alice.ExternalID, user.ExternalID)
			}
		}
	}
}

func TestDirectoryAuthenticateBindsAsTheUser(t *testing.T) {
	config := directoryConfig(t)
	user, ok, err := Authenticate(context.Background(), config, "alice", "alice-pass-1234")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("the correct password was refused")
	}
	if user.Username != "alice" || user.Email != "alice@example.test" {
		t.Errorf("authenticated user = %+v", user)
	}

	if _, ok, err := Authenticate(context.Background(), config, "alice", "wrong-password"); err != nil || ok {
		t.Errorf("a wrong password was accepted: ok=%v err=%v", ok, err)
	}
	// An empty password must never succeed: LDAP treats a bind with no
	// password as an anonymous bind, which servers accept.
	if _, ok, err := Authenticate(context.Background(), config, "alice", ""); err != nil || ok {
		t.Errorf("an empty password was accepted: ok=%v err=%v", ok, err)
	}
	if _, ok, err := Authenticate(context.Background(), config, "nobody-here", "any-password"); err != nil || ok {
		t.Errorf("an unknown user was accepted: ok=%v err=%v", ok, err)
	}
}

// Writing back to a directory is the riskiest thing this package does: a
// mistake lands in a system the service does not own and does not back up.
// The clearing case is the one worth stating — the schema rejects replacing an
// optional attribute with an empty value, so an operator removing somebody's
// address needs the attribute deleted instead.
func TestDirectoryUpdateWritesBackAndCanClearAnOptionalAttribute(t *testing.T) {
	config := directoryConfig(t)
	users, err := FetchUsers(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	var bob User
	for _, user := range users {
		if user.Username == "bob" {
			bob = user
		}
	}
	if bob.DN == "" {
		t.Fatal("bob was not found in the directory")
	}
	t.Cleanup(func() {
		_ = UpdateUser(context.Background(), config, bob.DN, "bob@example.test", "Bob Lee")
	})

	if err := UpdateUser(context.Background(), config, bob.DN, "robert@example.test", "Robert Lee"); err != nil {
		t.Fatalf("writing back to the directory failed: %v", err)
	}
	reread := func() User {
		t.Helper()
		current, fetchErr := FetchUsers(context.Background(), config)
		if fetchErr != nil {
			t.Fatal(fetchErr)
		}
		for _, user := range current {
			if user.Username == "bob" {
				return user
			}
		}
		t.Fatal("bob disappeared from the directory")
		return User{}
	}
	if updated := reread(); updated.Email != "robert@example.test" || updated.DisplayName != "Robert Lee" {
		t.Errorf("the directory kept %+v", updated)
	}

	if err := UpdateUser(context.Background(), config, bob.DN, "", "Robert Lee"); err != nil {
		t.Fatalf("clearing the address failed, which is what the delete change is for: %v", err)
	}
	if cleared := reread(); cleared.Email != "" {
		t.Errorf("the address was not cleared: %q", cleared.Email)
	}
}

// A password change has to take effect for the directory, not just return
// without error: the account is the one the person signs in with afterwards.
func TestDirectoryPasswordChangeTakesEffect(t *testing.T) {
	config := directoryConfig(t)
	const original = "bob-pass-1234"
	const replacement = "bob-new-pass-5678"
	users, err := FetchUsers(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	var dn string
	for _, user := range users {
		if user.Username == "bob" {
			dn = user.DN
		}
	}
	if dn == "" {
		t.Fatal("bob was not found in the directory")
	}
	t.Cleanup(func() {
		_ = ChangePassword(context.Background(), config, dn, "", original)
	})

	if err := ChangePassword(context.Background(), config, dn, original, replacement); err != nil {
		t.Fatalf("changing the password failed: %v", err)
	}
	if _, ok, err := Authenticate(context.Background(), config, "bob", replacement); err != nil || !ok {
		t.Errorf("the new password was refused: ok=%v err=%v", ok, err)
	}
	if _, ok, err := Authenticate(context.Background(), config, "bob", original); err != nil || ok {
		t.Errorf("the old password still worked: ok=%v err=%v", ok, err)
	}
}
