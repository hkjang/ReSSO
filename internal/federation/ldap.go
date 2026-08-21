package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"

	"github.com/hkjang/ReSSO/internal/domain"
)

const operationTimeout = 15 * time.Second

var ldapAttributePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._;-]{0,127}$`)

type RuntimeConfig struct {
	Provider       domain.LDAPFederation
	BindCredential string
}

type User struct {
	ExternalID  string
	DN          string
	Username    string
	Email       string
	DisplayName string
	FirstName   string
	LastName    string
	MemberOf    []string
}

func Validate(provider domain.LDAPFederation, bindCredential string, credentialRequired bool) error {
	parsed, err := url.Parse(provider.ConnectionURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "ldap" && parsed.Scheme != "ldaps") {
		return errors.New("connection URL must use ldap:// or ldaps:// and include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("connection URL must not contain credentials, query parameters, or fragments")
	}
	if provider.StartTLS && parsed.Scheme != "ldap" {
		return errors.New("StartTLS can only be used with an ldap:// connection URL")
	}
	if strings.TrimSpace(provider.UsersDN) == "" {
		return errors.New("users DN is required")
	}
	if _, err := ldap.ParseDN(provider.UsersDN); err != nil {
		return fmt.Errorf("users DN is invalid: %w", err)
	}
	if provider.BindDN != "" {
		if _, err := ldap.ParseDN(provider.BindDN); err != nil {
			return fmt.Errorf("bind DN is invalid: %w", err)
		}
		if credentialRequired && bindCredential == "" {
			return errors.New("bind credential is required when bind DN is configured")
		}
	}
	attributes := map[string]string{
		"username": provider.UsernameLDAPAttribute, "RDN": provider.RDNLDAPAttribute,
		"UUID": provider.UUIDLDAPAttribute, "email": provider.EmailLDAPAttribute,
		"first name": provider.FirstNameLDAPAttribute, "last name": provider.LastNameLDAPAttribute,
		"display name": provider.DisplayNameLDAPAttribute, "memberOf": provider.MemberOfLDAPAttribute,
	}
	for label, attribute := range attributes {
		if attribute != "" && !ldapAttributePattern.MatchString(attribute) {
			return fmt.Errorf("%s LDAP attribute is invalid", label)
		}
	}
	if provider.UsernameLDAPAttribute == "" || provider.UUIDLDAPAttribute == "" || provider.RDNLDAPAttribute == "" {
		return errors.New("username, RDN, and UUID LDAP attributes are required")
	}
	if len(provider.UserObjectClasses) == 0 {
		return errors.New("at least one user object class is required")
	}
	for _, class := range provider.UserObjectClasses {
		if !ldapAttributePattern.MatchString(class) {
			return fmt.Errorf("user object class %q is invalid", class)
		}
	}
	if provider.UserLDAPFilter != "" {
		if _, err := ldap.CompileFilter(provider.UserLDAPFilter); err != nil {
			return fmt.Errorf("user LDAP filter is invalid: %w", err)
		}
	}
	if provider.SearchScope != "ONE_LEVEL" && provider.SearchScope != "SUBTREE" {
		return errors.New("search scope must be ONE_LEVEL or SUBTREE")
	}
	if provider.CACertificate != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(provider.CACertificate)) {
			return errors.New("CA certificate does not contain a valid PEM certificate")
		}
	}
	return nil
}

func TestConnection(ctx context.Context, config RuntimeConfig) error {
	connection, err := connect(ctx, config)
	if err != nil {
		return err
	}
	defer connection.Close()
	request := ldap.NewSearchRequest(config.Provider.UsersDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, 5, false, "(objectClass=*)", []string{"1.1"}, nil)
	if _, err := connection.Search(request); err != nil {
		return fmt.Errorf("search users DN: %w", err)
	}
	return nil
}

func Authenticate(ctx context.Context, config RuntimeConfig, username, password string) (User, bool, error) {
	if password == "" {
		return User{}, false, nil
	}
	connection, err := connect(ctx, config)
	if err != nil {
		return User{}, false, err
	}
	result, err := search(connection, config.Provider, username, 2)
	connection.Close()
	if err != nil {
		return User{}, false, fmt.Errorf("search LDAP user: %w", err)
	}
	if len(result.Entries) != 1 {
		return User{}, false, nil
	}
	user := entryToUser(config.Provider, result.Entries[0])
	if user.Username == "" || user.ExternalID == "" {
		return User{}, false, errors.New("LDAP user is missing the configured username or UUID attribute")
	}
	userConnection, err := dial(ctx, config.Provider)
	if err != nil {
		return User{}, false, err
	}
	defer userConnection.Close()
	if err := userConnection.Bind(user.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return User{}, false, nil
		}
		return User{}, false, fmt.Errorf("bind LDAP user: %w", err)
	}
	return user, true, nil
}

func FetchUsers(ctx context.Context, config RuntimeConfig) ([]User, error) {
	connection, err := connect(ctx, config)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	result, err := search(connection, config.Provider, "", 0)
	if err != nil {
		return nil, fmt.Errorf("search LDAP users: %w", err)
	}
	users := make([]User, 0, len(result.Entries))
	for _, entry := range result.Entries {
		user := entryToUser(config.Provider, entry)
		if user.Username == "" || user.ExternalID == "" {
			continue
		}
		users = append(users, user)
	}
	return users, nil
}

func UpdateUser(ctx context.Context, config RuntimeConfig, dn, email, displayName string) error {
	connection, err := connect(ctx, config)
	if err != nil {
		return err
	}
	defer connection.Close()
	request := userModifyRequest(config.Provider, dn, email, displayName)
	if err := connection.Modify(request); err != nil {
		return fmt.Errorf("update LDAP user: %w", err)
	}
	return nil
}

func userModifyRequest(provider domain.LDAPFederation, dn, email, displayName string) *ldap.ModifyRequest {
	request := ldap.NewModifyRequest(dn, nil)
	if provider.EmailLDAPAttribute != "" {
		if email == "" {
			// RFC 4511 deletes the complete attribute when a delete change has
			// no values. Replacing it with a single empty value is rejected by
			// common LDAP schemas instead of clearing optional mail attributes.
			request.Delete(provider.EmailLDAPAttribute, nil)
		} else {
			request.Replace(provider.EmailLDAPAttribute, []string{email})
		}
	}
	if provider.DisplayNameLDAPAttribute != "" {
		request.Replace(provider.DisplayNameLDAPAttribute, []string{displayName})
	}
	return request
}

func ChangePassword(ctx context.Context, config RuntimeConfig, dn, current, replacement string) error {
	if config.Provider.Vendor == "AD" {
		return changeADPassword(ctx, config, dn, current, replacement)
	}
	connection, err := connect(ctx, config)
	if err != nil {
		return err
	}
	defer connection.Close()
	if _, err := connection.PasswordModify(ldap.NewPasswordModifyRequest(dn, current, replacement)); err != nil {
		return fmt.Errorf("change LDAP password: %w", err)
	}
	return nil
}

func connect(ctx context.Context, config RuntimeConfig) (*ldap.Conn, error) {
	connection, err := dial(ctx, config.Provider)
	if err != nil {
		return nil, err
	}
	if config.Provider.BindDN != "" {
		if err := connection.Bind(config.Provider.BindDN, config.BindCredential); err != nil {
			connection.Close()
			return nil, fmt.Errorf("bind service account: %w", err)
		}
	}
	return connection, nil
}

func dial(ctx context.Context, provider domain.LDAPFederation) (*ldap.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tlsConfig, err := tlsConfiguration(provider)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: operationTimeout, KeepAlive: 30 * time.Second}
	connection, err := ldap.DialURL(provider.ConnectionURL, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("connect LDAP server: %w", err)
	}
	connection.SetTimeout(operationTimeout)
	if provider.StartTLS {
		if err := connection.StartTLS(tlsConfig); err != nil {
			connection.Close()
			return nil, fmt.Errorf("start LDAP TLS: %w", err)
		}
	}
	return connection, nil
}

func tlsConfiguration(provider domain.LDAPFederation) (*tls.Config, error) {
	parsed, err := url.Parse(provider.ConnectionURL)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsed.Hostname()}
	if provider.CACertificate != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(provider.CACertificate)) {
			return nil, errors.New("invalid LDAP CA certificate")
		}
		config.RootCAs = pool
	}
	return config, nil
}

func search(connection *ldap.Conn, provider domain.LDAPFederation, username string, sizeLimit int) (*ldap.SearchResult, error) {
	scope := ldap.ScopeWholeSubtree
	if provider.SearchScope == "ONE_LEVEL" {
		scope = ldap.ScopeSingleLevel
	}
	filter := userFilter(provider, username)
	attributes := uniqueStrings([]string{provider.UsernameLDAPAttribute, provider.UUIDLDAPAttribute,
		provider.EmailLDAPAttribute, provider.FirstNameLDAPAttribute, provider.LastNameLDAPAttribute,
		provider.DisplayNameLDAPAttribute, provider.MemberOfLDAPAttribute})
	request := ldap.NewSearchRequest(provider.UsersDN, scope, ldap.NeverDerefAliases, sizeLimit, 10, false,
		filter, attributes, nil)
	if username != "" {
		return connection.Search(request)
	}
	return connection.SearchWithPaging(request, uint32(provider.BatchSize))
}

func userFilter(provider domain.LDAPFederation, username string) string {
	parts := make([]string, 0, len(provider.UserObjectClasses)+2)
	for _, class := range provider.UserObjectClasses {
		parts = append(parts, "(objectClass="+ldap.EscapeFilter(class)+")")
	}
	if provider.UserLDAPFilter != "" {
		parts = append(parts, provider.UserLDAPFilter)
	}
	if username != "" {
		parts = append(parts, "("+provider.UsernameLDAPAttribute+"="+ldap.EscapeFilter(strings.TrimSpace(username))+")")
	}
	return "(&" + strings.Join(parts, "") + ")"
}

func entryToUser(provider domain.LDAPFederation, entry *ldap.Entry) User {
	firstName := strings.TrimSpace(entry.GetAttributeValue(provider.FirstNameLDAPAttribute))
	lastName := strings.TrimSpace(entry.GetAttributeValue(provider.LastNameLDAPAttribute))
	displayName := strings.TrimSpace(entry.GetAttributeValue(provider.DisplayNameLDAPAttribute))
	username := strings.TrimSpace(entry.GetAttributeValue(provider.UsernameLDAPAttribute))
	if displayName == "" {
		displayName = strings.TrimSpace(firstName + " " + lastName)
	}
	if displayName == "" {
		displayName = username
	}
	return User{ExternalID: stableAttributeValue(entry.GetRawAttributeValue(provider.UUIDLDAPAttribute)), DN: entry.DN,
		Username: username, Email: strings.TrimSpace(strings.ToLower(entry.GetAttributeValue(provider.EmailLDAPAttribute))),
		DisplayName: displayName, FirstName: firstName, LastName: lastName,
		MemberOf: entry.GetAttributeValues(provider.MemberOfLDAPAttribute)}
}

func stableAttributeValue(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	if utf8.Valid(value) {
		text := string(value)
		hasControl := false
		for _, character := range text {
			hasControl = hasControl || unicode.IsControl(character)
		}
		if !hasControl {
			return text
		}
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func MappedRoles(provider domain.LDAPFederation, memberOf []string) []string {
	roles := map[string]struct{}{}
	for _, group := range memberOf {
		candidates := []string{strings.ToLower(strings.TrimSpace(group))}
		if parsed, err := ldap.ParseDN(group); err == nil && len(parsed.RDNs) > 0 && len(parsed.RDNs[0].Attributes) > 0 {
			candidates = append(candidates, strings.ToLower(parsed.RDNs[0].Attributes[0].Value))
		}
		for _, candidate := range candidates {
			if role := strings.TrimSpace(provider.GroupRoleMappings[candidate]); role != "" {
				roles[role] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(roles))
	for role := range roles {
		result = append(result, role)
	}
	sort.Strings(result)
	return result
}

func changeADPassword(ctx context.Context, config RuntimeConfig, dn, current, replacement string) error {
	parsed, _ := url.Parse(config.Provider.ConnectionURL)
	if parsed.Scheme != "ldaps" && !config.Provider.StartTLS {
		return errors.New("Active Directory password changes require LDAPS or StartTLS")
	}
	connection, err := connect(ctx, config)
	if err != nil {
		return err
	}
	defer connection.Close()
	request := ldap.NewModifyRequest(dn, nil)
	newValue := quotedUTF16LE(replacement)
	if current == "" {
		request.Replace("unicodePwd", []string{newValue})
	} else {
		request.Delete("unicodePwd", []string{quotedUTF16LE(current)})
		request.Add("unicodePwd", []string{newValue})
	}
	if err := connection.Modify(request); err != nil {
		return fmt.Errorf("change Active Directory password: %w", err)
	}
	return nil
}

func quotedUTF16LE(value string) string {
	codeUnits := utf16.Encode([]rune(`"` + value + `"`))
	encoded := make([]byte, len(codeUnits)*2)
	for index, codeUnit := range codeUnits {
		binary.LittleEndian.PutUint16(encoded[index*2:], codeUnit)
	}
	return string(encoded)
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}
