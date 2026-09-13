package mail

import (
	"strings"
	"time"
)

// Setting keys. They are the ones every service on the network uses, so an
// operator who has configured one has configured them all.
const (
	KeyEnabled       = "mail.enabled"
	KeyHost          = "mail.smtp_host"
	KeyPort          = "mail.smtp_port"
	KeySecurity      = "mail.security"
	KeySkipTLSVerify = "mail.skip_tls_verify"
	KeyUsername      = "mail.username"
	KeyPassword      = "mail.password"
	KeyFromAddress   = "mail.from_address"
	KeyFromName      = "mail.from_name"
	KeyBaseURL       = "mail.base_url"
	KeyTimeout       = "mail.timeout_seconds"
)

// Event names. Each is also the suffix of the setting that switches it off.
const (
	EventApprovalRequested = "approval.requested"
	EventApprovalDecided   = "approval.decided"
	EventAPIKeyExpiring    = "api_key.expiring"
	EventFederationFailed  = "federation.sync_failed"
	EventTest              = "test"
)

// EventSetting is the switch for one event, as the settings screen lists it.
type EventSetting struct {
	Event       string `json:"event"`
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// Events are the notifications this service sends, in the order the screen
// shows them. The test mail has no switch: it is sent by hand.
var Events = []EventSetting{
	{Event: EventApprovalRequested, Key: "mail.notify_approval_request", Label: "승인 요청이 도착함",
		Description: "검토자(지정된 관리자, 없으면 Realm 관리자)에게. 오지 않으면 요청한 사람은 기약 없이 기다립니다."},
	{Event: EventApprovalDecided, Key: "mail.notify_approval_decision", Label: "승인 요청이 결정됨",
		Description: "요청한 사람에게. 오지 않으면 내 요청 화면을 계속 새로 고치게 됩니다."},
	{Event: EventAPIKeyExpiring, Key: "mail.notify_api_key_expiry", Label: "개인 API 키 만료 임박",
		Description: "키 소유자에게, 만료 7일 전 한 번. 오지 않으면 연동이 예고 없이 멈춥니다."},
	{Event: EventFederationFailed, Key: "mail.notify_federation_failure", Label: "예약 LDAP 동기화 실패",
		Description: "서비스 관리자에게, 성공하던 동기화가 실패로 바뀔 때 한 번. 오지 않으면 입사자 계정이 생기지 않고 퇴사자 계정이 남습니다."},
}

// Keys is every setting the screen may write, so a key that is not one of
// these is refused rather than stored.
func Keys() []string {
	keys := []string{KeyEnabled, KeyHost, KeyPort, KeySecurity, KeySkipTLSVerify, KeyUsername, KeyPassword,
		KeyFromAddress, KeyFromName, KeyBaseURL, KeyTimeout}
	for _, event := range Events {
		keys = append(keys, event.Key)
	}
	return keys
}

// Defaults are the common internal relay: port 25, no credentials, whatever
// security the relay advertises.
const (
	DefaultPort     = 25
	DefaultSecurity = SecurityAuto
	DefaultTimeout  = 10 * time.Second
	DefaultFromName = "ReSSO"
)

// Read builds the configuration from stored values. A missing key is its
// default, so an installation nobody configured is off.
func Read(values map[string]any) Config {
	config := Config{Port: DefaultPort, Security: DefaultSecurity, Timeout: DefaultTimeout, Events: map[string]bool{}}
	config.Enabled = boolValue(values, KeyEnabled)
	config.Host = stringValue(values, KeyHost, "")
	config.Username = stringValue(values, KeyUsername, "")
	config.Password = stringValue(values, KeyPassword, "")
	config.FromAddress = stringValue(values, KeyFromAddress, "")
	config.FromName = stringValue(values, KeyFromName, DefaultFromName)
	config.Security = strings.ToLower(stringValue(values, KeySecurity, DefaultSecurity))
	config.BaseURL = stringValue(values, KeyBaseURL, "")
	config.SkipVerify = boolValue(values, KeySkipTLSVerify)
	if port, ok := numberValue(values, KeyPort); ok && port > 0 {
		config.Port = port
	}
	if seconds, ok := numberValue(values, KeyTimeout); ok && seconds > 0 {
		config.Timeout = time.Duration(seconds) * time.Second
	}
	// The implicit-TLS port needs no further configuration.
	if config.Security == SecurityAuto && config.Port == 465 {
		config.Security = SecurityTLS
	}
	for _, event := range Events {
		if enabled, ok := values[event.Key].(bool); ok {
			config.Events[event.Event] = enabled
		}
	}
	return config
}

// View is what the settings API answers: every stored value with its default
// filled in, and the password replaced by whether one is set. The password
// leaves this process only towards the relay.
func View(values map[string]any) map[string]any {
	config := Read(values)
	view := map[string]any{
		KeyEnabled: config.Enabled, KeyHost: config.Host, KeyPort: config.Port, KeySecurity: config.Security,
		KeySkipTLSVerify: config.SkipVerify, KeyUsername: config.Username, KeyFromAddress: config.FromAddress,
		KeyFromName: config.FromName, KeyBaseURL: config.BaseURL, KeyTimeout: int(config.Timeout / time.Second),
	}
	for _, event := range Events {
		view[event.Key] = config.Allows(event.Event)
	}
	return view
}

func boolValue(values map[string]any, key string) bool {
	enabled, _ := values[key].(bool)
	return enabled
}

func stringValue(values map[string]any, key, fallback string) string {
	if value, ok := values[key].(string); ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func numberValue(values map[string]any, key string) (int, bool) {
	switch typed := values[key].(type) {
	case float64:
		return int(typed), true
	case int:
		return typed, true
	case int64:
		return int(typed), true
	}
	return 0, false
}
