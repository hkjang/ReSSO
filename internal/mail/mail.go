// Package mail sends event notifications through the company SMTP relay.
//
// An internal relay usually takes mail on port 25 with no credentials and no
// TLS, so that is the default and both authentication and encryption are
// optional, negotiated only as far as the relay advertises. Nothing here holds
// a request: sending happens in the background, and every attempt is recorded
// so an administrator can see what left the building and answer "it never
// arrived".
package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

var (
	// ErrDisabled is answered when a test send is asked for while mail is off.
	ErrDisabled = errors.New("메일 알림이 꺼져 있습니다")
	// ErrInvalid marks a configuration the relay can never be reached with.
	ErrInvalid = errors.New("메일 설정이 올바르지 않습니다")
)

// Security is how the connection to the relay is protected.
const (
	SecurityAuto     = "auto"
	SecurityNone     = "none"
	SecurityStartTLS = "starttls"
	SecurityTLS      = "tls"
)

// Config is the relay configuration as the sender needs it. Username and
// password are never serialized: the settings API answers with View.
type Config struct {
	Enabled     bool
	Host        string
	Port        int
	Security    string
	SkipVerify  bool
	Username    string
	Password    string
	FromAddress string
	FromName    string
	BaseURL     string
	Timeout     time.Duration
	// Events holds the per-event switches that were explicitly set; an
	// event absent here is on, so a new notification never needs a settings
	// change before it is sent.
	Events map[string]bool
}

// Allows reports whether an event is switched on.
func (c Config) Allows(event string) bool {
	if enabled, known := c.Events[event]; known {
		return enabled
	}
	return true
}

// From is the RFC 5322 From header value.
func (c Config) From() string {
	from := strings.TrimSpace(c.FromAddress)
	if name := strings.TrimSpace(c.FromName); name != "" {
		return fmt.Sprintf("%s <%s>", name, from)
	}
	return from
}

func (c Config) endpoint() string { return net.JoinHostPort(c.Host, fmt.Sprint(c.Port)) }

// Validate says why a relay could not be reached with this configuration.
// It is what a send fails with while the settings are incomplete, and what
// the settings screen refuses to save when a value can never work.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Host) == "" {
		return fmt.Errorf("%w: mail.smtp_host가 비어 있습니다", ErrInvalid)
	}
	if err := c.ValidateShape(); err != nil {
		return err
	}
	if !strings.Contains(c.FromAddress, "@") {
		return fmt.Errorf("%w: mail.from_address는 메일 주소여야 합니다", ErrInvalid)
	}
	return nil
}

// ValidateShape checks the values that are wrong regardless of whether the
// relay has been named yet, so saving a half-filled screen is allowed but a
// port that cannot exist is not.
func (c Config) ValidateShape() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("%w: mail.smtp_port는 1에서 65535 사이여야 합니다", ErrInvalid)
	}
	switch c.Security {
	case SecurityAuto, SecurityNone, SecurityStartTLS, SecurityTLS:
	default:
		return fmt.Errorf("%w: mail.security는 auto, none, starttls, tls 중 하나여야 합니다", ErrInvalid)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("%w: mail.timeout_seconds는 0보다 커야 합니다", ErrInvalid)
	}
	return nil
}

// Message is one mail to one recipient, ready to send.
type Message struct {
	To      string
	Subject string
	Body    string
}

// Deliver opens a connection to the relay and sends one message. Exported so
// the settings screen can prove the relay works before anything depends on it.
func Deliver(ctx context.Context, config Config, message Message) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(message.To) == "" {
		return fmt.Errorf("%w: 받는 사람이 비어 있습니다", ErrInvalid)
	}
	client, err := dial(ctx, config)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	if err := startSession(client, config); err != nil {
		return err
	}
	if err := client.Mail(strings.TrimSpace(config.FromAddress)); err != nil {
		return fmt.Errorf("MAIL FROM 실패: %w", err)
	}
	if err := client.Rcpt(strings.TrimSpace(message.To)); err != nil {
		return fmt.Errorf("RCPT TO 실패: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA 실패: %w", err)
	}
	if _, err := writer.Write([]byte(compose(config, message))); err != nil {
		return fmt.Errorf("본문 전송 실패: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("본문 종료 실패: %w", err)
	}
	return client.Quit()
}

func dial(ctx context.Context, config Config) (*smtp.Client, error) {
	dialer := &net.Dialer{Timeout: config.Timeout}
	var connection net.Conn
	var err error
	if config.Security == SecurityTLS {
		connection, err = (&tls.Dialer{NetDialer: dialer, Config: config.tlsConfig()}).DialContext(ctx, "tcp", config.endpoint())
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", config.endpoint())
	}
	if err != nil {
		return nil, fmt.Errorf("SMTP 연결 실패: %w", err)
	}
	// The relay conversation is bounded by the same timeout as the dial, so
	// a relay that accepts the connection and then says nothing cannot hold
	// a goroutine forever.
	deadline := time.Now().Add(config.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = connection.SetDeadline(deadline)
	client, err := smtp.NewClient(connection, config.Host)
	if err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("SMTP 세션 시작 실패: %w", err)
	}
	return client, nil
}

// startSession upgrades and authenticates only as far as the relay allows, so
// an unauthenticated internal relay works with the same settings as a hosted
// provider that demands both.
func startSession(client *smtp.Client, config Config) error {
	if err := client.Hello(helloName(config)); err != nil {
		return fmt.Errorf("EHLO 실패: %w", err)
	}
	if config.Security == SecurityStartTLS || config.Security == SecurityAuto {
		if supported, _ := client.Extension("STARTTLS"); supported {
			if err := client.StartTLS(config.tlsConfig()); err != nil {
				return fmt.Errorf("STARTTLS 실패: %w", err)
			}
		} else if config.Security == SecurityStartTLS {
			return fmt.Errorf("%w: 릴레이가 STARTTLS를 지원하지 않습니다", ErrInvalid)
		}
	}
	if strings.TrimSpace(config.Username) == "" {
		return nil
	}
	supported, mechanisms := client.Extension("AUTH")
	if !supported {
		return fmt.Errorf("%w: 릴레이가 인증을 지원하지 않습니다. 사용자 이름을 비우고 사용하세요", ErrInvalid)
	}
	var auth smtp.Auth
	switch {
	case strings.Contains(strings.ToUpper(mechanisms), "PLAIN"):
		auth = smtp.PlainAuth("", config.Username, config.Password, config.Host)
	case strings.Contains(strings.ToUpper(mechanisms), "LOGIN"):
		auth = loginAuth{username: config.Username, password: config.Password, host: config.Host}
	default:
		auth = smtp.CRAMMD5Auth(config.Username, config.Password)
	}
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP 인증 실패: %w", err)
	}
	return nil
}

func (c Config) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.SkipVerify} //nolint:gosec // opt-in for internal relays with private certificates
}

// helloName keeps the EHLO name to the sender's domain; relays that check the
// greeting accept that more readily than a container hostname.
func helloName(config Config) string {
	if index := strings.LastIndex(config.FromAddress, "@"); index >= 0 && index+1 < len(config.FromAddress) {
		return config.FromAddress[index+1:]
	}
	return "localhost"
}

// loginAuth is the LOGIN mechanism several corporate relays offer instead of
// PLAIN; the standard library ships only PLAIN and CRAM-MD5.
type loginAuth struct{ username, password, host string }

func (a loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && server.Name != a.host {
		return "", nil, errors.New("LOGIN 인증은 신뢰할 수 있는 서버에서만 사용합니다")
	}
	return "LOGIN", nil, nil
}

func (a loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimRight(string(fromServer), ": ")) {
	case "username":
		return []byte(a.username), nil
	case "password":
		return []byte(a.password), nil
	}
	return nil, fmt.Errorf("알 수 없는 LOGIN 요청: %s", fromServer)
}
