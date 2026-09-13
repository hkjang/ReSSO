package mail

import (
	"fmt"
	"mime"
	"strings"
	"time"
)

// compose builds the MIME message. Korean subjects are encoded so relays and
// clients that predate UTF-8 headers still show them.
func compose(config Config, message Message) string {
	var builder strings.Builder
	builder.WriteString("From: " + encodeAddress(config.From()) + "\r\n")
	builder.WriteString("To: " + message.To + "\r\n")
	builder.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", message.Subject) + "\r\n")
	builder.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	builder.WriteString("MIME-Version: 1.0\r\n")
	builder.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	builder.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	builder.WriteString("Auto-Submitted: auto-generated\r\n")
	builder.WriteString("X-ReSSO-Notification: 1\r\n")
	builder.WriteString("\r\n")
	builder.WriteString(normalizeBody(message.Body))
	return builder.String()
}

func encodeAddress(address string) string {
	open := strings.LastIndex(address, "<")
	if open <= 0 {
		return address
	}
	return mime.QEncoding.Encode("utf-8", strings.TrimSpace(address[:open])) + " " + address[open:]
}

// normalizeBody uses CRLF line endings. Leading dots are left alone: the
// DATA writer of net/smtp stuffs them itself, and doing it here as well put
// two dots in front of every such line.
func normalizeBody(body string) string {
	body = strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")
	if !strings.HasSuffix(body, "\r\n") {
		body += "\r\n"
	}
	return body
}

// Notification is one event mail before its recipients are resolved.
type Notification struct {
	Event   string
	Subject string
	Lines   []string
	// Reference identifies what the mail is about, for the delivery record.
	Reference string
	// Path is where in the console the reader should go, appended to
	// mail.base_url when one is configured.
	Path string
}

// Render is the message body: the lines, the console link when the base URL
// is known, and a footer that says why the mail arrived.
func (n Notification) Render(config Config) string {
	lines := append([]string{}, n.Lines...)
	base := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	if base != "" && n.Path != "" {
		lines = append(lines, "", "바로 열기: "+base+"/"+strings.TrimLeft(n.Path, "/"))
	}
	lines = append(lines, "", "—", "이 메일은 ReSSO 알림 설정에 따라 자동으로 발송되었습니다. 서비스 관리자가 관리 화면의 메일 알림에서 종류별로 끌 수 있습니다.")
	return strings.Join(lines, "\n")
}

// ApprovalRequested tells a reviewer that somebody is waiting on them.
func ApprovalRequested(requester, realm, role, reason, requestID string) Notification {
	lines := []string{fmt.Sprintf("%s 님이 %s Realm의 '%s' Role을 요청했습니다.", requester, realm, role)}
	if strings.TrimSpace(reason) != "" {
		lines = append(lines, "", quote(reason))
	}
	lines = append(lines, "", "승인하거나 거절하기 전까지 요청한 사람은 그 Role 없이 기다립니다.")
	return Notification{Event: EventApprovalRequested, Subject: fmt.Sprintf("[ReSSO] %s 님의 '%s' Role 승인 요청", requester, role),
		Lines: lines, Reference: requestID, Path: "/personal/requests"}
}

// ApprovalDecided tells the requester what was decided.
func ApprovalDecided(realm, role, status, note, requestID string) Notification {
	result := "거절되었습니다"
	if status == "APPROVED" {
		result = "승인되었습니다. 다음 로그인부터 그 Role이 적용됩니다"
	}
	lines := []string{fmt.Sprintf("%s Realm의 '%s' Role 요청이 %s.", realm, role, result)}
	if strings.TrimSpace(note) != "" {
		lines = append(lines, "", quote(note))
	}
	return Notification{Event: EventApprovalDecided, Subject: fmt.Sprintf("[ReSSO] '%s' Role 요청이 처리되었습니다", role),
		Lines: lines, Reference: requestID, Path: "/personal/requests"}
}

// ExpiringKey is one personal API key about to expire, as the warning lists it.
type ExpiringKey struct {
	ID        string
	Name      string
	Prefix    string
	ExpiresAt time.Time
}

// APIKeysExpiring warns the owner about every key of theirs that expires
// within the week — one mail, however many keys, so a person with five keys
// made on the same day gets one message and not five.
func APIKeysExpiring(keys []ExpiringKey) Notification {
	lines := []string{"다음 개인 API 키가 곧 만료됩니다. 만료되면 그 키를 쓰는 연동이 예고 없이 멈춥니다.", ""}
	references := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("- %s (%s…) — %s 만료", key.Name, key.Prefix, key.ExpiresAt.Local().Format("2006-01-02 15:04")))
		references = append(references, key.ID)
	}
	lines = append(lines, "", "계속 쓰려면 개인 설정의 API 키 화면에서 회전하세요. 회전하면 같은 이름과 범위의 새 키가 나오고 옛 키는 곧 멈춥니다.")
	subject := "[ReSSO] 개인 API 키가 곧 만료됩니다"
	if len(keys) == 1 {
		subject = fmt.Sprintf("[ReSSO] 개인 API 키 '%s'가 곧 만료됩니다", keys[0].Name)
	}
	return Notification{Event: EventAPIKeyExpiring, Subject: subject, Lines: lines,
		Reference: strings.Join(references, ","), Path: "/personal/api-keys"}
}

// FederationSyncFailed tells the service administrators that a scheduled
// directory sync that used to work has stopped.
func FederationSyncFailed(realm, federation, cause, federationID string) Notification {
	return Notification{Event: EventFederationFailed,
		Subject: fmt.Sprintf("[ReSSO] %s Realm의 LDAP 동기화 '%s'가 실패했습니다", realm, federation),
		Lines: []string{
			fmt.Sprintf("%s Realm의 User Federation '%s'의 예약 동기화가 실패했습니다.", realm, federation),
			"", quote(cause), "",
			"해결될 때까지 디렉터리의 입사자는 계정을 받지 못하고 퇴사자 계정은 비활성화되지 않습니다.",
			"다시 성공하기 전까지 이 메일은 다시 보내지 않습니다.",
		},
		Reference: federationID, Path: "/admin/user-federation"}
}

// TestMessage proves the relay works from the settings screen.
func TestMessage() Notification {
	return Notification{Event: EventTest, Subject: "[ReSSO] SMTP 발송 테스트",
		Lines: []string{"ReSSO 관리 화면에서 보낸 테스트 메일입니다.", "이 메일을 받았다면 SMTP 설정이 정상입니다."}}
}

func quote(body string) string {
	trimmed := strings.TrimSpace(body)
	if len([]rune(trimmed)) > 500 {
		trimmed = string([]rune(trimmed)[:500]) + "…"
	}
	lines := strings.Split(trimmed, "\n")
	for index, line := range lines {
		lines[index] = "> " + line
	}
	return strings.Join(lines, "\n")
}
