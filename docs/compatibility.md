# Keycloak 및 OIDC 호환 범위

## 구현됨

| 기능 | 상태 |
|---|---|
| Realm 기반 Issuer | 구현 |
| OIDC Discovery | 구현. Realm이 **없거나 꺼져 있으면** 404 `realm_not_found`, 이 서비스가 Realm을 **조회하지 못하면** 500 `internal_error`입니다 — JWKS·인가·로그아웃 Endpoint도 같습니다. RP 라이브러리는 404를 "이 Issuer는 존재하지 않는다"는 설정 오류로 읽고 캐시하기도 하므로, 이쪽 장애는 404가 아니라 재시도할 5xx로 알립니다. Revocation은 같은 이유로 200 대신 503입니다(200은 "일치하는 Token이 없다"는 뜻이라, 조회조차 못 한 경우에 쓰면 아직 살아 있는 Token을 폐기했다고 답하는 것이 됩니다) |
| Authorization Code | 구현. 1회 사용이며 재사용 시 해당 Session·Client의 Refresh Token 폐기 |
| 인가 Endpoint의 `client_id` | 등록되지 않았거나 **꺼진** Client는 400 `invalid_request` "unknown client_id", 이 서비스가 Client를 **조회하지 못하면** 500 `server_error`입니다. 400은 RP의 설정에 관한 단언이라 RP가 재시도할 것이 없으므로(사람이 등록을 고쳐야 합니다), 이쪽 장애를 그렇게 알리면 Realm의 모든 연동에 "너희는 등록이 해지되었다"고 한꺼번에 통지하는 것이 됩니다. 500은 `redirect_uri`로 리다이렉트되지 않고 본문으로 나갑니다 — `redirect_uri` 검증이 바로 이 Client 레코드로 이루어지므로, 이 시점에는 호출자의 것임이 확인된 목적지가 없습니다 |
| PKCE S256 | 구현, Public Client 강제 |
| 인가 응답 `iss` (RFC 9207) | 구현. 성공과 오류 응답 모두에 붙이며, Discovery의 `authorization_response_iss_parameter_supported`로 알립니다. 값은 Discovery의 `issuer`와 같은 문자열이므로 RP에서 Mix-Up 공격 방어를 위한 `iss` 검증을 강제로 켜도 됩니다 |
| `prompt` | 사양대로 공백으로 구분된 목록으로 읽습니다. `login`은 SSO Session이 있어도 재인증을 요구하고, `none`은 재사용할 Session이 없으면 `login_required`를 반환합니다. Session이 **없는** 것과 이 서비스가 Session을 **조회하지 못한** 것은 구분하며, 후자는 `server_error`입니다 — `login_required`는 RP가 조용한 갱신에서 "사용자가 로그아웃했다"로 읽고 자신의 Session도 끝내는 신호이므로, 이쪽 장애를 그렇게 알리면 장애가 전 RP 로그아웃이 됩니다. 화면이 없는 `consent`·`select_account`는 무시하며, 그것들이 함께 와도 `login`·`none` 처리는 그대로입니다. 서로 모순되는 `none`과 `login`을 함께 요구하면 `invalid_request`로 거절합니다 |
| `id_token_hint` | 구현. 지정한 계정과 현재 Session의 사용자가 다르면 조용히 코드를 발급하지 않고 재인증을 요구합니다. **그 재인증까지 hint를 지킵니다** — hint는 인가 요청과 함께 보관되고, 로그인 화면에서 다른 계정으로 로그인하면 코드를 발급하지 않고 403 `account_mismatch`로 답합니다(로그인 자체는 성공하며 감사 기록은 `LOGIN_SUCCESS` `result=PARTIAL`, 상세 `reason=id_token_hint_mismatch`입니다). 요청은 소진되지 않으므로 같은 화면에서 지정된 계정으로 다시 로그인하면 흐름이 이어집니다. 응답은 어느 계정인지 밝히지 않습니다 |
| `request` / `request_uri` | 미지원. 무시하지 않고 `request_not_supported` / `request_uri_not_supported`로 거절합니다 |
| `max_age` | 구현. 마지막 인증이 지정한 시간보다 오래되었으면 SSO Session이 있어도 재인증을 요구하며, `prompt=none`이면 `login_required`를 반환합니다. 로그인 화면을 거친 요청은 항상 새 Session을 만들므로(`auth_time`이 그 시점입니다) 값을 따로 보관하지 않아도 충족됩니다. 숫자가 아니거나 음수인 값은 `invalid_request`로 거절하지만, **아무리 큰 값도 거절하지 않고 2147483647초로 clamp합니다** — SSO Session의 수명 상한이 30일이므로 그보다 큰 `max_age`는 존재하는 어떤 Session이든 충족하며, 답은 같습니다 |
| ID Token / JWT Access Token | RS256 구현 |
| Refresh Token | 회전·재사용 탐지 구현 |
| Client Credentials | Confidential Client 구현 |
| UserInfo / JWKS | 구현 |
| Introspection / Revocation | 구현. Access Token은 같은 Realm의 모든 Confidential Client가 조회 가능 |
| RP-Initiated Logout | 구현. `id_token_hint` 또는 `client_id`. `id_token_hint`는 만료된 ID Token도 받습니다(RP가 로그아웃 시점에 들고 있는 것이 보통 만료된 토큰입니다). Access Token은 hint가 아닙니다. 어느 쪽으로 지목하든 Client를 **조회하지 못하면** `post_logout_redirect_uri`는 쓰지 않습니다(등록 목록을 읽지 못한 목적지를 허용할 수는 없습니다). 로그아웃 자체는 그대로 수행하고 브라우저는 이 서비스의 페이지로 돌아오며, 그 이유는 `the client named at logout could not be looked up` 로그로만 드러납니다 |
| Back-Channel Logout | 구현. Session 참여 Client에 서명된 `logout_token` 전송 |
| ID Token `at_hash` | 구현 |
| Keycloak `realm_access` / `resource_access` Claim | 구현 |
| Keycloak URL 구조 | 핵심 OIDC Endpoint 구현 |
| SSO Browser Session | PostgreSQL 기반 구현 |
| LDAP/AD User Federation | Simple Bind, LDAPS/StartTLS, JIT·전체·주기 동기화 구현 |
| LDAP 속성 및 Group→Role 매핑 | 직접 `memberOf` 매핑 구현 |
| OIDC CORS | Client별 정확한 Web Origin 허용 |
| Realm/Client Role 관리 | 관리자 할당·회수 및 Claim 반영 구현 |
| Realm 관리자 위임 | `realm-admin` Role의 Realm 범위 관리 구현 |

## 아직 구현하지 않음

- Dynamic Client Registration
- Device Authorization, CIBA, Token Exchange
- SAML, Kerberos/SPNEGO
- 외부 OIDC/SAML Identity Broker
- TOTP/WebAuthn/Passkey MFA
- Front-channel Logout 알림 전송
- Keycloak Admin REST API wire compatibility
- Keycloak Theme 또는 전체 Admin Console 호환
- LDAP Changed Users Sync, 중첩 Group 탐색, LDAP Connection Pool

Claim은 Scope에 따라 최소화됩니다. `profile`은 이름·사용자명, `email`은 등록된 이메일과 검증 상태, `roles`는 `realm_access`와 `resource_access`를 제공합니다. 이메일이 비어 있으면 `email`과 `email_verified` Claim도 생략합니다. v0.2.0 Migration은 기존 Client에 `roles` 기본 Scope를 추가해 이전 동작을 유지합니다.

`email_verified=true`는 ReSSO가 확인 메일을 발송해 소유권을 검증했다는 뜻이 아니라, Realm 관리자가 조직의 절차와 외부 근거에 따라 해당 이메일을 확인했다는 관리적 attestation입니다. Relying Party는 이 Claim을 조직의 관리자 확인 정책 수준으로 해석해야 하며, 이메일 링크 challenge가 필요한 계정 연결·복구 흐름에서는 별도의 검증을 수행해야 합니다.

Access Token의 `aud`는 발급 Client 자신입니다. 별도 Resource Server를 audience로 하는 Token 발급은 아직 지원하지 않으므로, API는 Introspection 또는 `azp` 기반 인가를 사용해야 합니다.

ReSSO의 목표는 Keycloak 전체 복제가 아니라 issuer 변경만으로 일반 OIDC Client가 연동되는 핵심 L3~L4 호환 서버입니다. 기존 애플리케이션이 Keycloak Admin API, SAML 또는 고유 SPI를 사용한다면 별도의 Migration 분석이 필요합니다.

## 검증 권장사항

- Spring Security Resource Server의 `issuer-uri` 변경 테스트
- 사용하는 SDK별 Discovery → Code+PKCE → Token → UserInfo → Refresh → Logout 테스트
- `iss`, `aud`, `nonce`, `state`, `sid`, `at_hash`, `realm_access`, `resource_access` Claim 회귀 테스트
- Back-Channel Logout을 사용하는 RP는 `logout_token` 검증(JWKS 서명, `iss`, `aud`, `events`, `sid`, `nonce` 부재) 테스트
- OpenID Foundation Conformance Suite는 운영 승격 전 별도 수행 권장
