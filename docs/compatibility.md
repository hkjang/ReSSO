# Keycloak 및 OIDC 호환 범위

## 구현됨

| 기능 | 상태 |
|---|---|
| Realm 기반 Issuer | 구현 |
| OIDC Discovery | 구현 |
| Authorization Code | 구현. 1회 사용이며 재사용 시 해당 Session·Client의 Refresh Token 폐기 |
| PKCE S256 | 구현, Public Client 강제 |
| 인가 응답 `iss` (RFC 9207) | 구현. 성공과 오류 응답 모두에 붙이며, Discovery의 `authorization_response_iss_parameter_supported`로 알립니다. 값은 Discovery의 `issuer`와 같은 문자열이므로 RP에서 Mix-Up 공격 방어를 위한 `iss` 검증을 강제로 켜도 됩니다 |
| `prompt` | 사양대로 공백으로 구분된 목록으로 읽습니다. `login`은 SSO Session이 있어도 재인증을 요구하고, `none`은 재사용할 Session이 없으면 `login_required`를 반환합니다. 화면이 없는 `consent`·`select_account`는 무시하며, 그것들이 함께 와도 `login`·`none` 처리는 그대로입니다. 서로 모순되는 `none`과 `login`을 함께 요구하면 `invalid_request`로 거절합니다 |
| `id_token_hint` | 구현. 지정한 계정과 현재 Session의 사용자가 다르면 조용히 코드를 발급하지 않고 재인증을 요구합니다 |
| `request` / `request_uri` | 미지원. 무시하지 않고 `request_not_supported` / `request_uri_not_supported`로 거절합니다 |
| `max_age` | 구현. 마지막 인증이 지정한 시간보다 오래되었으면 SSO Session이 있어도 재인증을 요구하며, `prompt=none`이면 `login_required`를 반환합니다 |
| ID Token / JWT Access Token | RS256 구현 |
| Refresh Token | 회전·재사용 탐지 구현 |
| Client Credentials | Confidential Client 구현 |
| UserInfo / JWKS | 구현 |
| Introspection / Revocation | 구현. Access Token은 같은 Realm의 모든 Confidential Client가 조회 가능 |
| RP-Initiated Logout | 구현. `id_token_hint` 또는 `client_id` |
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
