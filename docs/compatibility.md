# Keycloak 및 OIDC 호환 범위

## 구현됨

| 기능 | 상태 |
|---|---|
| Realm 기반 Issuer | 구현 |
| OIDC Discovery | 구현 |
| Authorization Code | 구현 |
| PKCE S256 | 구현, Public Client 강제 |
| ID Token / JWT Access Token | RS256 구현 |
| Refresh Token | 회전·재사용 탐지 구현 |
| Client Credentials | Confidential Client 구현 |
| UserInfo / JWKS | 구현 |
| Introspection / Revocation | 구현 |
| RP-Initiated Logout | 구현 |
| Keycloak `realm_access` / `resource_access` Claim | 구현 |
| Keycloak URL 구조 | 핵심 OIDC Endpoint 구현 |
| SSO Browser Session | PostgreSQL 기반 구현 |

## 아직 구현하지 않음

- Dynamic Client Registration
- Device Authorization, CIBA, Token Exchange
- SAML, LDAP/AD Federation, Kerberos
- 외부 OIDC/SAML Identity Broker
- TOTP/WebAuthn/Passkey MFA
- Front-channel / Back-channel Logout 알림 전송
- Keycloak Admin REST API wire compatibility
- Keycloak Theme 또는 전체 Admin Console 호환

ReSSO의 목표는 Keycloak 전체 복제가 아니라 issuer 변경만으로 일반 OIDC Client가 연동되는 핵심 L3~L4 호환 서버입니다. 기존 애플리케이션이 Keycloak Admin API, SAML 또는 고유 SPI를 사용한다면 별도의 Migration 분석이 필요합니다.

## 검증 권장사항

- Spring Security Resource Server의 `issuer-uri` 변경 테스트
- 사용하는 SDK별 Discovery → Code+PKCE → Token → UserInfo → Refresh → Logout 테스트
- `iss`, `aud`, `nonce`, `state`, `sid`, `realm_access`, `resource_access` Claim 회귀 테스트
- OpenID Foundation Conformance Suite는 운영 승격 전 별도 수행 권장
