# Changelog

## v0.2.0

- LDAP/Active Directory User Federation: LDAPS/StartTLS, 연결·인증 테스트, JIT·전체·주기 동기화, Group→Role 매핑
- Realm Role과 Client Role CRUD, 사용자별 수동 할당·회수, LDAP 관리 Role 보존
- `realm-admin`을 실제 Realm 범위 관리 권한으로 연결하고 교차 Realm 접근 차단
- Client Web Origin 기반 OIDC CORS와 정확한 Origin 검증
- `profile`, `email`, `roles` Scope에 따른 Claim 최소화, 명시적인 `email_verified`, 최초 Session 기준 `auth_time`
- PostgreSQL 공용 로그인 Rate Limit과 신뢰 Proxy CIDR 기반 Client IP/TLS 판정
- 개인 API Key `api:read` 및 관리자 `admin:read` REST GET 인증
- 실제 운영 위험을 표시하는 관리자 준비 상태 대시보드와 사용자 목록 페이지네이션
- 이메일이 없는 사용자에게 합성 주소를 만들지 않고 여러 빈 이메일 계정을 허용
- PostgreSQL 통합 Smoke Test를 CI와 Release workflow에 추가

### Upgrade notes

- Migration `003_hardening.sql`이 이메일 검증 상태와 로그인 제한 테이블을 추가합니다.
- 기존 Client에는 `roles` 기본 Scope가 자동으로 추가되어 v0.1.x의 Role Claim 동작을 유지합니다.
- Reverse Proxy Header는 `TRUSTED_PROXY_CIDRS`에 등록된 발신지에서만 신뢰합니다. 운영 Proxy CIDR을 배포 전에 설정하세요.
