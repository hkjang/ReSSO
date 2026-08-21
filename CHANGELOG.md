# Changelog

## v0.2.1

- Data Encryption Keyring과 Digest Keyring을 분리하고, Key ID가 포함된 암호문 Envelope 및 기존 v0.2.0 키 읽기 호환 추가
- 기존 Session, Authorization Code, Refresh Token, 개인 API Key를 유지하는 다중 Digest 조회와 무중단 단계형 키 회전 지원
- `admin diagnose`, `admin recover --password-stdin`, `crypto rewrap` 운영 복구 CLI 추가
- 계정별 로그인 제한은 실패 시에만 증가하고 성공 시 초기화하며 실제 남은 시간을 `Retry-After`로 반환
- Digest Key 활성 순서가 다른 인스턴스도 로그인 제한 버킷을 원자적으로 병합하고, 관리자 복구 시 계정 제한까지 초기화
- MCP OIDC 인증을 활성 사용자 Session에 정확히 결합해 `client_credentials` 주체 혼동과 폐기 Session 재사용 차단
- 이메일을 선택값으로 통일하고 변경·삭제 시 `email_verified`를 해제하며 관리자가 명시적으로 확인할 수 있는 UI 추가
- 비어 있지 않은 이메일의 서버 형식 검증, Keyring 설정 오류의 키 재료 비노출, 변경 상태 감사 metadata 보강
- Authorization Code 동시 소비, Refresh Token 재사용, Keyring 회전, Rate Limit, 관리자 복구를 실제 PostgreSQL에서 검증하는 통합 테스트 추가
- 빈 배열 Client 필드의 `NULL` 저장과 복구 감사 이벤트의 PostgreSQL 타입 추론 오류 수정

### Upgrade notes

- 기존 `ENCRYPTION_KEY` 단일 키 모드는 v0.2.0 형식의 암호문 쓰기를 유지하므로 먼저 모든 인스턴스를 v0.2.1로 안전하게 올릴 수 있습니다. 이후 새 Keyring에 기존 키를 포함하는 단계형 회전을 수행하세요.
- 암호문이 참조하는 Data Encryption Key ID는 변경하거나 다른 키 재료에 재사용하지 마세요. `crypto rewrap`은 Signing Private Key와 LDAP Bind Credential만 재암호화하며 Digest는 재작성하지 않습니다.
- `crypto rewrap`과 `admin diagnose`가 완료되면 이전 Data Encryption Key를 제거할 수 있습니다. 이전 Digest Key는 해당 키로 만든 모든 장기 API Key까지 회전·폐기한 후에만 제거하세요.
- 공식 오프라인 Docker 아카이브는 `linux/amd64` 전용입니다.

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
