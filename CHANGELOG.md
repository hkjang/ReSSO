# Changelog

## v0.3.0

### 보안

- Client Secret 검증을 Argon2에서 Digest Keyring 기반 HMAC으로 전환. Client Secret은 ReSSO가 생성하는 256bit 난수라 Password Stretching이 불필요한 반면, 인증 없이 호출 가능한 Token·Introspection·Revocation endpoint에서 요청 1건마다 64MiB와 CPU 1코어를 소비하는 경로였습니다. 기존 Argon2 Hash는 그대로 동작하며 최초 인증 성공 시 자동 승격됩니다.
- OIDC Client 인증 실패에 대한 발신지·Client 식별자별 Rate limit 추가. 성공 경로에는 비용을 추가하지 않도록 실패만 계수하며 `429`와 `Retry-After`로 응답합니다.
- Argon2 동시 실행 수를 CPU 수에 비례해 제한. 인증 요청 폭주 시 메모리 사용량이 요청 수에 비례해 증가하던 문제를 해소합니다.
- Back-Channel Logout URI에 Redirect URI와 동일한 전송 규칙(HTTPS 또는 Loopback HTTP)을 적용. 이전에는 검증 없이 저장되었습니다.

### 기능

- OIDC Back-Channel Logout 1.0 구현. 이전 버전은 Client에 Back-Channel Logout URI를 저장하고 관리 화면에서 편집까지 가능했지만 실제로 통지하지 않았습니다. 이제 Session 종료 시 해당 Session에 참여한 Client에만 서명된 `logout_token`을 전송합니다.
- Prometheus `/metrics` endpoint 추가. 요청률·지연, Token 발급, 로그인 결과, Client 인증 실패, Back-Channel Logout 전달, LDAP 동기화 결과를 노출하며 `admin:read` 인증을 요구합니다.
- Access Token Introspection을 같은 Realm의 모든 Confidential Client에 허용. 이전에는 발급 Client만 조회할 수 있어 Resource Server 패턴이 불가능했습니다. Refresh Token Introspection은 보유 Client로 제한됩니다.
- ID Token에 `at_hash` Claim 추가. 이 Claim을 요구하는 엄격한 RP가 ID Token을 거부하던 문제를 해소합니다.
- RP-Initiated Logout에서 `id_token_hint` 대신 `client_id` 파라미터 허용.
- Discovery에 `backchannel_logout_supported`, `backchannel_logout_session_supported`, `frontchannel_logout_supported`, Request Object 지원 여부 메타데이터 추가.

### 안정성과 성능

- 로그인 검증이 Argon2 연산 내내 PostgreSQL 커넥션을 점유하던 문제 수정. 동시 로그인이 커넥션 풀을 고갈시켜 Token 발급과 관리 API까지 지연시켰습니다. 실패 계수는 Row Lock 대신 원자적 UPDATE로 처리하고, 해싱 도중 계정이 잠기면 성공 처리를 거부합니다.
- Refresh Token 회전에 30초 유예 창 도입. 병렬 탭이나 네트워크 재시도로 같은 Token이 두 번 제시되면 전체 Token Family가 폐기되어 정상 사용자가 강제 로그아웃되었습니다. 유예 창 밖의 재사용은 이전과 동일하게 침해로 처리합니다.
- Realm별 서명 키 캐시 추가. Token 발급마다 조회·복호화·PKCS#8 파싱을, 검증마다 조회·JWK 파싱을 반복하던 경로를 제거합니다. 회전 시 즉시 무효화되며, 이전 키는 2시간 동안 PASSIVE로 유지되므로 다중 인스턴스에서도 안전합니다.
- 서버 로그를 건별 INSERT에서 배치 `COPY`로 전환. HTTP 요청마다 로그가 1건 생성되므로 이전에는 로그 기록이 데이터베이스의 최다 쓰기 작업이었습니다.
- 사용자 검색용 선택적 Trigram 색인 추가. 관리 화면은 선행 Wildcard로 검색하므로 B-tree 색인을 사용할 수 없었고 입력마다 전체 스캔이 두 번 발생했습니다. `pg_trgm`이 설치되어 있으면 기동 시 색인을 만들며, ReSSO가 확장을 직접 설치하지는 않습니다.
- 보존 정책 정리 작업을 기동 1분 후 1회 실행. 이전에는 첫 실행이 24시간 뒤라 매일 재시작하는 서비스에서 만료 데이터가 전혀 정리되지 않았습니다. 만료된 Refresh Token 정리도 추가했습니다.

### 사용성 — 사용자

- 로그인 제한(429)의 `Retry-After`를 화면에 표시하고 남은 시간을 카운트다운합니다. 이전에는 헤더가 있어도 사용자에게 전달되지 않아, 차단된 상태에서 계속 재시도하게 되었습니다.
- 로그인 연속 실패 시 잠금 정책을 안내합니다. 계정 존재 여부를 노출하지 않도록 서버 응답은 그대로 두고 브라우저에서만 계수합니다.
- 비밀번호 변경 화면이 Realm의 실제 최소 길이를 조건 목록으로 보여주고 충족 전까지 제출을 막습니다. 이전에는 8자로 하드코딩되어 있어 기본 정책(12자)과 어긋났고, 서버 오류로만 알 수 있었습니다.
- 복사 버튼이 평문 HTTP Origin에서도 동작합니다. `navigator.clipboard`가 없는 오프라인 배포에서 예외가 조용히 삼켜져 일회성 Secret 복사가 실패하던 문제를 수정했습니다. 실패 시에도 사용자에게 알립니다.
- 세션 목록이 User-Agent 원문 대신 "Chrome · Windows" 형태로 표시합니다.
- 현재 사용 중인 세션을 종료할 때 확인을 요구합니다.

### 사용성 — 관리자

- 잠긴 계정을 비밀번호 재설정 없이 해제하는 기능을 추가했습니다(`POST .../users/{userID}/unlock`). 이전에는 잠금 해제 수단이 비밀번호 재설정뿐이라 잘못 입력했을 뿐인 사용자에게 불필요한 자격증명 변경을 강요했습니다.
- Realm의 비밀번호 최소 길이·잠금 횟수·잠금 시간을 조회하고 변경할 수 있습니다. 이 정책은 로그인과 비밀번호 변경에 계속 적용되고 있었지만 데이터베이스에만 존재해 확인할 수도 바꿀 수도 없었습니다.
- 관리 화면의 Realm 선택이 URL(`?realm=<name>`)에 반영되어 화면을 공유·북마크할 수 있습니다. 이전에는 localStorage에만 있어 같은 링크가 수신자마다 다른 Realm을 열었습니다.
- Client Secret 회전에 확인 단계를 추가했습니다. 클릭 한 번으로 즉시 회전되어 운영 중인 연동이 예고 없이 끊겼습니다.
- 사용자 목록에 잠김·비활성 상태 필터와 행 단위 잠금 해제를 추가하고, 잠금 해제 시점을 함께 표시합니다.
- 대시보드의 준비 상태 항목과 지표 카드가 해당 화면으로 연결됩니다. 이전에는 "3개 실패"만 알려주고 원인을 찾는 것은 운영자 몫이었습니다.
- 저장 성공 알림을 사라지는 Toast로 통일했습니다. 편집을 계속해도 남아 있던 성공 Alert이 의미를 잃던 문제를 해소합니다.
- `LISTEN_ADDRESS`로 Listen 주소를 설정할 수 있습니다. 이전에는 코드에 `:8080`이 고정되어 Container 밖에서 포트를 바꿀 수 없었습니다.

### 개발

- `golangci-lint`, `govulncheck`, ESLint, Trivy 이미지 스캔을 CI에 추가하고 `make lint` 제공.
- 프론트엔드 테스트에 Testing Library 정리(cleanup)를 등록했습니다. Vitest가 `globals: false`로 동작해 자동 정리가 걸리지 않았고, 한 파일에 테스트를 추가하면 DOM이 누적되어 조회가 실패했습니다.
- 콘솔의 "비동기 데이터에서 상태를 파생"하는 9곳을 `useEffect` 대신 렌더 중 조정으로 바꿨습니다. 효과로 동기화하면 갱신 전 값이 한 프레임 보이고 렌더가 연쇄됩니다. `AuthProvider`·`ToastProvider`의 Hook을 별도 모듈로 분리해 Fast Refresh도 복구했습니다.
- 프론트엔드 린트를 `--max-warnings 0`으로 고정했습니다.
- `go.mod`의 `go` 지시자를 `1.26`으로 낮추고 `toolchain go1.26.7`을 분리. 이전에는 모든 기여자에게 정확한 Patch 버전을 강제했습니다.

### Upgrade notes

- Migration `004_operations.sql`이 Back-Channel Logout 대상 조회와 만료 Refresh Token 정리를 위한 인덱스를 추가합니다. 별도 조치는 필요 없습니다.
- Client Secret이 Digest Keyring으로 보호됩니다. 기존 Argon2 Secret은 계속 동작하며 최초 인증 성공 시 자동 승격되지만, **Digest Key를 제거하기 전에 모든 Confidential Client의 Secret을 회전**해야 합니다. Client Secret은 만료되지 않으므로 이 항목이 사실상 이전 Digest Key의 보관 기간을 결정합니다.
- Access Token Introspection이 같은 Realm의 모든 Confidential Client에 허용됩니다. 이전에는 발급 Client만 조회할 수 있었으므로, 이 동작에 의존해 접근을 제한하던 구성이 있다면 검토하세요. Refresh Token Introspection은 보유 Client로 계속 제한됩니다.
- Refresh Token 재사용 판정에 30초 유예 창이 생겼습니다. 유예 창 안의 재제시는 침해가 아닌 재시도로 처리되어 새 Token을 발급합니다.
- ID Token에 `at_hash`가 추가됩니다. Claim을 화이트리스트로 검증하는 RP가 있다면 확인하세요.
- `GET /metrics`는 `admin:read` 권한을 요구합니다. Prometheus에 개인 API Key를 Bearer token으로 설정하세요.
- 사용자 검색 색인은 선택 사항입니다. 데이터베이스 소유자 권한으로 `CREATE EXTENSION pg_trgm;`을 실행하면 다음 기동 시 색인이 생성됩니다. 실행하지 않으면 기존 동작을 유지합니다.
- 공식 오프라인 Docker 아카이브는 `linux/amd64` 전용입니다.

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
