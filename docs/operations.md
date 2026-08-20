# ReSSO 운영 가이드

## 배포 전 점검

1. PostgreSQL 전용 Database와 최소 권한 사용자를 준비합니다.
2. PostgreSQL 연결에 TLS를 사용합니다.
3. 32바이트 `ENCRYPTION_KEY`를 생성해 Password Vault에 보관합니다.
4. 12자 이상의 임시 Bootstrap 관리자 비밀번호를 준비합니다.
5. Reverse Proxy에서 TLS를 종료하고 `/`, `/api`, `/realms`, `/mcp`, `/.well-known` 경로를 변경 없이 전달합니다.
   Proxy 네트워크만 `TRUSTED_PROXY_CIDRS`에 등록합니다. 등록되지 않은 발신지의 전달 Header는 무시됩니다.
6. 최초 로그인 후 `master` Realm의 Issuer URL을 외부 URL로 변경합니다.
7. Bootstrap 관리자 비밀번호를 개인 설정에서 즉시 변경합니다.

## 데이터 보호와 백업

PostgreSQL에는 사용자, Client, Session, Refresh Token의 HMAC digest, 감사 이벤트와 AES-256-GCM으로 암호화된 Signing Private Key 및 LDAP Bind Credential이 저장됩니다. 백업 복구에는 동일한 `ENCRYPTION_KEY`가 반드시 필요합니다.

- PostgreSQL: 조직의 RPO/RTO에 맞춰 PITR 가능한 백업 사용
- `ENCRYPTION_KEY`: DB와 다른 보안 경계에 복제 보관
- 복구 훈련: 격리 환경에서 분기별 수행 권장

`ENCRYPTION_KEY`를 임의 변경한 상태로 서비스를 시작하면 기존 Private Key를 사용할 수 없어 Token 발급이 실패합니다.

## 로그와 감사

- 컨테이너 표준 출력: JSON 구조화 로그
- 관리자 → 서버 로그: 최근 30일, Trace ID 검색, 민감 이름의 Attribute 자동 마스킹
- 관리자 → 감사 이벤트: 최근 365일, 로그인·Token·설정·키 변경 이벤트

보존 기간이 더 길어야 한다면 표준 출력을 조직의 수집 Agent가 SIEM으로 전달하도록 구성하세요. 관리자 UI의 내장 로그 저장은 장애 분석 편의를 위한 보조 계층입니다.

## Health Check

```text
GET /health/live   프로세스 생존
GET /health/ready  PostgreSQL 연결 준비 상태
```

Docker 이미지에는 `/resso healthcheck`가 포함됩니다.

관리 대시보드는 외부 Issuer HTTPS, Realm ACTIVE 서명 키, LDAP 동기화 실패, 잠긴 사용자와 7일 내 만료 API Key를 실제 DB 상태로 표시합니다.

## 관리자 권한

- `platform_admin`: 모든 Realm, 새 Realm 생성, 서버 로그를 포함한 서비스 전체 관리
- `realm-admin` Realm Role: 자신이 속한 Realm의 사용자, Federation, Client, Role, Session, Signing Key, 승인과 감사 이벤트 관리
- Realm 관리자는 다른 Realm과 플랫폼 서버 로그에 접근할 수 없습니다.
- 개인 API Key의 `api:read`·`admin:read`는 GET 요청만 허용하며 변경에는 브라우저 Session과 CSRF Token이 필요합니다.

## Key Rotation

관리자 → 서명 키에서 Realm별로 회전합니다.

1. 새 RSA-3072 키 생성
2. 새 키를 `ACTIVE`로 전환
3. 기존 키를 `PASSIVE`로 전환하고 JWKS에 함께 제공
4. 새 Token은 새 `kid`로 서명

개인 API Key는 개인 설정에서 회전합니다. 회전 성공과 동시에 이전 키가 폐기되고 새 Secret은 한 번만 표시됩니다.

## 승인 프로세스

Realm 설정의 “팀장 검토·승인 프로세스 사용”이 켜진 경우에만:

- 사용자에게 내 요청 메뉴 표시
- 관리자에게 승인함 메뉴 표시
- 사용자에 지정한 팀장의 검토함에 요청 표시
- 승인 시 Role을 Transaction 내에서 할당

설정을 끄면 요청·승인·반려 UI와 신규 요청 API 동작이 제외됩니다. 기존 감사 기록은 유지됩니다.

## 업그레이드와 롤백

1. PostgreSQL 백업과 `ENCRYPTION_KEY` 복구 가능성을 확인합니다.
2. 새 `resso:vX.Y.Z` 이미지를 로드합니다.
3. 단일 인스턴스를 교체하고 `/health/ready`를 확인합니다.
4. Discovery, 로그인, Token, JWKS, UserInfo smoke test를 수행합니다.
5. 문제가 있으면 이전 이미지로 Container를 되돌립니다.

DB Migration은 기동 시 Advisory Lock 아래 자동 적용됩니다. Migration 적용 후 애플리케이션 이미지 롤백이 필요한 경우에는 릴리즈 노트의 DB 호환성을 먼저 확인해야 합니다.

## LDAP Federation 운영

- 관리 → User Federation에서 Realm별 LDAP 또는 AD 공급자를 구성합니다.
- 실제 동기화 전 `연결 테스트`와 별도 시험 계정의 `인증 테스트`를 모두 통과시킵니다.
- 운영 연결은 `ldaps://` 또는 StartTLS와 조직 CA 인증서를 사용합니다.
- `DISABLE` 정책은 전체 동기화에서 사라진 계정을 비활성화하고 세션을 종료하므로 LDAP 필터 변경 전에 영향 범위를 확인합니다.
- 자동 동기화는 5분 이상 주기로 설정하며 다중 Pod에서는 PostgreSQL `SKIP LOCKED` claim으로 중복 실행을 방지합니다.
- 상세 설정과 장애 대응은 [user-federation.md](user-federation.md)를 참고하세요.
