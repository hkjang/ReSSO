# ReSSO 운영 가이드

## 배포 전 점검

1. PostgreSQL 전용 Database와 최소 권한 사용자를 준비합니다.
2. PostgreSQL 연결에 TLS를 사용합니다.
3. 서로 다른 32바이트 Data Encryption Key와 Digest Key를 생성해 Password Vault에 보관합니다.
4. 12자 이상의 임시 Bootstrap 관리자 비밀번호를 준비합니다.
5. Reverse Proxy에서 TLS를 종료하고 `/`, `/api`, `/realms`, `/mcp`, `/.well-known` 경로를 변경 없이 전달합니다.
   Proxy 네트워크만 `TRUSTED_PROXY_CIDRS`에 등록합니다. 등록되지 않은 발신지의 전달 Header는 무시됩니다.
6. 최초 로그인 후 `master` Realm의 Issuer URL을 외부 URL로 변경합니다.
7. Bootstrap 관리자 비밀번호를 개인 설정에서 즉시 변경합니다.

## 데이터 보호와 백업

PostgreSQL에는 사용자, Client, Session, Refresh Token의 HMAC digest, 감사 이벤트와 AES-256-GCM으로 암호화된 Signing Private Key 및 LDAP Bind Credential이 저장됩니다. 백업 복구에는 해당 시점의 Data Encryption·Digest Keyring이 모두 필요합니다.

- PostgreSQL: 조직의 RPO/RTO에 맞춰 PITR 가능한 백업 사용
- Data Encryption·Digest Keyring: DB와 다른 보안 경계에 복제 보관
- 복구 훈련: 격리 환경에서 분기별 수행 권장

필요한 읽기 키를 제외한 상태로 서비스를 시작하면 기존 Private Key, Session, Token 또는 API Key를 사용할 수 없습니다. Keyring은 쉼표로 구분한 `key-id:base64-or-hex-key` 형식이며 첫 항목이 신규 쓰기에 사용됩니다. 암호문은 Data Encryption Key ID를 참조하므로 ID는 키 재료와 함께 백업하고 rewrap이 끝나기 전에는 이름을 바꾸지 마세요. 같은 ID를 다른 키 재료에 재사용해서도 안 됩니다.

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

## 사용자 검색 색인

관리 화면의 사용자 검색은 선행 Wildcard를 사용하므로 B-tree 색인을 사용할 수 없습니다. 사용자 수가 많은 Realm에서는 `pg_trgm` 확장을 설치하면 전체 스캔 대신 색인 스캔을 사용합니다.

```sql
CREATE EXTENSION IF NOT EXISTS pg_trgm;
```

ReSSO는 확장을 직접 설치하지 않습니다. 확장 설치는 데이터베이스 소유자 권한이 필요하고, Migration이 확장을 임의의 스키마에 설치하면 다른 객체에 영향을 주기 때문입니다. 확장이 존재하면 다음 기동 시 색인을 만들고, 없으면 기존 동작을 그대로 유지합니다. 나중에 확장을 설치했다면 재기동만 하면 됩니다. 기동 로그에서 결과를 확인할 수 있습니다.

## 운영 지표

`GET /metrics`가 Prometheus text format을 제공하며 관리 API와 동일한 인증을 요구합니다. Prometheus에는 `admin:read` 범위의 개인 API Key를 Bearer token으로 설정하세요. 지표 목록은 [README](../README.md#운영-지표)에 있습니다.

권장 경보:

- `resso_login_attempts_total{result="failure"}` 급증 — 자격증명 대입 시도
- `resso_token_errors_total` 발생 — Token을 발급하지 못하는 상태. Signing Key를 열 수 없는 경우(Keyring 불일치)가 대표적이며, 모든 RP의 Token 교환이 함께 실패합니다. 발급 성공만 세면 이 상황도 시계열이 조용해질 뿐입니다.
- `resso_login_attempts_total{result="error"}` 발생 — 로그인 시도를 완료하지 못하는 상태. LDAP 디렉터리 장애가 대표적입니다. 이 경우 성공도 실패도 집계되지 않으므로, `failure` 급증만 보고 있으면 전면 장애가 조용해 보입니다.
- `resso_client_auth_failures_total` 급증 — Client Secret 오설정 또는 대입 시도
- `resso_backchannel_logout_total{result!="delivered"}` — RP가 로그아웃 통지를 받지 못하는 상태
- `resso_federation_sync_total{result="failure"}` — LDAP 동기화 실패
- `resso_http_request_duration_seconds` 상위 분위 상승 — 커넥션 풀 포화 또는 LDAP 지연
- `resso_system_log_records_total{result!="written"}` — 서버 로그가 데이터베이스에 남지 않는 상태. 관리 화면의 로그에 구멍이 생깁니다.

지표만으로는 드러나지 않는 신호는 감사 이벤트에 있습니다. 관리 → 운영 → 감사에서 종류로 걸러 확인하세요.

| 이벤트 | 의미 |
|---|---|
| `AUTHORIZATION_CODE_REUSED` | 인가 코드가 두 번 제시되었습니다. 코드가 유출된 것이며, 해당 Session·Client의 Refresh Token은 이미 폐기되었습니다. 기록된 계정과 Client를 확인하고 RP의 Redirect 설정과 Referrer 정책을 점검하세요. |
| `REFRESH_TOKEN_REUSE` | Refresh Token이 회전 이후 다시 제시되어 계열이 폐기되었습니다. |
| `LDAP_FEDERATION_SYNC` `result=FAILURE` | 동기화 실패. `DISABLE` 정책이면 계정 비활성화가 반영되지 않습니다. 실행이 끝났는데도 이 이벤트가 **아예 없다면** 결과를 기록하지 못한 것입니다. 그때는 공급자의 동기화 상태도 이전 실행에 머물러 있으므로, 서버 로그에서 `outcome was not recorded`를 확인하세요. |
| `result=PARTIAL` | 요청은 요구받은 일을 했고 그에 딸린 동작이 실패한 경우입니다. 비밀번호 변경·재설정에서 다른 세션 종료가 실패했거나, 로그아웃에서 세션 폐기가 실패한 경우가 여기에 해당합니다. 상세에 실패 사유가 들어 있습니다. **`result=FAILURE`만 걸어둔 알림은 이 항목을 놓칩니다.** 해당 세션은 살아 있으므로 관리 → 세션에서 직접 종료하세요. |
| `MCP_TOOL_CALL` | 에이전트가 MCP로 사람 또는 Client의 기록을 조회했습니다. 상세의 `tool`이 어떤 도구인지, `result`가 허용 여부입니다. `FAILURE`는 권한이 없는 키가 시도했다는 뜻이므로 어떤 키인지 확인하세요. 서비스 상태 조회는 기록하지 않습니다. |
| `TOKEN_REVOKED` | RP가 Revocation endpoint를 호출했습니다. 상세의 `revoked`가 실제 결과입니다 — `refresh_token`(계열 폐기, `family_id` 포함), `access_token`(`jti` 포함), `none`(일치하는 Token 없음). RFC 7009은 일치 여부와 무관하게 200을 반환하므로, Token이 실제로 폐기되었는지는 이 값으로만 알 수 있습니다. |

## Back-Channel Logout

관리 → Client에서 Back-Channel Logout URI를 등록하면 Session 종료 시 해당 Session에 참여한 Client에만 서명된 `logout_token`을 POST합니다.

- 사용자 로그아웃, RP-Initiated Logout, 관리자의 Session 강제 폐기, 계정 복구가 모두 통지를 발생시킵니다.
- URI는 HTTPS(또는 Loopback HTTP)만 허용하며 Redirect는 따라가지 않습니다.
- 전달은 Best effort이며 사용자의 로그아웃 응답을 지연시키지 않습니다. 저절로 해소될 수 있는 실패(연결 실패, 5xx, 429)만 2초·8초 간격으로 재시도하고, RP가 명시적으로 거절한 4xx는 반복하지 않습니다. 종료 중에는 즉시 중단합니다.
- RP는 `logout_token`을 Realm JWKS로 검증하고 `iss`, `aud`, `events`, `sid`를 확인해야 합니다.
- 실패는 서버 로그와 `resso_backchannel_logout_total`에 기록됩니다.
- 통지 대상은 해당 Session에 실제로 참여한 Client입니다. 참여 기록은 Session이 살아 있는 동안 유지되며 Session이 끝나면 정리됩니다.

## Token과 Session 수명

Realm에는 서로 다른 것을 재는 네 개의 시간이 있습니다. 자주 혼동되므로 관계를 정리합니다.

| 설정 | 재는 대상 | 범위 | 기본값 |
|---|---|---|---|
| Access Token | 발급된 Access Token 하나의 수명 | 60–3600초 | 300초 |
| Refresh Token | **최초 발급 시점부터 Token 계열 전체의 총 수명** | 300–2592000초 | 1800초 |
| SSO Session | 로그인 후 활동과 무관한 세션 최대 수명 | 300–2592000초 | 28800초 |
| 유휴 만료 | 마지막 사용 이후 세션이 유지되는 시간 | `0` 또는 300–2592000초 | `0`(사용 안 함) |

Refresh Token은 회전할 때마다 새 값이 발급되지만 **만료 시각은 연장되지 않습니다.** 계속 갱신하는 Client가 자격증명을 무기한 보유하지 못하도록 하는 상한입니다. 이 시간이 지나면 Refresh는 거부되고 RP는 인가 과정을 다시 거칩니다.

SSO Session이 아직 살아 있으면 이 재인가는 사용자에게 보이지 않습니다. 브라우저가 인가 endpoint로 갔다가 즉시 돌아오므로 다시 로그인하라는 화면이 나오지 않습니다. 다만 다음 경우에는 실제 재로그인이 됩니다.

- SSO Session이 이미 만료되었거나 유휴 만료에 걸린 경우
- 브라우저 Redirect를 쓰기 어려운 Native·Mobile Client
- 사용자 상호작용 없이 장시간 동작해야 하는 통합

이런 Client가 있다면 Refresh Token 값을 SSO Session에 가깝게 올리세요. 기본값 1800초는 브라우저 기반 RP를 기준으로 한 값입니다.

## 세션 유휴 만료

Realm 상세의 `유휴 만료`는 그 시간 동안 사용되지 않은 세션을 만료시킵니다. 관리 콘솔 요청뿐 아니라 Token 갱신·발급과 MCP·Introspection의 Session 확인도 사용으로 셉니다. 따라서 RP를 통해서만 접속하는 사용자의 Session도 작업 중에는 만료되지 않습니다. `0`이면 사용하지 않으며, 이 경우 세션은 `SSO Session` 절대 수명까지만 유효합니다.

| 항목 | 범위 | 기본값 |
|---|---|---|
| 유휴 만료 | `0`(사용 안 함) 또는 300–2592000초 | `0` |

- 요청이 발생할 때마다 활동으로 기록되므로, 콘솔이나 연동 애플리케이션을 사용하는 동안에는 만료되지 않습니다.
- 브라우저 세션 검증, Token 발급, Refresh Token 회전, MCP 인증에 동일하게 적용됩니다. 유휴로 만료된 세션은 Refresh Token으로도 연장되지 않습니다.
- `SSO Session`보다 크게 설정할 수 없습니다.
- 공용 단말이나 정책상 유휴 종료가 요구되는 환경에서 설정하세요. 값을 바꾸면 사용자의 `내 세션` 화면에도 안내가 표시됩니다.

## 서버·데이터베이스 시각 차이

ReSSO 프로세스와 PostgreSQL은 **서로 다른 시계**를 씁니다. 서비스의 모든 수명은 한쪽에서 계산되어 다른 쪽에서 판정됩니다 — Session의 `expires_at`은 ReSSO가 계산하고 데이터베이스가 만료를 판정하며, 계정 잠금 해제 시각은 데이터베이스가 계산하고 ReSSO가 판정합니다.

두 시계가 어긋나면 무엇이 곧바로 고장 나지는 않고, **모든 창(window)이 그 차이만큼 밀립니다.** 그래서 서로 무관해 보이는 증상 여러 개로 나타납니다 — Session이 설정보다 일찍 끊기거나 늦게까지 남고, 잠금이 예정보다 일찍 풀리는 식입니다.

관리 대시보드의 `서버·데이터베이스 시각 차이` 항목이 이 값을 보여줍니다. 측정에는 왕복 시간만큼의 오차가 있으므로 함께 표시합니다.

- 기준은 **Refresh Token 회전 유예(30초)**입니다. 차이가 이보다 커지면 단순히 밀리는 수준을 넘어, 정상적인 재시도가 재사용으로 판정될 수 있는 영역에 들어갑니다.
- 오프라인 설치에서는 NTP를 쓸 수 없는 경우가 많습니다. 두 호스트가 다르다면 같은 시각 소스를 쓰도록 맞추거나, 최소한 이 값을 주기적으로 확인하세요.

## Realm 정지

Realm 상세의 `Realm 활성`을 끄면 그 테넌트 전체가 즉시 멈춥니다.

- Discovery·JWKS·인가·Token·userinfo·Introspection·Revocation이 모두 거절합니다.
- 새 로그인뿐 아니라 **열려 있는 콘솔 세션과 개인 API 키도 중단됩니다.** API 키는 세션보다 오래 살아남으므로 "전원 로그아웃 후 대기"로는 대체할 수 없습니다. MCP도 같은 키를 쓰므로 함께 멈춥니다.
- **자신이 로그인한 Realm은 비활성화할 수 없습니다.** 요청을 보내는 세션과 되돌릴 수 있는 API 키가 함께 끊기므로, 허용하면 데이터베이스를 직접 수정하는 것 외에 복구 수단이 없습니다. 다른 Realm은 정지시킬 수 있습니다.
- 정지는 **폐기가 아니라 차단**입니다. 다시 활성화하면 그동안 만료되지 않은 세션과 API 키는 그대로 다시 동작합니다. 계정 비활성화가 세션을 영구히 종료하는 것과 다릅니다 — 테넌트 정지는 보통 일시적이고, 특정 개인의 세션이 원인인 상황이 아니기 때문입니다. 영구히 끊어야 한다면 정지와 별개로 세션을 폐기하세요.
- 이미 발급된 Access Token은 서명 자체가 만료까지 유효하지만, Introspection과 userinfo가 거절하므로 이를 확인하는 RP는 즉시 차단합니다.

## Bootstrap 관리자 계정

`BOOTSTRAP_ADMIN`·`BOOTSTRAP_ADMIN_PASSWORD`는 **비어 있는 데이터베이스에 첫 관리자를 만들 때만** 사용됩니다. 계정이 이미 있으면 Bootstrap은 비밀번호를 재설정하지 않으며, **활성 상태와 `platform_admin` 권한도 다시 부여하지 않습니다.**

- 이름을 지은 관리자 계정을 만든 뒤 Bootstrap 계정을 비활성화하거나 권한을 회수했다면, 그 결정은 재시작해도 유지됩니다.
- 반대로 **재시작으로 관리자 접근을 되살릴 수는 없습니다.** 마지막 관리자가 잠겼다면 `admin recover`를 사용하세요. 의도적으로 실행해야 하고, 감사에 남으며, 복구한 계정의 기존 Session과 API 키를 폐기합니다.
- `BOOTSTRAP_ADMIN`에 이미 존재하는 일반 사용자의 이름을 넣어도 그 사용자가 플랫폼 관리자가 되지 않습니다.

## 계정 비활성화

사용자 상세에서 `계정 활성`을 끄면 그 계정은 즉시 로그아웃됩니다.

- 열려 있던 모든 SSO Session과 그 Session에서 발급된 Refresh Token이 폐기됩니다.
- Back-Channel Logout을 등록한 RP에는 로그아웃이 전달되므로, 자체 세션을 유지하는 애플리케이션에서도 로그아웃됩니다.
- 이미 발급된 Access Token은 만료까지 서명이 유효하지만, userinfo·Token Introspection·Refresh 교환이 모두 거절하므로 이를 확인하는 RP는 즉시 차단합니다. 확인 없이 서명만 신뢰하는 Resource Server가 있다면 `Access Token` 수명이 곧 최대 노출 시간입니다.
- **계정을 다시 활성화해도 기존 Session은 복구되지 않습니다.** 사용자는 새로 로그인해야 합니다. 정지 후 복귀처럼 되돌리는 운영에서도 이전 Session이 되살아나지 않습니다.
- LDAP `DISABLE` 정책이 실행하는 비활성화도 같은 처리를 거칩니다.

계정을 완전히 막아야 하는 상황이라면 비밀번호 재설정을 함께 수행하세요. 비활성화만으로는 사용자가 알고 있는 비밀번호가 남아 있습니다.

## 로그인 요청 제한

계정 잠금 앞에는 잠금과 별개인 두 가지 요청 제한이 있습니다. 둘 다 Realm 설정이 아니라 고정값이며, 걸리면 `429`와 `Retry-After`로 응답합니다.

| 대상 | 세는 것 | 한도 |
|---|---|---|
| 출발지 주소 | 로그인 요청 전부(성공 포함) | 5분에 100건 |
| 계정 | 로그인 실패 | 5분에 30건 |

- 주소 쪽이 성공까지 세는 것은 의도된 것입니다. 이 제한은 비밀번호 해싱 비용을 출발지별로 묶어두기 위해 **인증 작업을 시작하기 전에** 적용되기 때문입니다. 계정 쪽 실패 횟수는 로그인에 성공하면 초기화됩니다.
- **사용자가 이유 없이 `429`를 받는다면 여러 사람이 한 주소로 보이고 있는지부터 확인하세요.** 가장 흔한 원인은 두 가지입니다. 사무실 전체가 하나의 공인 IP(NAT)를 쓰는 경우와, TLS를 종료하는 Reverse Proxy가 `TRUSTED_PROXY_CIDRS`에 없어서 **모든 사용자가 Proxy의 주소 하나로 합쳐지는** 경우입니다. 후자는 설정 실수이며, 이 경우 전체 설치가 5분에 100건이라는 하나의 예산을 나눠 쓰게 됩니다.
- 감사 이벤트 `LOGIN_RATE_LIMITED`로 확인할 수 있습니다. 기록된 IP가 실제 사용자 주소인지 Proxy 주소인지 함께 보세요.

## 계정 잠금 운영

Realm의 잠금 정책은 관리 → Realm 상세에서 설정합니다.

| 항목 | 범위 | 기본값 |
|---|---|---|
| 비밀번호 최소 길이 | 8 ~ 128자 | 12자 |
| 잠금까지 허용할 연속 실패 | 3 ~ 50회 | 5회 |
| 잠금 유지 시간 | 30초 ~ 24시간 | 900초 |

이 정책은 개인 설정의 비밀번호 변경 화면에 그대로 안내되므로, 값을 바꾸면 사용자가 보는 조건도 함께 바뀝니다.

잠긴 계정은 관리 → 사용자에서 상태 필터를 `잠김`으로 두고 확인하며, `잠금 해제` 버튼으로 비밀번호를 바꾸지 않고 해제합니다. 비밀번호 재설정으로도 잠금이 풀리지만, 사용자가 단순히 오타를 냈을 뿐이라면 불필요한 자격증명 변경을 강요하게 되므로 잠금 해제를 사용하세요. 두 작업 모두 감사 이벤트(`USER_UNLOCK`, `PASSWORD_RESET`)로 기록됩니다.

로그인 화면은 계정 존재 여부를 노출하지 않기 위해 잠금 여부와 무관하게 동일한 메시지를 반환합니다. 사용자가 "비밀번호는 맞는데 로그인이 안 된다"고 문의하면 이 화면에서 잠금 상태를 먼저 확인하세요.

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

서명 키는 자동으로 회전되지 않습니다. 콘솔은 활성 키가 180일을 넘기면 대시보드 준비 상태와 서명 키 화면에서 회전을 권고하며, 이는 실패가 아니라 권고이므로 키는 계속 정상 동작합니다. 회전 후 이전 공개키는 기존 Token 검증을 위해 일정 시간 JWKS에 유지되므로 서비스 중단 없이 수행할 수 있습니다.

개인 API Key는 개인 설정에서 회전합니다. 회전 성공과 동시에 이전 키가 폐기되고 새 Secret은 한 번만 표시됩니다.

### Data Encryption·Digest Keyring 회전

다중 인스턴스에서 혼합 배포 중에도 서로의 값을 읽을 수 있도록 다음 두 단계로 순서를 바꿉니다. 예시는 `old`에서 `new`로 회전하는 경우입니다.

1. 모든 인스턴스에 `old:OLD_KEY,new:NEW_KEY`를 배포합니다. 아직 첫 키는 `old`이므로 신규 쓰기는 바뀌지 않습니다.
2. 모든 인스턴스가 두 키를 가진 것을 확인합니다.
3. `new:NEW_KEY,old:OLD_KEY` 순서로 Rolling Restart합니다. 어느 인스턴스도 상대가 쓴 값을 읽지 못하는 구간이 없습니다.
4. 전체 전환 후 아래 명령으로 암호화된 Signing Key와 LDAP Credential을 검증·재암호화합니다.

```bash
docker compose -f compose.maintenance.yaml --profile maintenance run --rm resso-maintenance admin diagnose
docker compose -f compose.maintenance.yaml --profile maintenance run --rm resso-maintenance crypto rewrap
```

`crypto rewrap`은 PostgreSQL의 Signing Private Key와 LDAP Bind Credential을 검증하고 활성 Data Encryption Key로 다시 암호화합니다. Session·Authorization Request/Code·Refresh Token·개인 API Key·Client Secret의 Digest는 원문을 저장하지 않아 재작성하지 않습니다. rewrap 후 `admin diagnose` 결과와 서비스 동작을 확인한 뒤에만 이전 Data Encryption Key를 제거하세요.

이전 Digest Key는 다음이 모두 끝날 때까지 읽기 키로 유지합니다.

- 기존 Session과 Refresh Token 만료
- 해당 키로 만든 모든 개인 API Key 회전 또는 폐기
- **해당 키로 만든 모든 Client Secret 회전**

Client Secret은 만료되지 않으므로 마지막 항목이 사실상 제거 시점을 결정합니다. 관리 → Client에서 각 Confidential Client의 `Client Secret 회전`을 수행한 뒤에 이전 Digest Key를 제거하세요. v0.2.1 이하에서 만든 Argon2 형식 Secret은 Digest Key와 무관하게 계속 동작하며, 최초 인증 성공 시 활성 Digest Key 형식으로 자동 승격됩니다.

v0.2.0의 단일 `ENCRYPTION_KEY`에서 전환할 때는 먼저 기존 설정 그대로 모든 인스턴스를 v0.2.1로 업그레이드합니다. 이 모드에서는 v0.2.0 암호문 형식으로 계속 쓰므로 혼합 배포와 이미지 롤백이 가능합니다. 그 다음 분리형 Keyring을 설정하면서 `ENCRYPTION_KEY`도 유지하면 ReSSO가 기존 키를 `legacy` ID로 양쪽 읽기 Keyring에 자동 추가합니다. 첫 단계에는 `legacy:OLD_KEY,new:NEW_KEY`, 두 번째 단계에는 `new:NEW_KEY,legacy:OLD_KEY` 순서를 사용하세요. 새 Keyring을 활성화하거나 `crypto rewrap`을 실행한 뒤에는 v0.2.0으로 롤백하지 마세요.

## 관리자 진단과 Break-glass 복구

HTTP 서비스가 시작되지 않거나 관리자 계정이 잠긴 경우 유지보수 CLI를 사용합니다.

```bash
docker compose -f compose.maintenance.yaml --profile maintenance run --rm resso-maintenance admin diagnose

read -rsp 'New recovery password: ' RESSO_RECOVERY_PASSWORD; echo
printf '%s\n' "$RESSO_RECOVERY_PASSWORD" | docker compose -f compose.maintenance.yaml --profile maintenance run --rm -T resso-maintenance \
  admin recover --username recovery-admin --password-stdin
unset RESSO_RECOVERY_PASSWORD
```

복구 명령은 `master` Realm의 로컬 사용자를 만들거나 재설정하고 `platform_admin`·`realm-admin` 권한을 복구합니다. 계정 잠금을 해제하며 기존 Session, Refresh Token, 개인 API Key를 즉시 폐기하고 감사 이벤트를 기록합니다. Federated 사용자는 로컬 계정으로 바꾸지 않으므로 별도의 로컬 사용자명을 지정해야 합니다.

## 승인 프로세스

Realm 설정의 “팀장 검토·승인 프로세스 사용”이 켜진 경우에만:

- 사용자에게 내 요청 메뉴 표시
- 관리자에게 승인함 메뉴 표시
- 사용자에 지정한 팀장의 검토함에 요청 표시
- 승인 시 Role을 Transaction 내에서 할당

설정을 끄면 요청·승인·반려 UI와 신규 요청 API 동작이 제외됩니다. 기존 감사 기록은 유지됩니다.

## 업그레이드와 롤백

1. PostgreSQL 백업과 모든 Keyring의 복구 가능성을 확인합니다.
2. 새 `resso:vX.Y.Z` 이미지를 로드합니다.
3. 단일 인스턴스를 교체하고 `/health/ready`를 확인합니다.
4. Discovery, 로그인, Token, JWKS, UserInfo smoke test를 수행합니다.
5. 문제가 있으면 이전 이미지로 Container를 되돌립니다.

DB Migration은 기동 시 Advisory Lock 아래 자동 적용됩니다. Migration 적용 후 애플리케이션 이미지 롤백이 필요한 경우에는 릴리즈 노트의 DB 호환성을 먼저 확인해야 합니다. 각 릴리즈의 Upgrade notes에 직전 버전으로 되돌릴 수 있는지와, 되돌린 동안 적용되지 않는 설정이 무엇인지 적습니다.

되돌린 이미지는 자기가 모르는 Migration이 이미 적용된 데이터베이스를 만나게 됩니다. 이 경우 기동 로그에 경고가 남고 어떤 버전인지 함께 표시되며, `admin diagnose`의 `migrations_ahead_of_binary`에도 나타납니다. **기동을 막지는 않습니다** — 롤백은 이미 무언가 잘못됐을 때 하는 조치이고, 뜨지 않는 서비스는 빠져나갈 길마저 없애기 때문입니다. 경고가 보이면 그 Migration을 넣은 버전의 Upgrade notes를 확인하세요.

GitHub Release에 첨부되는 공식 오프라인 Docker 아카이브는 `linux/amd64` 전용입니다. ARM64 운영 환경은 대상 플랫폼에서 별도 이미지를 빌드하고 동일한 검증 절차를 수행해야 합니다.

## LDAP Federation 운영

- 관리 → User Federation에서 Realm별 LDAP 또는 AD 공급자를 구성합니다.
- 실제 동기화 전 `연결 테스트`와 별도 시험 계정의 `인증 테스트`를 모두 통과시킵니다.
- 운영 연결은 `ldaps://` 또는 StartTLS와 조직 CA 인증서를 사용합니다.
- `DISABLE` 정책은 전체 동기화에서 사라진 계정을 비활성화하고 세션을 종료하므로 LDAP 필터 변경 전에 영향 범위를 확인합니다.
- 자동 동기화는 5분 이상 주기로 설정하며 다중 Pod에서는 PostgreSQL `SKIP LOCKED` claim으로 중복 실행을 방지합니다.
- 상세 설정과 장애 대응은 [user-federation.md](user-federation.md)를 참고하세요.

## 관리 화면 링크 공유

관리 화면의 Realm 선택은 주소의 `realm` 파라미터에 반영됩니다. 장애 대응 중 특정 Realm의 화면을 공유하려면 주소를 그대로 전달하면 됩니다.

```text
https://sso.company.com/admin/users?realm=partners
https://sso.company.com/admin/clients?realm=master
```

파라미터가 없으면 마지막으로 선택한 Realm을, 그것도 없으면 첫 번째 Realm을 사용하고 주소를 보정합니다.
