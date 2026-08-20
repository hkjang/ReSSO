import ApprovalRoundedIcon from '@mui/icons-material/ApprovalRounded'
import DnsRoundedIcon from '@mui/icons-material/DnsRounded'
import GroupsRoundedIcon from '@mui/icons-material/GroupsRounded'
import SecurityRoundedIcon from '@mui/icons-material/SecurityRounded'
import VpnKeyRoundedIcon from '@mui/icons-material/VpnKeyRounded'
import { Box, Grid, LinearProgress, Stack, Typography } from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { PageHeader, ContentCard } from '../components/Page'
import { ErrorAlert, PageLoading } from '../components/Feedback'

interface DashboardData { realms: number; users: number; clients: number; active_sessions: number; pending_approvals: number; readiness: { issuer_https: boolean; signing_keys_ready: boolean; federation_failures: number; locked_users: number; expiring_api_keys: number } }

export function DashboardPage() {
  const query = useQuery({ queryKey: ['dashboard'], queryFn: () => api<DashboardData>('/api/admin/v1/dashboard'), refetchInterval: 30_000 })
  if (query.isLoading) return <PageLoading />
  if (query.error) return <ErrorAlert error={query.error} />
  const cards = [
    { label: 'Realm', value: query.data?.realms ?? 0, icon: DnsRoundedIcon, color: '#2f6fed' },
    { label: '사용자', value: query.data?.users ?? 0, icon: GroupsRoundedIcon, color: '#12a594' },
    { label: 'OIDC Client', value: query.data?.clients ?? 0, icon: VpnKeyRoundedIcon, color: '#7f56d9' },
    { label: '활성 세션', value: query.data?.active_sessions ?? 0, icon: SecurityRoundedIcon, color: '#f79009' },
    { label: '승인 대기', value: query.data?.pending_approvals ?? 0, icon: ApprovalRoundedIcon, color: '#d92d20' },
  ]
  const readiness = [
    { label: '외부 Issuer HTTPS', ready: Boolean(query.data?.readiness.issuer_https), detail: query.data?.readiness.issuer_https ? '정상' : 'HTTP Issuer 확인 필요' },
    { label: 'Realm 서명 키', ready: Boolean(query.data?.readiness.signing_keys_ready), detail: query.data?.readiness.signing_keys_ready ? '정상' : 'ACTIVE 키 누락' },
    { label: 'LDAP 최근 동기화', ready: (query.data?.readiness.federation_failures ?? 0) === 0, detail: `${query.data?.readiness.federation_failures ?? 0}개 실패` },
    { label: '잠긴 사용자', ready: (query.data?.readiness.locked_users ?? 0) === 0, detail: `${query.data?.readiness.locked_users ?? 0}명` },
    { label: '7일 내 API 키 만료', ready: (query.data?.readiness.expiring_api_keys ?? 0) === 0, detail: `${query.data?.readiness.expiring_api_keys ?? 0}개` },
  ]
  return (
    <>
      <PageHeader title="서비스 대시보드" description="ReSSO 전체 Realm과 인증 운영 상태를 한눈에 확인합니다." />
      <Grid container spacing={2.25}>
        {cards.map(({ label, value, icon: Icon, color }) => (
          <Grid key={label} size={{ xs: 12, sm: 6, lg: 2.4 }}>
            <ContentCard>
              <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                <Box><Typography color="text.secondary" variant="body2">{label}</Typography><Typography sx={{ fontSize: 31, fontWeight: 760, mt: .5 }}>{value.toLocaleString()}</Typography></Box>
                <Box sx={{ width: 42, height: 42, borderRadius: 1.5, display: 'grid', placeItems: 'center', bgcolor: `${color}15`, color }}><Icon /></Box>
              </Stack>
            </ContentCard>
          </Grid>
        ))}
      </Grid>
      <Grid container spacing={2.25} sx={{ mt: .25 }}>
        <Grid size={{ xs: 12, lg: 8 }}>
          <ContentCard>
            <Typography variant="h3">운영 준비 상태</Typography>
            <Typography color="text.secondary" variant="body2" sx={{ mt: .75, mb: 3 }}>핵심 인증 구성요소가 PostgreSQL 기반으로 준비되어 있습니다.</Typography>
            <Stack spacing={2.2}>
              {readiness.map((item) => <Box key={item.label}><Stack direction="row" justifyContent="space-between" sx={{ mb: .7 }}><Typography variant="body2" fontWeight={650}>{item.label}</Typography><Typography variant="caption" color={item.ready ? 'success.main' : 'warning.main'}>{item.detail}</Typography></Stack><LinearProgress variant="determinate" value={item.ready ? 100 : 35} color={item.ready ? 'success' : 'warning'} sx={{ height: 7, borderRadius: 99 }} /></Box>)}
            </Stack>
          </ContentCard>
        </Grid>
        <Grid size={{ xs: 12, lg: 4 }}>
          <ContentCard>
            <Typography variant="h3">보안 운영 원칙</Typography>
            <Stack spacing={1.5} sx={{ mt: 2 }}>
              {['공개 Client는 PKCE S256을 강제합니다.', 'Refresh Token은 사용 때마다 회전합니다.', 'Redirect URI는 등록값과 정확히 비교합니다.', 'Signing Private Key는 AES-256-GCM으로 보호합니다.'].map((item) => <Stack key={item} direction="row" spacing={1.2}><Box sx={{ mt: .75, width: 7, height: 7, borderRadius: '50%', bgcolor: 'secondary.main', flex: '0 0 auto' }} /><Typography variant="body2">{item}</Typography></Stack>)}
            </Stack>
          </ContentCard>
        </Grid>
      </Grid>
    </>
  )
}
