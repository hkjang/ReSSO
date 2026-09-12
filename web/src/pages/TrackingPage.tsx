import { useState } from 'react'
import AddRoundedIcon from '@mui/icons-material/AddRounded'
import DeleteSweepRoundedIcon from '@mui/icons-material/DeleteSweepRounded'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import { Alert, Box, Button, Chip, FormControlLabel, MenuItem, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, jsonBody } from '../lib/api'
import { formatTimestamp } from '../lib/format'
import type { TrackingConfig, TrackingProvider, TrackingView, TrackingViolation } from '../types'
import { ContentCard, PageHeader } from '../components/Page'
import { CopyButton } from '../components/CopyField'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'
import { useToast } from '../components/toast-context'

// Momento first: it is the collector hosted inside the network, so it is the
// one choice whose data does not leave.
const providers: Array<{ value: TrackingProvider; label: string }> = [
  { value: 'none', label: '없음' },
  { value: 'momento', label: 'Momento (사내 수집기)' },
  { value: 'ga4', label: 'Google Analytics 4' },
  { value: 'gtm', label: 'Google Tag Manager' },
  { value: 'matomo', label: 'Matomo' },
  { value: 'custom', label: '직접 붙여넣기' },
]

const MAX_SNIPPET_BYTES = 8 * 1024

export function TrackingPage() {
  const view = useQuery({ queryKey: ['tracking'], queryFn: () => api<TrackingView>('/api/admin/v1/tracking') })
  if (view.error) return <ErrorAlert error={view.error} onRetry={() => void view.refetch()} />
  if (!view.data) return <PageLoading />
  return <TrackingEditor view={view.data} />
}

// The form is seeded from the server once and then owned by the person
// typing; a refetch of the view must not overwrite what they have not saved,
// which is why the editor is its own component with its own state.
function TrackingEditor({ view }: { view: TrackingView }) {
  const queryClient = useQueryClient()
  const { notify } = useToast()
  const violations = useQuery({
    queryKey: ['tracking-violations'],
    queryFn: () => api<{ items: TrackingViolation[] }>('/api/admin/v1/tracking/violations'),
    refetchInterval: 15_000,
  })
  const [form, setForm] = useState<TrackingConfig>(view.config)

  const refresh = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['tracking'] }),
      queryClient.invalidateQueries({ queryKey: ['tracking-violations'] }),
    ])
  }
  const save = useMutation({
    mutationFn: (config: TrackingConfig) => api<TrackingView>('/api/admin/v1/tracking', { method: 'PUT', ...jsonBody(config) }),
    onSuccess: async (saved) => {
      setForm(saved.config)
      queryClient.setQueryData(['tracking'], saved)
      notify(saved.config.enabled ? '방문 추적을 켰습니다. 로그인 화면을 열어 수집이 들어오는지 확인하세요.' : '방문 추적 설정을 저장했습니다.', 'success')
      await refresh()
    },
  })
  const allow = useMutation({
    mutationFn: (origin: string) => api<TrackingView>('/api/admin/v1/tracking/allowed-hosts', { method: 'POST', ...jsonBody({ origin }) }),
    onSuccess: async (saved, origin) => {
      // The allow list changed on the server; carry it into the unsaved form
      // so saving afterwards does not drop it.
      setForm((current) => ({ ...current, allowed_hosts: saved.config.allowed_hosts }))
      queryClient.setQueryData(['tracking'], saved)
      notify(`${origin}을(를) 허용 목록에 넣었습니다.`, 'success')
      await refresh()
    },
  })
  const clear = useMutation({
    mutationFn: () => api<void>('/api/admin/v1/tracking/violations', { method: 'DELETE' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['tracking-violations'] }),
  })

  const set = <K extends keyof TrackingConfig>(key: K, value: TrackingConfig[K]) => setForm({ ...form, [key]: value })
  const snippetBytes = new TextEncoder().encode(form.custom_snippet).length
  const snippetTooLong = snippetBytes > MAX_SNIPPET_BYTES
  const proxied = form.provider === 'momento' && form.momento_proxy
  const blocked = (violations.data?.items ?? []).filter((item) => !item.allowed)
  const alreadyAllowed = (violations.data?.items ?? []).filter((item) => item.allowed)

  return <>
    <PageHeader title="방문 추적" description="로그인 화면과 개인 화면에 방문 추적 스크립트를 붙입니다. 기본값은 꺼짐이며, 켜도 콘텐츠 보안 정책은 요청마다 다른 nonce로 그 스니펫만 허용합니다." />
    <Stack spacing={2}>
      <ContentCard>
        <Stack spacing={2} component="form" onSubmit={(event) => { event.preventDefault(); save.mutate(form) }}>
          <FormControlLabel control={<Switch checked={form.enabled} onChange={(event) => set('enabled', event.target.checked)} />} label="방문 추적 사용" />
          <TextField select label="수집 도구" value={form.provider} onChange={(event) => set('provider', event.target.value as TrackingProvider)} helperText="Momento는 사내 자체 호스팅 수집기라 데이터가 밖으로 나가지 않는 유일한 선택지입니다." sx={{ maxWidth: 420 }}>
            {providers.map((provider) => <MenuItem key={provider.value} value={provider.value}>{provider.label}</MenuItem>)}
          </TextField>
          {form.provider === 'momento' && <>
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
              <TextField label="Momento 수집기 주소" value={form.momento_url} onChange={(event) => set('momento_url', event.target.value)} placeholder="https://momento.example.com" fullWidth required />
              <TextField label="사이트 ID" value={form.momento_site_id} onChange={(event) => set('momento_site_id', event.target.value)} placeholder="SITE_XXXXXXXX" fullWidth required />
            </Stack>
            <FormControlLabel control={<Switch checked={form.momento_proxy} onChange={(event) => set('momento_proxy', event.target.checked)} />} label={`같은 오리진 프록시 사용 — ReSSO가 ${view.proxy_path}/* 를 수집기로 넘깁니다`} />
            <Alert severity={proxied ? 'success' : 'info'}>{proxied
              ? '스크립트와 수집 요청이 모두 이 서비스 주소를 거치므로 정책에 외부 출처가 등장하지 않습니다. 세션 쿠키는 수집기로 전달되지 않습니다.'
              : '브라우저가 수집기에 직접 연결합니다. 정책의 script-src·connect-src·img-src에 수집기 주소가 더해집니다.'}</Alert>
          </>}
          {(form.provider === 'ga4' || form.provider === 'gtm') &&
            <TextField label="측정 ID" value={form.measurement_id} onChange={(event) => set('measurement_id', event.target.value)} placeholder={form.provider === 'ga4' ? 'G-XXXXXXXXXX' : 'GTM-XXXXXXX'} sx={{ maxWidth: 420 }} required />}
          {form.provider === 'matomo' && <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
            <TextField label="Matomo 주소" value={form.matomo_url} onChange={(event) => set('matomo_url', event.target.value)} placeholder="https://matomo.example.com" fullWidth required />
            <TextField label="사이트 ID" value={form.matomo_site_id} onChange={(event) => set('matomo_site_id', event.target.value)} placeholder="1" fullWidth required />
          </Stack>}
          {form.provider === 'custom' &&
            <TextField label="추적 코드" value={form.custom_snippet} onChange={(event) => set('custom_snippet', event.target.value)} multiline minRows={5} inputProps={{ className: 'mono', spellCheck: false }}
              error={snippetTooLong} helperText={`${snippetBytes.toLocaleString()} / ${MAX_SNIPPET_BYTES.toLocaleString()} 바이트. <script> 태그마다 요청별 nonce가 붙고, 코드 안의 http(s) 출처는 정책에 자동으로 더해집니다.`} required />}
          <TextField label="추가 허용 출처" value={form.allowed_hosts} onChange={(event) => set('allowed_hosts', event.target.value)} multiline minRows={2}
            helperText="스니펫에서 자동으로 읽지 못한 출처를 https://host 형태로 한 줄에 하나씩. 아래 차단 목록의 '허용'을 누르면 여기에 더해집니다." />
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
            <TextField select label="삽입 위치" value={form.placement} onChange={(event) => set('placement', event.target.value as 'head' | 'body')} sx={{ minWidth: 200 }}>
              <MenuItem value="head">head</MenuItem>
              <MenuItem value="body">body</MenuItem>
            </TextField>
            <FormControlLabel control={<Switch checked={form.include_admin} onChange={(event) => set('include_admin', event.target.checked)} />} label="관리 화면(/admin)에서도 추적" />
          </Stack>
          {save.error && <ErrorAlert error={save.error} />}
          <Box><Button type="submit" variant="contained" disabled={save.isPending || snippetTooLong}>저장</Button></Box>
        </Stack>
      </ContentCard>

      <ContentCard>
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: .5 }}>이 설정이 만드는 콘텐츠 보안 정책</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          저장된 설정 기준입니다. 추적이 켜진 화면의 문서만 이 정책을 받고, API 경로와 추적이 꺼진 화면은 원래의 좁은 정책을 그대로 받습니다. 'unsafe-inline'은 어떤 경우에도 넣지 않습니다.
        </Typography>
        <Stack direction="row" alignItems="flex-start" spacing={1}>
          <Typography component="pre" className="mono" sx={{ fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-all', m: 0, flex: 1 }}>{view.policy}</Typography>
          <CopyButton value={view.policy} label="정책 복사" />
        </Stack>
      </ContentCard>

      <ContentCard noPadding>
        <Stack direction="row" alignItems="center" spacing={1} sx={{ px: 2, pt: 2, pb: 1 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, flex: 1 }}>정책이 차단한 출처</Typography>
          <Button size="small" startIcon={<RefreshRoundedIcon />} onClick={() => void violations.refetch()}>새로 고침</Button>
          <Button size="small" color="inherit" startIcon={<DeleteSweepRoundedIcon />} onClick={() => clear.mutate()} disabled={clear.isPending || !violations.data?.items.length}>비우기</Button>
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ px: 2, pb: 1.5 }}>
          추적이 켜진 동안 브라우저가 신고한 것입니다. 이 인스턴스의 메모리에만 남고(최대 100개 출처), 스니펫을 고친 뒤 비우면 아직 막히는 것이 있는지 바로 보입니다.
        </Typography>
        {violations.error ? <Box sx={{ p: 2 }}><ErrorAlert error={violations.error} onRetry={() => void violations.refetch()} /></Box>
          : !violations.data?.items.length ? <EmptyState title="차단된 출처가 없습니다" description={form.enabled ? '추적이 켜진 화면을 열어 보세요. 막히는 것이 있으면 여기에 나타납니다.' : '추적을 켜면 브라우저가 차단한 출처가 여기에 쌓입니다.'} />
            : <TableContainer><Table size="small" aria-label="차단된 출처">
              <TableHead><TableRow><TableCell>출처</TableCell><TableCell>지시어</TableCell><TableCell>화면</TableCell><TableCell align="right">횟수</TableCell><TableCell>마지막</TableCell><TableCell /></TableRow></TableHead>
              <TableBody>{[...blocked, ...alreadyAllowed].map((item) => <TableRow key={`${item.directive} ${item.origin}`}>
                <TableCell className="mono">{item.origin}</TableCell>
                <TableCell><Chip size="small" label={item.directive} /></TableCell>
                <TableCell sx={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.page}</TableCell>
                <TableCell align="right">{item.count.toLocaleString()}</TableCell>
                <TableCell>{formatTimestamp(item.last_seen)}</TableCell>
                <TableCell align="right">{item.allowed
                  ? <Chip size="small" color="success" label="허용됨" />
                  : item.origin.startsWith('http')
                    ? <Button size="small" startIcon={<AddRoundedIcon />} onClick={() => allow.mutate(item.origin)} disabled={allow.isPending}>허용</Button>
                    : <Typography variant="caption" color="text.secondary">nonce 없는 인라인 코드 — 스니펫의 script 태그를 확인하세요</Typography>}</TableCell>
              </TableRow>)}</TableBody>
            </Table></TableContainer>}
        {allow.error && <Box sx={{ p: 2 }}><ErrorAlert error={allow.error} /></Box>}
      </ContentCard>
    </Stack>
  </>
}
