import { useState } from 'react'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import SendRoundedIcon from '@mui/icons-material/SendRounded'
import { Alert, Box, Button, Chip, FormControlLabel, MenuItem, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, jsonBody } from '../lib/api'
import { formatTimestamp } from '../lib/format'
import type { MailDelivery, MailDeliveryPage, MailSettings, MailView } from '../types'
import { ContentCard, PageHeader } from '../components/Page'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'
import { useToast } from '../components/toast-context'

const securities = [
  { value: 'auto', label: 'auto — 릴레이가 알리는 대로 (STARTTLS가 있으면 사용)' },
  { value: 'none', label: 'none — 암호화 없음' },
  { value: 'starttls', label: 'starttls — STARTTLS 필수' },
  { value: 'tls', label: 'tls — 처음부터 TLS (대개 465)' },
]

const statusColor: Record<MailDelivery['status'], 'default' | 'success' | 'error'> = { queued: 'default', sent: 'success', failed: 'error' }
const statusLabel: Record<MailDelivery['status'], string> = { queued: '대기', sent: '발송됨', failed: '실패' }

export function MailPage() {
  const view = useQuery({ queryKey: ['mail'], queryFn: () => api<MailView>('/api/admin/v1/mail') })
  if (view.error) return <ErrorAlert error={view.error} onRetry={() => void view.refetch()} />
  if (!view.data) return <PageLoading />
  return <MailEditor view={view.data} />
}

// The form is seeded from the server once and then owned by the person
// typing, as the tracking screen does; a refetch must not overwrite what
// they have not saved.
function MailEditor({ view }: { view: MailView }) {
  const queryClient = useQueryClient()
  const { notify } = useToast()
  const [form, setForm] = useState<MailSettings>(view.settings)
  // The password is never in the settings the server answers with, so it
  // has its own field: empty means "leave the stored one alone".
  const [password, setPassword] = useState('')
  const [clearPassword, setClearPassword] = useState(false)
  const [recipient, setRecipient] = useState('')
  const [passwordSet, setPasswordSet] = useState(view.password_set)
  const deliveries = useQuery({
    queryKey: ['mail-deliveries'],
    queryFn: () => api<MailDeliveryPage>('/api/admin/v1/mail/deliveries?limit=100'),
    refetchInterval: 15_000,
  })

  const save = useMutation({
    mutationFn: () => api<MailView>('/api/admin/v1/mail', { method: 'PUT', ...jsonBody({ settings: form, password, clear_password: clearPassword }) }),
    onSuccess: (saved) => {
      setForm(saved.settings)
      setPasswordSet(saved.password_set)
      setPassword('')
      setClearPassword(false)
      queryClient.setQueryData(['mail'], saved)
      notify(saved.settings['mail.enabled'] ? '메일 알림 설정을 저장했습니다. 시험 발송으로 릴레이가 받는지 확인하세요.' : '메일 알림 설정을 저장했습니다.', 'success')
    },
  })
  const test = useMutation({
    mutationFn: () => api<{ sent: boolean; recipient: string }>('/api/admin/v1/mail/test', { method: 'POST', ...jsonBody({ recipient }) }),
    onSuccess: async (result) => {
      notify(`${result.recipient}(으)로 시험 메일을 보냈습니다. 받은 편지함을 확인하세요.`, 'success')
      await queryClient.invalidateQueries({ queryKey: ['mail-deliveries'] })
    },
    onError: async () => { await queryClient.invalidateQueries({ queryKey: ['mail-deliveries'] }) },
  })

  const set = (key: string, value: string | number | boolean) => setForm({ ...form, [key]: value })
  const text = (key: string) => String(form[key] ?? '')
  const enabled = Boolean(form['mail.enabled'])
  const summary = deliveries.data?.by_status ?? {}

  return <>
    <PageHeader title="메일 알림" description="승인 요청, 결정, API 키 만료, 디렉터리 동기화 실패를 사내 SMTP 릴레이로 알립니다. 기본값은 꺼짐이고, 메일은 배경에서 보내므로 릴레이가 멎어도 요청은 평소처럼 끝납니다." />
    <Stack spacing={2}>
      <ContentCard>
        <Stack spacing={2} component="form" onSubmit={(event) => { event.preventDefault(); save.mutate() }}>
          <FormControlLabel control={<Switch checked={enabled} onChange={(event) => set('mail.enabled', event.target.checked)} />} label="메일 알림 사용" />
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
            <TextField label="SMTP 릴레이 주소 (mail.smtp_host)" value={text('mail.smtp_host')} onChange={(event) => set('mail.smtp_host', event.target.value)} placeholder="relay.corp.example" fullWidth required={enabled} />
            <TextField label="포트 (mail.smtp_port)" type="number" value={text('mail.smtp_port')} onChange={(event) => set('mail.smtp_port', Number(event.target.value))} sx={{ minWidth: 160 }} inputProps={{ min: 1, max: 65535 }} />
            <TextField select label="보안 (mail.security)" value={text('mail.security') || 'auto'} onChange={(event) => set('mail.security', event.target.value)} sx={{ minWidth: 320 }}>
              {securities.map((option) => <MenuItem key={option.value} value={option.value}>{option.label}</MenuItem>)}
            </TextField>
          </Stack>
          <Alert severity="info">사내 릴레이는 대개 포트 25 · 인증 없음 · TLS 없음입니다. 그것이 기본값이며, 인증과 암호화는 릴레이가 요구할 때만 채웁니다. 폐쇄망에서는 릴레이로 postra를 가리키면 알림이 밖으로 나가지 않습니다.</Alert>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
            <TextField label="사용자 이름 (mail.username, 선택)" value={text('mail.username')} onChange={(event) => set('mail.username', event.target.value)} fullWidth />
            <TextField label="비밀번호 (mail.password, 선택)" type="password" value={password} onChange={(event) => setPassword(event.target.value)} fullWidth autoComplete="new-password"
              placeholder={passwordSet ? '설정됨 — 바꿀 때만 입력' : '설정되지 않음'} helperText={passwordSet ? '저장된 비밀번호는 되읽을 수 없습니다. 비워 두면 그대로 유지됩니다.' : undefined} />
          </Stack>
          {passwordSet && <FormControlLabel control={<Switch checked={clearPassword} onChange={(event) => setClearPassword(event.target.checked)} />} label="저장된 비밀번호 지우기" />}
          <FormControlLabel control={<Switch checked={Boolean(form['mail.skip_tls_verify'])} onChange={(event) => set('mail.skip_tls_verify', event.target.checked)} />} label="TLS 인증서 검증 건너뛰기 (mail.skip_tls_verify) — 사내 사설 인증서일 때만" />
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
            <TextField label="보내는 주소 (mail.from_address)" value={text('mail.from_address')} onChange={(event) => set('mail.from_address', event.target.value)} placeholder="resso@corp.example" fullWidth required={enabled} />
            <TextField label="보내는 이름 (mail.from_name)" value={text('mail.from_name')} onChange={(event) => set('mail.from_name', event.target.value)} fullWidth />
          </Stack>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
            <TextField label="이 서비스 주소 (mail.base_url)" value={text('mail.base_url')} onChange={(event) => set('mail.base_url', event.target.value)} placeholder="https://sso.corp.example" fullWidth helperText="메일 속 '바로 열기' 링크가 가리킬 주소. 비우면 링크를 넣지 않습니다." />
            <TextField label="시간 제한 초 (mail.timeout_seconds)" type="number" value={text('mail.timeout_seconds')} onChange={(event) => set('mail.timeout_seconds', Number(event.target.value))} sx={{ minWidth: 200 }} inputProps={{ min: 1 }} />
          </Stack>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mt: 1 }}>보낼 이벤트</Typography>
          <Typography variant="body2" color="text.secondary">자기가 한 일은 자기에게 보내지 않고, 한 사람에게 한 번에 여러 건이 생기면 한 통으로 묶습니다. 종류별로 끌 수 있습니다.</Typography>
          {view.events.map((event) => <FormControlLabel key={event.key}
            control={<Switch checked={form[event.key] !== false} onChange={(change) => set(event.key, change.target.checked)} />}
            label={<Box><Typography variant="body2">{event.label} <Typography component="span" variant="caption" className="mono" color="text.secondary">{event.key}</Typography></Typography><Typography variant="caption" color="text.secondary">{event.description}</Typography></Box>} />)}
          {save.error && <ErrorAlert error={save.error} />}
          <Box><Button type="submit" variant="contained" disabled={save.isPending}>저장</Button></Box>
        </Stack>
      </ContentCard>

      <ContentCard>
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: .5 }}>시험 발송</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
          저장된 설정으로 실제 한 통을 보내고 릴레이의 답을 그 자리에서 보여 줍니다. 릴레이 설정은 한 번에 맞는 일이 드뭅니다 — 저장한 뒤 여기서 확인하세요. 시험 발송도 아래 기록에 남습니다.
        </Typography>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} component="form" onSubmit={(event) => { event.preventDefault(); test.mutate() }}>
          <TextField label="받는 사람" type="email" value={recipient} onChange={(event) => setRecipient(event.target.value)} placeholder="me@corp.example" fullWidth required />
          <Button type="submit" variant="outlined" startIcon={<SendRoundedIcon />} disabled={test.isPending || !enabled} sx={{ whiteSpace: 'nowrap' }}>시험 발송</Button>
        </Stack>
        {!enabled && <Typography variant="caption" color="text.secondary">메일 알림을 켜고 저장한 뒤에 보낼 수 있습니다.</Typography>}
        {test.error && <Box sx={{ mt: 2 }}><ErrorAlert error={test.error} /></Box>}
      </ContentCard>

      <ContentCard noPadding>
        <Stack direction="row" alignItems="center" spacing={1} sx={{ px: 2, pt: 2, pb: 1 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, flex: 1 }}>발송 기록</Typography>
          {Object.entries(summary).map(([status, count]) => <Chip key={status} size="small" color={statusColor[status as MailDelivery['status']] ?? 'default'} label={`${statusLabel[status as MailDelivery['status']] ?? status} ${count.toLocaleString()}`} />)}
          <Button size="small" startIcon={<RefreshRoundedIcon />} onClick={() => void deliveries.refetch()}>새로 고침</Button>
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ px: 2, pb: 1.5 }}>
          시도마다 남습니다 — 언제, 어떤 이벤트로, 누구에게, 무슨 제목으로, 되었는지. "안 왔다"는 문의에 여기서 답합니다. 본문은 담지 않으며, 90일 뒤 지워집니다.
        </Typography>
        {deliveries.error ? <Box sx={{ p: 2 }}><ErrorAlert error={deliveries.error} onRetry={() => void deliveries.refetch()} /></Box>
          : !deliveries.data?.items.length ? <EmptyState title="아직 보낸 메일이 없습니다" description={enabled ? '시험 발송을 하거나, 승인 요청 같은 이벤트가 생기면 여기에 나타납니다.' : '메일 알림을 켜면 보낸 메일이 여기에 쌓입니다.'} />
            : <TableContainer><Table size="small" aria-label="발송 기록">
              <TableHead><TableRow><TableCell>시각</TableCell><TableCell>이벤트</TableCell><TableCell>받는 사람</TableCell><TableCell>제목</TableCell><TableCell>상태</TableCell><TableCell>오류</TableCell></TableRow></TableHead>
              <TableBody>{deliveries.data.items.map((item) => <TableRow key={item.id}>
                <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatTimestamp(item.created_at)}</TableCell>
                <TableCell><Chip size="small" label={item.event} /></TableCell>
                <TableCell className="mono">{item.recipient}</TableCell>
                <TableCell sx={{ maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.subject}</TableCell>
                <TableCell><Chip size="small" color={statusColor[item.status]} label={`${statusLabel[item.status]}${item.attempts > 1 ? ` (${item.attempts}회)` : ''}`} /></TableCell>
                <TableCell sx={{ maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={item.error_message}>{item.error_message}</TableCell>
              </TableRow>)}</TableBody>
            </Table></TableContainer>}
      </ContentCard>
    </Stack>
  </>
}
