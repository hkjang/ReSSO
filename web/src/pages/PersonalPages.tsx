import { useState, type FormEvent } from 'react'
import CheckCircleRoundedIcon from '@mui/icons-material/CheckCircleRounded'
import LogoutRoundedIcon from '@mui/icons-material/LogoutRounded'
import RadioButtonUncheckedRoundedIcon from '@mui/icons-material/RadioButtonUncheckedRounded'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import { Alert, Box, Button, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Grid, IconButton, MenuItem, Stack, Tab, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Tabs, TextField, Tooltip, Typography } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, jsonBody } from '../lib/api'
import { useAuth } from '../lib/auth-context'
import type { APIKey, ApprovalRequest, Role, Session } from '../types'
import { formatDate, shortId } from '../lib/format'
import { EMAIL_MAX_LENGTH, normalizeEmail } from '../lib/email'
import { ContentCard, PageHeader, StatusChip } from '../components/Page'
import { ApprovalRequester, ApprovalTarget } from '../components/ApprovalSummary'
import { approvalKindLabel } from '../lib/approvals'
import { CopyButton } from '../components/CopyField'
import { useToast } from '../components/toast-context'
import { describeDevice } from '../lib/device'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'

export function ProfilePage() {
  const { me, refresh } = useAuth()
  const { notify } = useToast()
  const [email, setEmail] = useState(me?.user.email ?? '')
  const [displayName, setDisplayName] = useState(me?.user.display_name ?? '')
  // Reload the form when the account record changes, adjusting during render
  // rather than in an effect.
  const profileVersion = me ? `${me.user.id}:${me.user.updated_at}` : ''
  const [loadedProfile, setLoadedProfile] = useState(profileVersion)
  if (loadedProfile !== profileVersion) {
    setLoadedProfile(profileVersion)
    setEmail(me?.user.email ?? '')
    setDisplayName(me?.user.display_name ?? '')
  }
  const update = useMutation({ mutationFn: () => api('/api/v1/me/profile', { method: 'PUT', ...jsonBody({ email, display_name: displayName }) }), onSuccess: async () => { notify('프로필을 저장했습니다.'); await refresh() } })
  const emailChanged = normalizeEmail(email) !== normalizeEmail(me?.user.email)
  return <><PageHeader title="내 프로필" description="서비스 관리와 분리된 개인화 영역입니다. 내 정보와 할당된 역할을 확인합니다." /><Grid container spacing={2.25}><Grid size={{ xs: 12, lg: 8 }}><ContentCard><Stack component="form" spacing={2.2} onSubmit={(e: FormEvent) => { e.preventDefault(); update.mutate() }}>{me?.user.federation_id && <Alert severity="info">LDAP 연동 계정입니다. READ_ONLY 정책이면 프로필 변경은 원본 디렉터리에서 수행해야 합니다.</Alert>}{update.error && <ErrorAlert error={update.error} />}<TextField label="아이디" value={me?.user.username ?? ''} disabled helperText="아이디는 Realm 관리자가 관리합니다." /><TextField label="표시 이름" required value={displayName} onChange={(e) => setDisplayName(e.target.value)} /><TextField label="이메일 (선택)" type="email" value={email} inputProps={{ maxLength: EMAIL_MAX_LENGTH }} onChange={(e) => setEmail(e.target.value)} helperText={emailChanged ? '저장하면 기존 이메일 확인 상태가 해제됩니다.' : '이메일 변경 시 확인 상태가 해제됩니다.'} />{me?.user.email && !emailChanged && <Chip label={me.user.email_verified ? '이메일 확인됨' : '이메일 미확인'} size="small" color={me.user.email_verified ? 'success' : 'warning'} variant="outlined" sx={{ alignSelf: 'flex-start' }} />}<Button type="submit" variant="contained" disabled={update.isPending || !displayName} sx={{ alignSelf: 'flex-start' }}>프로필 저장</Button></Stack></ContentCard></Grid><Grid size={{ xs: 12, lg: 4 }}><ContentCard><Typography variant="h3">내 접근 컨텍스트</Typography><Stack spacing={1.5} sx={{ mt: 2 }}><Info label="Realm ID" value={me?.user.realm_id} mono copyable /><Info label="User ID" value={me?.user.id} mono copyable /><Info label="인증 소스" value={me?.user.federation_id ? 'LDAP Federation' : 'Local'} /><Info label="서비스 관리자" value={me?.permissions.platform_admin ? '예' : '아니요'} /><Info label="Realm 관리자" value={me?.permissions.realm_admin ? '예' : '아니요'} /><Box><Typography variant="caption" color="text.secondary">Realm Role</Typography><Stack direction="row" flexWrap="wrap" gap={.7} sx={{ mt: .7 }}>{me?.roles.map((role) => <Chip key={role} label={role} size="small" />)}</Stack></Box></Stack></ContentCard></Grid></Grid></>
}

export function PersonalSecurityPage() {
  const { me } = useAuth()
  const { notify } = useToast()
  const [current, setCurrent] = useState('')
  const [replacement, setReplacement] = useState('')
  const [confirm, setConfirm] = useState('')
  const change = useMutation({
    mutationFn: () => api<{ other_sessions_ended?: boolean; message?: string } | undefined>('/api/v1/me/password', { method: 'PUT', ...jsonBody({ current_password: current, new_password: replacement }) }),
    // The toast said the other sessions were ended whatever happened. Ending
    // them can fail on its own after the password has already changed, and
    // somebody who changed it because they think it is known needs to hear
    // that rather than be reassured.
    onSuccess: (result) => {
      setCurrent(''); setReplacement(''); setConfirm('')
      if (result?.other_sessions_ended === false) {
        notify(result.message ?? '비밀번호는 변경되었지만 다른 세션을 종료하지 못했습니다.', 'warning')
        return
      }
      notify('비밀번호를 변경하고 다른 세션을 종료했습니다.')
    },
  })
  // The Realm's own minimum, rather than a guess. The form previously allowed
  // submitting at 8 characters while the default policy required 12, so the
  // only feedback was a server error after the fact.
  const minLength = me?.password_policy?.min_length ?? 12
  const lockoutMinutes = Math.round((me?.password_policy?.lockout_seconds ?? 900) / 60)
  const requirements = [
    { label: `${minLength}자 이상`, met: replacement.length >= minLength },
    { label: '현재 비밀번호와 다름', met: Boolean(replacement) && replacement !== current },
    { label: '확인란과 일치', met: Boolean(replacement) && replacement === confirm },
  ]
  const ready = requirements.every((item) => item.met)
  const mismatch = Boolean(confirm) && replacement !== confirm
  return <><PageHeader title="로그인 보안" description="비밀번호를 변경하면 현재 브라우저를 제외한 모든 SSO 세션이 종료됩니다." /><ContentCard><Stack component="form" spacing={2.2} sx={{ maxWidth: 560 }} onSubmit={(e: FormEvent) => { e.preventDefault(); change.mutate() }}>{me?.user.federation_id && <Alert severity="info">LDAP 연동 계정입니다. 공급자가 WRITABLE일 때만 여기서 변경할 수 있으며, 그 외에는 원본 디렉터리의 비밀번호 변경 절차를 이용하세요.</Alert>}{change.error && <ErrorAlert error={change.error} />}<TextField label="현재 비밀번호" type="password" required autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} /><TextField label="새 비밀번호" type="password" required autoComplete="new-password" value={replacement} onChange={(e) => setReplacement(e.target.value)} inputProps={{ 'aria-describedby': 'password-requirements' }} /><Box id="password-requirements"><Typography variant="caption" color="text.secondary">이 Realm의 비밀번호 조건</Typography><Stack sx={{ mt: .5 }}>{requirements.map((item) => <Stack key={item.label} direction="row" spacing={.8} alignItems="center"><Box sx={{ width: 16, display: 'grid', placeItems: 'center' }}>{item.met ? <CheckCircleRoundedIcon color="success" sx={{ fontSize: 15 }} /> : <RadioButtonUncheckedRoundedIcon sx={{ fontSize: 15, color: 'text.disabled' }} />}</Box><Typography variant="body2" color={item.met ? 'success.main' : 'text.secondary'}>{item.label}</Typography></Stack>)}</Stack></Box><TextField label="새 비밀번호 확인" type="password" required autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={mismatch} helperText={mismatch ? '새 비밀번호가 일치하지 않습니다.' : ' '} /><Button type="submit" variant="contained" disabled={change.isPending || !current || !ready} sx={{ alignSelf: 'flex-start' }}>비밀번호 변경</Button><Typography variant="caption" color="text.secondary">로그인을 {me?.password_policy?.max_login_attempts ?? 5}회 연속 실패하면 계정이 약 {lockoutMinutes}분 동안 잠깁니다.</Typography></Stack></ContentCard></>
}

export function APIKeysPage() {
  const { me } = useAuth()
  const { notify } = useToast()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [days, setDays] = useState(90)
  const [scopes, setScopes] = useState<string[]>(['api:read', 'mcp:read'])
  const [secret, setSecret] = useState('')
  const [target, setTarget] = useState<APIKey | null>(null)
  const keys = useQuery({ queryKey: ['my-api-keys'], queryFn: () => api<{ items: APIKey[] }>('/api/v1/me/api-keys') })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['my-api-keys'] })
  const create = useMutation({ mutationFn: () => api<{ key: APIKey; secret: string }>('/api/v1/me/api-keys', { method: 'POST', ...jsonBody({ name, scopes, expires_days: days }) }), onSuccess: async (result) => { setOpen(false); setName(''); setSecret(result.secret); await invalidate() } })
  // A rotation that fails used to change nothing and say nothing: the dialog
  // with the new secret simply did not appear, which reads as a click that did
  // not register. Every other mutation on this page shows its error.
  const rotate = useMutation({ mutationFn: (key: APIKey) => api<{ key: APIKey; secret: string }>(`/api/v1/me/api-keys/${key.id}/rotate`, { method: 'POST' }), onSuccess: async (result) => { setSecret(result.secret); await invalidate() }, onError: (error: Error) => notify(error.message, 'error') })
  const revoke = useMutation({ mutationFn: (key: APIKey) => api<void>(`/api/v1/me/api-keys/${key.id}`, { method: 'DELETE' }), onSuccess: async () => { setTarget(null); await invalidate() } })
  const toggleScope = (scope: string) => setScopes((current) => current.includes(scope) ? current.filter((item) => item !== scope) : [...current, scope])
  return <><PageHeader title="개인 API 키" description="REST API와 MCP에 사용할 개인 키를 최소 권한으로 발급하고 주기적으로 회전합니다." action={{ label: 'API 키 만들기', onClick: () => setOpen(true) }} /><Alert severity="warning" sx={{ mb: 2 }}>API 키는 계정 권한을 상속합니다. Secret을 소스 코드나 로그에 남기지 마세요.</Alert><ContentCard noPadding>{keys.isLoading ? <PageLoading /> : keys.error ? <Box sx={{ p: 2 }}><ErrorAlert error={keys.error} onRetry={() => void keys.refetch()} /></Box> : !keys.data?.items.length ? <EmptyState title="개인 API 키가 없습니다" /> : <TableContainer><Table aria-label="개인 API 키 목록"><TableHead><TableRow><TableCell>이름</TableCell><TableCell>Prefix</TableCell><TableCell>Scope</TableCell><TableCell>마지막 사용</TableCell><TableCell>만료</TableCell><TableCell>상태</TableCell><TableCell align="right">작업</TableCell></TableRow></TableHead><TableBody>{keys.data.items.map((key) => { const active = key.active; return <TableRow key={key.id}><TableCell><Typography fontWeight={650}>{key.name}</Typography></TableCell><TableCell className="mono">{key.prefix}</TableCell><TableCell>{key.scopes.map((scope) => <Chip key={scope} label={scope} size="small" sx={{ mr: .5, mb: .5 }} />)}</TableCell><TableCell>{formatDate(key.last_used_at)}</TableCell><TableCell>{formatDate(key.expires_at)}</TableCell><TableCell><StatusChip active={active} activeLabel="활성" inactiveLabel={key.revoked_at ? '폐기' : '만료'} /></TableCell><TableCell align="right"><Stack direction="row" justifyContent="flex-end"><Tooltip title="키 회전"><span><IconButton aria-label={`${key.name} 키 회전`} disabled={!active} onClick={() => rotate.mutate(key)}><RefreshRoundedIcon /></IconButton></span></Tooltip><Tooltip title="키 폐기"><span><IconButton aria-label={`${key.name} 키 폐기`} disabled={!active} color="error" onClick={() => setTarget(key)}><LogoutRoundedIcon /></IconButton></span></Tooltip></Stack></TableCell></TableRow> })}</TableBody></Table></TableContainer>}</ContentCard><Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm"><Stack component="form" onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate() }}><DialogTitle>개인 API 키 만들기</DialogTitle><DialogContent><Stack spacing={2} sx={{ pt: 1 }}>{create.error && <ErrorAlert error={create.error} />}<TextField label="키 이름" required value={name} onChange={(e) => setName(e.target.value)} placeholder="예: 로컬 MCP 클라이언트" /><TextField label="만료 일수" type="number" value={days} onChange={(e) => setDays(Number(e.target.value))} inputProps={{ min: 1, max: 365 }} /><Box><Typography variant="body2" fontWeight={650}>권한 범위</Typography>{['api:read', 'mcp:read', ...(me?.permissions.admin ? ['admin:read'] : [])].map((scope) => <FormControlLabel key={scope} control={<Checkbox checked={scopes.includes(scope)} onChange={() => toggleScope(scope)} />} label={scope} />)}</Box></Stack></DialogContent><DialogActions><Button onClick={() => setOpen(false)}>취소</Button><Button type="submit" variant="contained" disabled={create.isPending || !name || !scopes.length || days < 1 || days > 365}>만들기</Button></DialogActions></Stack></Dialog><Dialog open={Boolean(secret)} onClose={() => setSecret('')} maxWidth="sm"><DialogTitle>Secret을 지금 복사하세요</DialogTitle><DialogContent><Alert severity="warning" sx={{ mb: 2 }}>보안을 위해 다시 표시하지 않습니다. 키를 잃으면 회전하세요.</Alert><Stack direction="row" spacing={1} alignItems="center"><TextField value={secret} fullWidth InputProps={{ readOnly: true }} inputProps={{ className: 'mono', 'aria-label': '발급된 API 키' }} /><CopyButton value={secret} label="Secret 복사" size="medium" /></Stack></DialogContent><DialogActions><Button variant="contained" onClick={() => setSecret('')}>저장 완료</Button></DialogActions></Dialog><Dialog open={Boolean(target)} onClose={() => setTarget(null)} maxWidth="xs"><DialogTitle>API 키 폐기</DialogTitle><DialogContent>키 “{target?.name}”은 즉시 사용할 수 없게 됩니다.</DialogContent><DialogActions><Button onClick={() => setTarget(null)}>취소</Button><Button color="error" variant="contained" onClick={() => target && revoke.mutate(target)}>폐기</Button></DialogActions></Dialog></>
}

export function PersonalSessionsPage() {
  const queryClient = useQueryClient()
  const { me } = useAuth()
  const { notify } = useToast()
  const idleMinutes = Math.round((me?.password_policy?.idle_timeout_seconds ?? 0) / 60)
  const [confirmCurrent, setConfirmCurrent] = useState<Session | null>(null)
  const sessions = useQuery({ queryKey: ['my-sessions'], queryFn: () => api<{ items: Session[]; current_session_id: string }>('/api/v1/me/sessions'), refetchInterval: 30_000 })
  const revoke = useMutation({
    mutationFn: (session: Session) => api<void>(`/api/v1/me/sessions/${session.id}`, { method: 'DELETE' }),
    onSuccess: async () => { setConfirmCurrent(null); notify('세션을 종료했습니다.'); await queryClient.invalidateQueries({ queryKey: ['my-sessions'] }) },
  })
  if (sessions.isLoading) return <PageLoading />
  if (sessions.error) return <ErrorAlert error={sessions.error} onRetry={() => void sessions.refetch()} />
  return <><PageHeader title="내 세션" description="로그인된 브라우저와 기기를 확인하고 사용하지 않는 세션을 종료합니다." />{idleMinutes > 0 && <Alert severity="info" sx={{ mb: 2 }}>이 Realm은 약 {idleMinutes}분 동안 사용되지 않은 세션을 자동으로 만료합니다.</Alert>}<ContentCard noPadding>{!sessions.data?.items.length ? <EmptyState title="세션이 없습니다" /> : <TableContainer><Table aria-label="내 로그인 세션 목록"><TableHead><TableRow><TableCell>기기</TableCell><TableCell>IP</TableCell><TableCell>마지막 접근</TableCell><TableCell>만료</TableCell><TableCell>상태</TableCell><TableCell align="right">작업</TableCell></TableRow></TableHead><TableBody>{sessions.data.items.map((session) => { const current = sessions.data.current_session_id === session.id; const active = session.active; return <TableRow key={session.id}><TableCell><Typography fontWeight={650}>{describeDevice(session.user_agent)}</Typography><Tooltip title={session.user_agent || '알 수 없는 클라이언트'}><Typography variant="caption" className="mono" color="text.secondary">{shortId(session.id)}</Typography></Tooltip></TableCell><TableCell className="mono">{session.ip_address}</TableCell><TableCell>{formatDate(session.last_access)}</TableCell><TableCell>{formatDate(session.expires_at)}</TableCell><TableCell>{current ? <Chip label="현재 세션" color="primary" size="small" /> : <StatusChip active={active} />}</TableCell><TableCell align="right"><Button color="error" size="small" disabled={!active || revoke.isPending} onClick={() => current ? setConfirmCurrent(session) : revoke.mutate(session)}>{current ? '지금 로그아웃' : '로그아웃'}</Button></TableCell></TableRow> })}</TableBody></Table></TableContainer>}</ContentCard>{revoke.error && <Box sx={{ mt: 2 }}><ErrorAlert error={revoke.error} /></Box>}<Dialog open={Boolean(confirmCurrent)} onClose={() => setConfirmCurrent(null)} maxWidth="xs"><DialogTitle>현재 세션을 종료할까요?</DialogTitle><DialogContent>지금 사용 중인 브라우저의 세션입니다. 종료하면 즉시 로그아웃되어 다시 로그인해야 합니다.</DialogContent><DialogActions><Button onClick={() => setConfirmCurrent(null)}>취소</Button><Button color="error" variant="contained" onClick={() => confirmCurrent && revoke.mutate(confirmCurrent)}>로그아웃</Button></DialogActions></Dialog></>
}

export function PersonalRequestsPage() {
  const queryClient = useQueryClient()
  const [tab, setTab] = useState(0)
  const [open, setOpen] = useState(false)
  const [roleID, setRoleID] = useState('')
  const [reason, setReason] = useState('')
  const [reviewTarget, setReviewTarget] = useState<ApprovalRequest | null>(null)
  const [reviewDecision, setReviewDecision] = useState<'approve' | 'reject'>('approve')
  const [note, setNote] = useState('')
  const requests = useQuery({ queryKey: ['my-requests'], queryFn: () => api<{ items: ApprovalRequest[] }>('/api/v1/me/requests') })
  const reviews = useQuery({ queryKey: ['my-reviews'], queryFn: () => api<{ items: ApprovalRequest[] }>('/api/v1/me/reviews') })
  const roles = useQuery({ queryKey: ['requestable-roles'], queryFn: () => api<{ items: Role[] }>('/api/v1/me/requestable-roles') })
  const create = useMutation({ mutationFn: () => api<ApprovalRequest>('/api/v1/me/requests', { method: 'POST', ...jsonBody({ role_id: roleID, reason }) }), onSuccess: async () => { setOpen(false); setRoleID(''); setReason(''); await queryClient.invalidateQueries({ queryKey: ['my-requests'] }) } })
  const decide = useMutation({ mutationFn: () => api<ApprovalRequest>(`/api/v1/me/reviews/${reviewTarget!.id}/decision`, { method: 'POST', ...jsonBody({ decision: reviewDecision, note }) }), onSuccess: async () => { setReviewTarget(null); setNote(''); await queryClient.invalidateQueries({ queryKey: ['my-reviews'] }) } })
  const data = tab === 0 ? requests : reviews
  return <><PageHeader title="접근 요청" description="Realm 관리자가 승인 절차를 켠 경우에만 제공됩니다. 역할을 요청하고 팀장 검토 결과를 확인합니다." action={{ label: 'Role 요청', onClick: () => setOpen(true) }} /><ContentCard noPadding><Tabs value={tab} onChange={(_, value) => setTab(value)} sx={{ px: 2, borderBottom: '1px solid', borderColor: 'divider' }}><Tab label="내 요청" /><Tab label={`내 검토함 (${reviews.data?.items.filter((item) => item.status === 'PENDING').length ?? 0})`} /></Tabs>{data.isLoading ? <PageLoading /> : data.error ? <Box sx={{ p: 2 }}><ErrorAlert error={data.error} onRetry={() => void data.refetch()} /></Box> : !data.data?.items.length ? <EmptyState title={tab === 0 ? '내 요청이 없습니다' : '검토할 요청이 없습니다'} /> : <TableContainer><Table aria-label="내 접근 요청 목록"><TableHead><TableRow><TableCell>유형</TableCell>{tab === 1 && <TableCell>요청자</TableCell>}<TableCell>부여 대상</TableCell><TableCell>사유</TableCell><TableCell>상태</TableCell><TableCell>요청일</TableCell>{tab === 1 && <TableCell align="right">결정</TableCell>}</TableRow></TableHead><TableBody>{data.data.items.map((request) => <TableRow key={request.id}><TableCell><Typography fontWeight={650}>{approvalKindLabel(request.kind)}</Typography><Typography variant="caption" color="text.secondary">{request.realm_name}</Typography></TableCell>{tab === 1 && <TableCell><ApprovalRequester request={request} /></TableCell>}<TableCell><ApprovalTarget request={request} /></TableCell><TableCell sx={{ maxWidth: 280 }}>{request.reason || '—'}</TableCell><TableCell><Chip label={request.status} size="small" color={request.status === 'PENDING' ? 'warning' : request.status === 'APPROVED' ? 'success' : 'default'} /></TableCell><TableCell>{formatDate(request.created_at)}</TableCell>{tab === 1 && <TableCell align="right">{request.status === 'PENDING' && <Stack direction="row" justifyContent="flex-end"><Button size="small" onClick={() => { setReviewTarget(request); setReviewDecision('reject') }}>반려</Button><Button size="small" variant="contained" onClick={() => { setReviewTarget(request); setReviewDecision('approve') }}>승인</Button></Stack>}</TableCell>}</TableRow>)}</TableBody></Table></TableContainer>}</ContentCard><Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm"><Stack component="form" onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate() }}><DialogTitle>Realm Role 요청</DialogTitle><DialogContent><Stack spacing={2} sx={{ pt: 1 }}>{create.error && <ErrorAlert error={create.error} />}<TextField select label="요청 Role" required value={roleID} onChange={(e) => setRoleID(e.target.value)}>{roles.data?.items.map((role) => <MenuItem key={role.id} value={role.id}>{role.name} — {role.description}</MenuItem>)}</TextField><TextField label="요청 사유" required multiline minRows={3} value={reason} onChange={(e) => setReason(e.target.value)} /></Stack></DialogContent><DialogActions><Button onClick={() => setOpen(false)}>취소</Button><Button type="submit" variant="contained" disabled={!roleID || !reason || create.isPending}>요청</Button></DialogActions></Stack></Dialog><Dialog open={Boolean(reviewTarget)} onClose={() => setReviewTarget(null)} maxWidth="sm"><DialogTitle>{reviewDecision === 'approve' ? '팀장 승인' : '팀장 반려'}</DialogTitle><DialogContent>{reviewTarget && <Alert severity={reviewDecision === 'approve' ? 'warning' : 'info'} sx={{ mb: 2 }}>{reviewDecision === 'approve' ? <>승인하면 <strong>{reviewTarget.requester_display_name || reviewTarget.requester_username}</strong> 계정에 {reviewTarget.kind === 'ROLE_ASSIGNMENT' ? <>Role <strong className="mono">{reviewTarget.target_role_name || '(확인 불가)'}</strong>이(가)</> : <>요청한 권한이</>} 즉시 부여됩니다.</> : <>반려하면 요청은 종료되고 권한은 부여되지 않습니다.</>}</Alert>}{reviewTarget?.reason && <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>요청 사유: {reviewTarget.reason}</Typography>}<TextField label="검토 의견" multiline minRows={3} value={note} onChange={(e) => setNote(e.target.value)} sx={{ mt: 1 }} helperText="결정 근거는 감사 이벤트에 함께 기록됩니다." />{decide.error && <Box sx={{ mt: 2 }}><ErrorAlert error={decide.error} /></Box>}</DialogContent><DialogActions><Button onClick={() => setReviewTarget(null)}>취소</Button><Button color={reviewDecision === 'approve' ? 'primary' : 'error'} variant="contained" onClick={() => decide.mutate()}>{reviewDecision === 'approve' ? '승인' : '반려'}</Button></DialogActions></Dialog></>
}

function Info({ label, value, mono = false, copyable = false }: { label: string; value?: string; mono?: boolean; copyable?: boolean }) {
  return <Box><Typography variant="caption" color="text.secondary">{label}</Typography><Stack direction="row" alignItems="center" spacing={.5}><Typography className={mono ? 'mono' : undefined} sx={{ overflowWrap: 'anywhere', minWidth: 0 }}>{value || '—'}</Typography>{copyable && <CopyButton value={value} label={`${label} 복사`} />}</Stack></Box>
}
