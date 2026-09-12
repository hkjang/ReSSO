import { useEffect, useMemo, useState } from 'react'
import LogoutRoundedIcon from '@mui/icons-material/LogoutRounded'
import SearchRoundedIcon from '@mui/icons-material/SearchRounded'
import { Alert, Box, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, InputAdornment, Paper, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip, Typography } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useRealms, useRealmSelection } from '../lib/realms'
import type { Session } from '../types'
import { formatDate, shortId } from '../lib/format'
import { RealmPicker } from '../components/RealmPicker'
import { useToast } from '../components/toast-context'
import { ContentCard, PageHeader, StatusChip } from '../components/Page'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'
import { CopyButton } from '../components/CopyField'
import { describeDevice } from '../lib/device'
import { describeBulkOutcome, runBulk } from '../lib/bulk'

export function SessionsPage() {
  const queryClient = useQueryClient()
  const { notify } = useToast()
  const realms = useRealms()
  const selection = useRealmSelection(realms.data?.items)
  const [target, setTarget] = useState<Session | null>(null)
  const [search, setSearch] = useState('')
  // Debounced: without it every keystroke is a request now that the search
  // reaches the server.
  const [searchInput, setSearchInput] = useState('')
  useEffect(() => {
    const timer = window.setTimeout(() => setSearch(searchInput.trim()), 300)
    return () => window.clearTimeout(timer)
  }, [searchInput])
  const sessions = useQuery({ queryKey: ['sessions', selection.realmID, search], queryFn: () => api<{ items: Session[]; truncated: boolean }>(`/api/admin/v1/realms/${selection.realmID}/sessions?limit=500&q=${encodeURIComponent(search)}`), enabled: Boolean(selection.realmID), refetchInterval: 20_000 })
  // The dialog promises this revokes the refresh tokens linked to the session,
  // and that is the half that can fail on its own after the session has ended.
  // Closing quietly leaves the operator believing the promise was kept while a
  // relying party holding one of those tokens carries on.
  const revoke = useMutation({
    mutationFn: () => api<{ refresh_tokens_revoked?: boolean; message?: string } | undefined>(
      `/api/admin/v1/realms/${selection.realmID}/sessions/${target!.id}`, { method: 'DELETE' }),
    onSuccess: async (result) => {
      setTarget(null)
      if (result?.refresh_tokens_revoked === false) {
        notify(result.message ?? '세션은 종료했지만 Refresh Token을 폐기하지 못했습니다.', 'warning')
      }
      await queryClient.invalidateQueries({ queryKey: ['sessions', selection.realmID] })
    },
  })
  // Answering "which sessions does this user have open" previously meant
  // scrolling the whole Realm. The search runs on the server: narrowing the
  // rows that came back answered it only for the 500 most recently used, and
  // said a session further down did not exist. Which is also why the empty
  // state has to ask whether a term is in play — these rows are the whole
  // answer now, so "none came back" is either an empty Realm or a search that
  // matched nothing, and telling an operator the Realm has no sessions when
  // their term simply missed sends them looking in the wrong place.
  const visibleSessions = useMemo(() => sessions.data?.items ?? [], [sessions.data])
  // And when there are more than the screen asked for, it has to say so rather
  // than let the missing ones look like they are not there. The server answers
  // that; counting the rows here says "there is more" for a Realm holding
  // exactly 500, and a notice that cries wolf stops being read.
  const truncated = sessions.data?.truncated ?? false
  // Only a session that is still open can be ended, so only those can be
  // picked. Offering a checkbox on an expired row would let an operator build
  // a selection of fourteen and end eleven.
  const revocable = useMemo(() => visibleSessions.filter((session) => session.active), [visibleSessions])
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set())
  // A selection survives neither a Realm change nor a new search: the rows it
  // named are gone from the screen, and acting on identifiers the operator can
  // no longer see is how a bulk action ends something nobody meant to end.
  // Dropped during render, so the toolbar never shows a count for rows that
  // are already off the screen.
  const scope = `${selection.realmID}\u0000${search}`
  const [lastScope, setLastScope] = useState(scope)
  if (lastScope !== scope) { setLastScope(scope); setSelected(new Set()) }
  // Rows also vanish on their own — sessions expire and the list refreshes
  // every twenty seconds — so the selection is narrowed to what is still
  // revocable before it is counted or acted on.
  const picked = useMemo(() => revocable.filter((session) => selected.has(session.id)), [revocable, selected])
  const toggle = (id: string) => setSelected((current) => {
    const next = new Set(current)
    if (!next.delete(id)) next.add(id)
    return next
  })
  const allPicked = revocable.length > 0 && picked.length === revocable.length
  const [bulkOpen, setBulkOpen] = useState(false)
  const bulk = useMutation({
    mutationFn: () => runBulk(picked, (session) =>
      api(`/api/admin/v1/realms/${selection.realmID}/sessions/${session.id}`, { method: 'DELETE' })),
    onSuccess: async (outcome) => {
      setBulkOpen(false)
      setSelected(new Set())
      const described = describeBulkOutcome(outcome, '세션 종료')
      notify(described.message, described.severity)
      await queryClient.invalidateQueries({ queryKey: ['sessions', selection.realmID] })
    },
  })
  if (realms.isLoading) return <PageLoading />
  return <><PageHeader title="SSO 세션" description="사용자가 로그인한 브라우저와 활동 상태를 확인하고 강제로 종료합니다." /><Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ mb: 2 }}><RealmPicker realms={realms.data?.items ?? []} value={selection.realmID} onChange={selection.setRealmID} /><TextField value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="사용자, IP 검색" sx={{ maxWidth: 360 }} inputProps={{ 'aria-label': '세션 검색' }} InputProps={{ startAdornment: <InputAdornment position="start"><SearchRoundedIcon /></InputAdornment> }} /></Stack>
    {truncated && <Alert severity="info" sx={{ mb: 2 }}>최근 사용 순으로 500건만 표시합니다. 사용자나 IP로 검색하면 이 범위 밖의 세션도 찾을 수 있습니다.</Alert>}
    {/* 침해된 계정의 세션 열네 개를 대화 상자 열네 번으로 끝내는 것이 원래
        동작이었다. 선택한 것이 있을 때만 나타나므로 평소 화면은 그대로다. */}
    {picked.length > 0 && <Paper variant="outlined" role="region" aria-label="선택한 세션 작업" sx={{ mb: 2, px: 2, py: 1.2, display: 'flex', alignItems: 'center', gap: 1.5, flexWrap: 'wrap', borderColor: 'primary.main', bgcolor: 'primary.50' }}>
      <Typography fontWeight={700}>{picked.length}개 선택됨</Typography>
      <Box sx={{ flex: 1 }} />
      <Button size="small" onClick={() => setSelected(new Set())}>선택 해제</Button>
      <Button size="small" color="error" variant="contained" startIcon={<LogoutRoundedIcon />} onClick={() => setBulkOpen(true)}>선택한 세션 강제 로그아웃</Button>
    </Paper>}
    <ContentCard noPadding>{sessions.isLoading ? <PageLoading /> : sessions.error ? <Box sx={{ p: 2 }}><ErrorAlert error={sessions.error} onRetry={() => void sessions.refetch()} /></Box> : !visibleSessions.length ? <EmptyState title={search ? '검색 조건에 맞는 세션이 없습니다' : '세션이 없습니다'} description={search ? '사용자 이름이나 IP의 일부로 검색합니다.' : undefined} /> : <TableContainer sx={{ maxHeight: 'calc(100vh - 245px)' }}><Table stickyHeader aria-label="SSO 세션 목록"><TableHead><TableRow><TableCell padding="checkbox"><Checkbox
      // 헤더 체크박스가 고르는 범위는 "지금 화면에 있고 아직 살아 있는 세션"이다.
      // 검색으로 좁힌 결과 전체나 Realm 전체가 아니라는 점은 확인 대화 상자가
      // 글자로 말한다 — 여기서 착각하면 끝내려던 것보다 훨씬 많이 끝난다.
      inputProps={{ 'aria-label': '표시된 활성 세션 모두 선택' }}
      checked={allPicked}
      indeterminate={picked.length > 0 && !allPicked}
      disabled={!revocable.length}
      onChange={() => setSelected(allPicked ? new Set() : new Set(revocable.map((session) => session.id)))}
    /></TableCell><TableCell>사용자</TableCell><TableCell>Session ID</TableCell><TableCell>IP</TableCell><TableCell>마지막 접근</TableCell><TableCell>만료</TableCell><TableCell>상태</TableCell><TableCell align="right">작업</TableCell></TableRow></TableHead><TableBody>{visibleSessions.map((session) => { const active = session.active; return <TableRow key={session.id} selected={selected.has(session.id)}><TableCell padding="checkbox"><Checkbox
        inputProps={{ 'aria-label': `${session.username ?? '이 사용자'} 세션 선택` }}
        checked={selected.has(session.id)} disabled={!active} onChange={() => toggle(session.id)}
      /></TableCell><TableCell><Typography fontWeight={650}>{session.username}</Typography><Tooltip title={session.user_agent || '알 수 없는 클라이언트'}><Typography variant="caption" color="text.secondary" noWrap sx={{ maxWidth: 260, display: 'block' }}>{describeDevice(session.user_agent)}</Typography></Tooltip></TableCell><TableCell><Stack direction="row" alignItems="center" spacing={.3}><Typography variant="body2" className="mono">{shortId(session.id)}</Typography><CopyButton value={session.id} label="Session ID 복사" /></Stack></TableCell><TableCell className="mono">{session.ip_address}</TableCell><TableCell>{formatDate(session.last_access)}</TableCell><TableCell>{formatDate(session.expires_at)}</TableCell><TableCell><StatusChip active={active} activeLabel="활성" inactiveLabel={session.revoked_at ? '종료' : '만료'} /></TableCell><TableCell align="right"><Tooltip title="강제 로그아웃"><span><IconButton aria-label={`${session.username ?? '이 사용자'} 세션 강제 로그아웃`} disabled={!active} color="error" onClick={() => setTarget(session)}><LogoutRoundedIcon /></IconButton></span></Tooltip></TableCell></TableRow> })}</TableBody></Table></TableContainer>}</ContentCard><Dialog open={Boolean(target)} onClose={() => setTarget(null)} maxWidth="xs"><DialogTitle>세션을 종료할까요?</DialogTitle><DialogContent><Typography>{target?.username} 사용자의 이 SSO 세션과 연결된 Refresh Token을 즉시 폐기합니다.</Typography>{revoke.error && <Box sx={{ mt: 2 }}><ErrorAlert error={revoke.error} /></Box>}</DialogContent><DialogActions><Button onClick={() => setTarget(null)}>취소</Button><Button color="error" variant="contained" onClick={() => revoke.mutate()} disabled={revoke.isPending}>강제 로그아웃</Button></DialogActions></Dialog>
    <Dialog open={bulkOpen} onClose={() => setBulkOpen(false)} maxWidth="xs"><DialogTitle>세션 {picked.length}개를 종료할까요?</DialogTitle><DialogContent>
      {/* 조용히 되돌릴 수 없는 일이고, 무엇이 범위인지 착각하기 쉬운 자리다. */}
      <Alert severity="warning" sx={{ mb: 2 }}>선택한 {picked.length}개 세션과 각 세션에 연결된 Refresh Token을 즉시 폐기합니다. 해당 사용자는 다시 로그인해야 합니다.</Alert>
      <Typography variant="body2" color="text.secondary">지금 화면에 표시된 세션 중 선택한 것만 해당합니다{search ? ` — 검색어 '${search}'에 맞는 범위입니다` : ''}. 되돌릴 수 없습니다.</Typography>
      {bulk.error && <Box sx={{ mt: 2 }}><ErrorAlert error={bulk.error} /></Box>}
    </DialogContent><DialogActions><Button onClick={() => setBulkOpen(false)}>취소</Button><Button color="error" variant="contained" onClick={() => bulk.mutate()} disabled={bulk.isPending}>{bulk.isPending ? '종료하는 중…' : `${picked.length}개 강제 로그아웃`}</Button></DialogActions></Dialog></>
}
