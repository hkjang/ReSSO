import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import ArrowForwardRoundedIcon from '@mui/icons-material/ArrowForwardRounded'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import SearchRoundedIcon from '@mui/icons-material/SearchRounded'
import { Alert, Box, Button, Chip, InputAdornment, MenuItem, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TablePagination, TableRow, TextField, Typography } from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { formatTimestamp, shortId } from '../lib/format'
import { rowActivation } from '../lib/rowActivation'
import { ContentCard, PageHeader } from '../components/Page'
import { CopyButton } from '../components/CopyField'
import { SortableCell } from '../components/SortableTable'
import { DetailDrawer } from '../components/DetailDrawer'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'

interface AuditRow { id: number; occurred_at: string; realm_id?: string; actor_name: string; event_type: string; result: string; target_type: string; target_id: string; ip_address: string; trace_id: string; detail: Record<string, unknown> }
interface LogRow { id: number; occurred_at: string; level: string; component: string; message: string; trace_id: string; attributes: Record<string, unknown> }

export function AuditPage() {
  const navigate = useNavigate()
  const [selected, setSelected] = useState<AuditRow | null>(null)
  const [result, setResult] = useState('')
  const [actorInput, setActorInput] = useState('')
  const [actor, setActor] = useState('')
  const [page, setPage] = useState(0)
  const [rowsPerPage, setRowsPerPage] = useState(100)
  // The event type lives in the URL so other screens can link straight to one
  // kind of event. The approvals screen shows the most recent requests and cuts
  // the rest; the decisions it cannot show are recorded here, and a link that
  // arrives unfiltered leaves the reader to find them again.
  const [params, setParams] = useSearchParams()
  const eventType = params.get('event_type') ?? ''
  const setEventType = (value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set('event_type', value)
    else next.delete('event_type')
    setParams(next, { replace: true })
    setPage(0)
  }
  const [oldestFirst, setOldestFirst] = useState(false)
  // The search box is debounced: without it every keystroke was a request.
  useEffect(() => {
    const timer = window.setTimeout(() => { setActor(actorInput.trim()); setPage(0) }, 300)
    return () => window.clearTimeout(timer)
  }, [actorInput])
  const eventTypes = useQuery({
    queryKey: ['audit-event-types'],
    queryFn: () => api<{ items: string[] }>('/api/admin/v1/audit/event-types'),
    staleTime: 60_000,
  })
  const query = useQuery({
    queryKey: ['audit', eventType, result, actor, oldestFirst, page, rowsPerPage],
    queryFn: () => api<{ items: AuditRow[]; total: number }>(`/api/admin/v1/audit?limit=${rowsPerPage}&offset=${page * rowsPerPage}`
      + `&event_type=${encodeURIComponent(eventType)}&result=${encodeURIComponent(result)}&actor=${encodeURIComponent(actor)}`
      + `&order=${oldestFirst ? 'asc' : 'desc'}`),
    refetchInterval: 30_000,
  })
  const filtered = Boolean(eventType || result || actor)
  const clear = () => { setEventType(''); setResult(''); setActorInput(''); setActor(''); setPage(0) }
  return <><PageHeader title="감사 이벤트" description="로그인, Token, 관리자 변경과 키 회전을 보안 감사 관점에서 추적합니다." badge="365일 보존" />
    <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} sx={{ mb: 2 }}>
      <TextField select label="이벤트" value={eventType} onChange={(e) => { setEventType(e.target.value); setPage(0) }} sx={{ minWidth: 220 }}>
        <MenuItem value="">전체</MenuItem>
        {eventTypes.data?.items.map((item) => <MenuItem key={item} value={item}>{item}</MenuItem>)}
      </TextField>
      <TextField select label="결과" value={result} onChange={(e) => { setResult(e.target.value); setPage(0) }} sx={{ minWidth: 150 }}>
        <MenuItem value="">전체</MenuItem>
        <MenuItem value="SUCCESS">SUCCESS</MenuItem>
        <MenuItem value="FAILURE">FAILURE</MenuItem>
        <MenuItem value="PARTIAL">PARTIAL</MenuItem>
      </TextField>
      <TextField value={actorInput} onChange={(e) => setActorInput(e.target.value)} placeholder="행위자 검색" sx={{ maxWidth: 320 }}
        inputProps={{ 'aria-label': '행위자 검색' }}
        InputProps={{ startAdornment: <InputAdornment position="start"><SearchRoundedIcon /></InputAdornment> }} />
      {filtered && <Button onClick={clear} sx={{ alignSelf: { md: 'center' } }}>필터 해제</Button>}
    </Stack>
    <ContentCard noPadding>{query.isLoading ? <PageLoading /> : query.error ? <Box sx={{ p: 2 }}><ErrorAlert error={query.error} onRetry={() => void query.refetch()} /></Box> : !query.data?.items.length ? <EmptyState title={filtered ? '조건에 맞는 감사 이벤트가 없습니다' : '감사 이벤트가 없습니다'} description={filtered ? '필터를 해제하거나 조건을 넓혀보세요.' : undefined} /> : <>
      <TableContainer sx={{ maxHeight: 'calc(100vh - 320px)' }}><Table stickyHeader aria-label="감사 이벤트 목록"><TableHead><TableRow><SortableCell column="occurred_at" sort={{ column: 'occurred_at', descending: !oldestFirst }} onSort={(next) => { setOldestFirst(!next.descending); setPage(0) }}>시각</SortableCell><TableCell>이벤트</TableCell><TableCell>결과</TableCell><TableCell>행위자</TableCell><TableCell>대상</TableCell><TableCell>IP</TableCell><TableCell>Trace</TableCell></TableRow></TableHead><TableBody>
        {query.data.items.map((event) => <TableRow hover key={event.id} {...rowActivation(() => setSelected(event))} sx={{ cursor: 'pointer' }}><TableCell>{formatTimestamp(event.occurred_at)}</TableCell><TableCell><Typography fontWeight={650}>{event.event_type}</Typography></TableCell><TableCell><Chip size="small" label={event.result} color={event.result === 'SUCCESS' ? 'success' : event.result === 'PARTIAL' ? 'warning' : 'error'} variant="outlined" /></TableCell><TableCell>{event.actor_name || 'system'}</TableCell><TableCell>{event.target_type} {event.target_id && <span className="mono">{shortId(event.target_id)}</span>}</TableCell><TableCell className="mono">{event.ip_address}</TableCell><TableCell onClick={(e) => e.stopPropagation()}><Stack direction="row" alignItems="center" spacing={.3}><Typography variant="body2" className="mono">{shortId(event.trace_id)}</Typography><CopyButton value={event.trace_id} label="Trace ID 복사" /></Stack></TableCell></TableRow>)}
      </TableBody></Table></TableContainer>
      <TablePagination component="div" count={query.data.total} page={page} rowsPerPage={rowsPerPage} rowsPerPageOptions={[50, 100, 200]} onPageChange={(_, next) => setPage(next)} onRowsPerPageChange={(event) => { setRowsPerPage(Number(event.target.value)); setPage(0) }} labelRowsPerPage="페이지당" />
    </>}</ContentCard>
    <DetailDrawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.event_type ?? ''} subtitle={selected ? formatTimestamp(selected.occurred_at) : undefined}>
      <KeyValue label="결과" value={selected?.result} />
      <KeyValue label="행위자" value={selected?.actor_name || 'system'} />
      <KeyValue label="대상" value={`${selected?.target_type ?? ''} ${selected?.target_id ?? ''}`} copyValue={selected?.target_id} />
      <KeyValue label="IP" value={selected?.ip_address} mono />
      <KeyValue label="Trace ID" value={selected?.trace_id} mono copyValue={selected?.trace_id} />
      {selected?.trace_id && <Button sx={{ mt: 2 }} size="small" endIcon={<ArrowForwardRoundedIcon />} onClick={() => navigate(`/admin/logs?trace=${encodeURIComponent(selected.trace_id)}`)}>같은 Trace의 서버 로그 보기</Button>}
      <Typography variant="h3" sx={{ mt: 3, mb: 1 }}>상세 데이터</Typography>
      <CodeBlock value={selected?.detail} />
    </DetailDrawer></>
}

export function LogsPage() {
  const [params, setParams] = useSearchParams()
  const [level, setLevel] = useState('')
  // A trace handed over from the audit screen seeds the search.
  const [searchInput, setSearchInput] = useState(() => params.get('trace') ?? '')
  const [search, setSearch] = useState(() => params.get('trace') ?? '')
  const [selected, setSelected] = useState<LogRow | null>(null)
  // Debounced: the query used to fire on every keystroke, so pasting or typing
  // a trace identifier issued one request per character.
  useEffect(() => {
    const timer = window.setTimeout(() => setSearch(searchInput.trim()), 300)
    return () => window.clearTimeout(timer)
  }, [searchInput])
  // Keep the handed-over trace in the URL only while it is what is displayed.
  useEffect(() => {
    if (params.get('trace') && params.get('trace') !== search) {
      const next = new URLSearchParams(params)
      next.delete('trace')
      setParams(next, { replace: true })
    }
  }, [search, params, setParams])
  // While the term is still the trace the audit screen handed over, send it as
  // the trace filter rather than as free text. It is an exact identifier, and
  // searching a mirror of thirty days of requests for it with a leading
  // wildcard scans the whole table for something one index lookup answers. The
  // moment the term is edited it is no longer that trace, and the effect above
  // has already dropped it from the URL, so this falls back to free text on its
  // own.
  const handedOverTrace = params.get('trace') === search ? search : ''
  const query = useQuery({
    queryKey: ['system-logs', level, search, handedOverTrace],
    queryFn: () => api<{ items: LogRow[] }>(`/api/admin/v1/system-logs?limit=500&level=${encodeURIComponent(level)}`
      + (handedOverTrace ? `&trace=${encodeURIComponent(handedOverTrace)}` : `&q=${encodeURIComponent(search)}`)),
    refetchInterval: 15_000,
  })
  const truncated = (query.data?.items.length ?? 0) >= 500
  return <><PageHeader title="서버 로그" description="ReSSO 서버의 구조화 로그를 Trace ID와 함께 확인합니다. Password, Secret, Token 필드는 저장 전에 마스킹됩니다." badge="30일 보존" />
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ mb: 2 }}>
      <TextField select label="Level" value={level} onChange={(e) => setLevel(e.target.value)} sx={{ maxWidth: 180 }}><MenuItem value="">전체</MenuItem>{['ERROR', 'WARN', 'INFO', 'DEBUG'].map((item) => <MenuItem key={item} value={item}>{item}</MenuItem>)}</TextField>
      <TextField placeholder="메시지, 컴포넌트, Trace ID 검색" value={searchInput} onChange={(e) => setSearchInput(e.target.value)} sx={{ maxWidth: 430 }} inputProps={{ 'aria-label': '로그 검색' }} InputProps={{ startAdornment: <InputAdornment position="start"><SearchRoundedIcon /></InputAdornment> }} />
      <Button startIcon={<RefreshRoundedIcon />} onClick={() => query.refetch()}>새로고침</Button>
    </Stack>
    {truncated && <Alert severity="info" sx={{ mb: 2 }}>가장 최근 500건만 표시합니다. 조건을 좁히면 더 정확하게 찾을 수 있습니다.</Alert>}
    <ContentCard noPadding>{query.isLoading ? <PageLoading /> : query.error ? <Box sx={{ p: 2 }}><ErrorAlert error={query.error} onRetry={() => void query.refetch()} /></Box> : !query.data?.items.length ? <EmptyState title="조건에 맞는 로그가 없습니다" description={search ? '검색어를 지우거나 Level 필터를 넓혀보세요.' : undefined} /> : <TableContainer sx={{ maxHeight: 'calc(100vh - 260px)' }}><Table stickyHeader aria-label="서버 로그 목록"><TableHead><TableRow><TableCell>시각</TableCell><TableCell>Level</TableCell><TableCell>Component</TableCell><TableCell>메시지</TableCell><TableCell>Trace ID</TableCell></TableRow></TableHead><TableBody>{query.data.items.map((log) => <TableRow hover key={log.id} {...rowActivation(() => setSelected(log))} sx={{ cursor: 'pointer' }}><TableCell>{formatTimestamp(log.occurred_at)}</TableCell><TableCell><LogLevel level={log.level} /></TableCell><TableCell className="mono">{log.component}</TableCell><TableCell sx={{ maxWidth: 540 }}><Typography noWrap>{log.message}</Typography></TableCell><TableCell onClick={(e) => e.stopPropagation()}><Stack direction="row" alignItems="center" spacing={.3}><Typography variant="body2" className="mono">{shortId(log.trace_id)}</Typography><CopyButton value={log.trace_id} label="Trace ID 복사" /></Stack></TableCell></TableRow>)}</TableBody></Table></TableContainer>}</ContentCard>
    <DetailDrawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.message ?? ''} subtitle={selected ? formatTimestamp(selected.occurred_at) : undefined}>
      <KeyValue label="Level" value={selected?.level} />
      <KeyValue label="Component" value={selected?.component} mono />
      <KeyValue label="Trace ID" value={selected?.trace_id} mono copyValue={selected?.trace_id} />
      {selected?.trace_id && selected.trace_id !== search && <Button sx={{ mt: 2 }} size="small" endIcon={<ArrowForwardRoundedIcon />} onClick={() => { setSearchInput(selected.trace_id); setSelected(null) }}>같은 Trace의 로그만 보기</Button>}
      <Typography variant="h3" sx={{ mt: 3, mb: 1 }}>Attributes</Typography>
      <CodeBlock value={selected?.attributes} />
    </DetailDrawer></>
}

function LogLevel({ level }: { level: string }) {
  const color = level === 'ERROR' ? 'error' : level === 'WARN' ? 'warning' : level === 'INFO' ? 'primary' : 'default'
  return <Chip size="small" label={level} color={color} variant="outlined" />
}

function KeyValue({ label, value, mono = false, copyValue }: { label: string; value?: string; mono?: boolean; copyValue?: string }) {
  return <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ py: 1.2, borderBottom: '1px solid', borderColor: 'divider' }}><Typography color="text.secondary" sx={{ width: 120, flex: '0 0 auto' }}>{label}</Typography><Stack direction="row" alignItems="center" spacing={.5} sx={{ minWidth: 0 }}><Typography className={mono ? 'mono' : undefined} sx={{ overflowWrap: 'anywhere' }}>{value || '—'}</Typography><CopyButton value={copyValue} label={`${label} 복사`} /></Stack></Stack>
}

function CodeBlock({ value }: { value: unknown }) {
  return <Box component="pre" className="mono" sx={{ m: 0, p: 2, bgcolor: '#101828', color: '#d0d5dd', borderRadius: 1.5, overflowX: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12.5 }}>{JSON.stringify(value ?? {}, null, 2)}</Box>
}
