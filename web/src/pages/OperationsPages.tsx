import { useState } from 'react'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import SearchRoundedIcon from '@mui/icons-material/SearchRounded'
import { Box, Button, Chip, InputAdornment, MenuItem, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { formatDate, shortId } from '../lib/format'
import { ContentCard, PageHeader } from '../components/Page'
import { DetailDrawer } from '../components/DetailDrawer'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'

interface AuditRow { id: number; occurred_at: string; realm_id?: string; actor_name: string; event_type: string; result: string; target_type: string; target_id: string; ip_address: string; trace_id: string; detail: Record<string, unknown> }
interface LogRow { id: number; occurred_at: string; level: string; component: string; message: string; trace_id: string; attributes: Record<string, unknown> }

export function AuditPage() {
  const [selected, setSelected] = useState<AuditRow | null>(null)
  const query = useQuery({ queryKey: ['audit'], queryFn: () => api<{ items: AuditRow[] }>('/api/admin/v1/audit?limit=500'), refetchInterval: 30_000 })
  if (query.isLoading) return <PageLoading />
  if (query.error) return <ErrorAlert error={query.error} />
  return <><PageHeader title="감사 이벤트" description="로그인, Token, 관리자 변경과 키 회전을 보안 감사 관점에서 추적합니다." badge="365일 보존" /><ContentCard noPadding>{!query.data?.items.length ? <EmptyState title="감사 이벤트가 없습니다" /> : <TableContainer sx={{ maxHeight: 'calc(100vh - 205px)' }}><Table stickyHeader><TableHead><TableRow><TableCell>시각</TableCell><TableCell>이벤트</TableCell><TableCell>결과</TableCell><TableCell>행위자</TableCell><TableCell>대상</TableCell><TableCell>IP</TableCell><TableCell>Trace</TableCell></TableRow></TableHead><TableBody>{query.data.items.map((event) => <TableRow hover key={event.id} onClick={() => setSelected(event)} sx={{ cursor: 'pointer' }}><TableCell>{formatDate(event.occurred_at)}</TableCell><TableCell><Typography fontWeight={650}>{event.event_type}</Typography></TableCell><TableCell><Chip size="small" label={event.result} color={event.result === 'SUCCESS' ? 'success' : 'error'} variant="outlined" /></TableCell><TableCell>{event.actor_name || 'system'}</TableCell><TableCell>{event.target_type} {event.target_id && <span className="mono">{shortId(event.target_id)}</span>}</TableCell><TableCell className="mono">{event.ip_address}</TableCell><TableCell className="mono">{shortId(event.trace_id)}</TableCell></TableRow>)}</TableBody></Table></TableContainer>}</ContentCard><DetailDrawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.event_type ?? ''} subtitle={selected ? formatDate(selected.occurred_at) : undefined}><KeyValue label="결과" value={selected?.result} /><KeyValue label="행위자" value={selected?.actor_name || 'system'} /><KeyValue label="대상" value={`${selected?.target_type ?? ''} ${selected?.target_id ?? ''}`} /><KeyValue label="IP" value={selected?.ip_address} mono /><KeyValue label="Trace ID" value={selected?.trace_id} mono /><Typography variant="h3" sx={{ mt: 3, mb: 1 }}>상세 데이터</Typography><CodeBlock value={selected?.detail} /></DetailDrawer></>
}

export function LogsPage() {
  const [level, setLevel] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<LogRow | null>(null)
  const query = useQuery({ queryKey: ['system-logs', level, search], queryFn: () => api<{ items: LogRow[] }>(`/api/admin/v1/system-logs?limit=500&level=${encodeURIComponent(level)}&q=${encodeURIComponent(search)}`), refetchInterval: 15_000 })
  return <><PageHeader title="서버 로그" description="ReSSO 서버의 구조화 로그를 Trace ID와 함께 확인합니다. Password, Secret, Token 필드는 저장 전에 마스킹됩니다." badge="30일 보존" /><Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ mb: 2 }}><TextField select label="Level" value={level} onChange={(e) => setLevel(e.target.value)} sx={{ maxWidth: 180 }}><MenuItem value="">전체</MenuItem>{['ERROR', 'WARN', 'INFO', 'DEBUG'].map((item) => <MenuItem key={item} value={item}>{item}</MenuItem>)}</TextField><TextField placeholder="메시지, 컴포넌트, Trace ID 검색" value={search} onChange={(e) => setSearch(e.target.value)} sx={{ maxWidth: 430 }} InputProps={{ startAdornment: <InputAdornment position="start"><SearchRoundedIcon /></InputAdornment> }} /><Button startIcon={<RefreshRoundedIcon />} onClick={() => query.refetch()}>새로고침</Button></Stack><ContentCard noPadding>{query.isLoading ? <PageLoading /> : query.error ? <Box sx={{ p: 2 }}><ErrorAlert error={query.error} /></Box> : !query.data?.items.length ? <EmptyState title="조건에 맞는 로그가 없습니다" /> : <TableContainer sx={{ maxHeight: 'calc(100vh - 260px)' }}><Table stickyHeader><TableHead><TableRow><TableCell>시각</TableCell><TableCell>Level</TableCell><TableCell>Component</TableCell><TableCell>메시지</TableCell><TableCell>Trace ID</TableCell></TableRow></TableHead><TableBody>{query.data.items.map((log) => <TableRow hover key={log.id} onClick={() => setSelected(log)} sx={{ cursor: 'pointer' }}><TableCell>{formatDate(log.occurred_at)}</TableCell><TableCell><LogLevel level={log.level} /></TableCell><TableCell className="mono">{log.component}</TableCell><TableCell sx={{ maxWidth: 540 }}><Typography noWrap>{log.message}</Typography></TableCell><TableCell className="mono">{shortId(log.trace_id)}</TableCell></TableRow>)}</TableBody></Table></TableContainer>}</ContentCard><DetailDrawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.message ?? ''} subtitle={selected ? formatDate(selected.occurred_at) : undefined}><KeyValue label="Level" value={selected?.level} /><KeyValue label="Component" value={selected?.component} mono /><KeyValue label="Trace ID" value={selected?.trace_id} mono /><Typography variant="h3" sx={{ mt: 3, mb: 1 }}>Attributes</Typography><CodeBlock value={selected?.attributes} /></DetailDrawer></>
}

function LogLevel({ level }: { level: string }) {
  const color = level === 'ERROR' ? 'error' : level === 'WARN' ? 'warning' : level === 'INFO' ? 'primary' : 'default'
  return <Chip size="small" label={level} color={color} variant="outlined" />
}

function KeyValue({ label, value, mono = false }: { label: string; value?: string; mono?: boolean }) {
  return <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ py: 1.2, borderBottom: '1px solid', borderColor: 'divider' }}><Typography color="text.secondary" sx={{ width: 120, flex: '0 0 auto' }}>{label}</Typography><Typography className={mono ? 'mono' : undefined} sx={{ overflowWrap: 'anywhere' }}>{value || '—'}</Typography></Stack>
}

function CodeBlock({ value }: { value: unknown }) {
  return <Box component="pre" className="mono" sx={{ m: 0, p: 2, bgcolor: '#101828', color: '#d0d5dd', borderRadius: 1.5, overflowX: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12.5 }}>{JSON.stringify(value ?? {}, null, 2)}</Box>
}
