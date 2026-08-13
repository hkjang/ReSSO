import { useState } from 'react'
import { Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, jsonBody } from '../lib/api'
import type { ApprovalRequest } from '../types'
import { formatDate, shortId } from '../lib/format'
import { ContentCard, PageHeader } from '../components/Page'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'

export function ApprovalsPage() {
  const queryClient = useQueryClient()
  const [target, setTarget] = useState<ApprovalRequest | null>(null)
  const [decision, setDecision] = useState<'approve' | 'reject'>('approve')
  const [note, setNote] = useState('')
  const requests = useQuery({ queryKey: ['approvals'], queryFn: () => api<{ items: ApprovalRequest[] }>('/api/admin/v1/approvals'), refetchInterval: 20_000 })
  const decide = useMutation({ mutationFn: () => api<ApprovalRequest>(`/api/admin/v1/approvals/${target!.id}/decision`, { method: 'POST', ...jsonBody({ decision, note }) }), onSuccess: async () => { setTarget(null); setNote(''); await queryClient.invalidateQueries({ queryKey: ['approvals'] }) } })
  if (requests.isLoading) return <PageLoading />
  if (requests.error) return <ErrorAlert error={requests.error} />
  return <><PageHeader title="검토 · 승인" description="승인 프로세스를 활성화한 Realm의 접근 요청을 검토합니다." badge={`${requests.data?.items.filter((item) => item.status === 'PENDING').length ?? 0} 대기`} /><Alert severity="info" sx={{ mb: 2 }}>Realm 설정에서 승인 프로세스를 끄면 관련 사용자 메뉴와 이 탐색 메뉴가 자동으로 제외됩니다.</Alert><ContentCard noPadding>{!requests.data?.items.length ? <EmptyState title="승인 요청이 없습니다" /> : <TableContainer><Table><TableHead><TableRow><TableCell>요청</TableCell><TableCell>요청자</TableCell><TableCell>사유</TableCell><TableCell>상태</TableCell><TableCell>요청일</TableCell><TableCell align="right">작업</TableCell></TableRow></TableHead><TableBody>{requests.data.items.map((request) => <TableRow key={request.id}><TableCell><Typography fontWeight={650}>{request.kind}</Typography><Typography variant="caption" className="mono">{shortId(request.id)}</Typography></TableCell><TableCell className="mono">{shortId(request.requester_id)}</TableCell><TableCell>{request.reason || '—'}</TableCell><TableCell><Chip size="small" label={request.status} color={request.status === 'PENDING' ? 'warning' : request.status === 'APPROVED' ? 'success' : 'default'} /></TableCell><TableCell>{formatDate(request.created_at)}</TableCell><TableCell align="right">{request.status === 'PENDING' && <Stack direction="row" justifyContent="flex-end" spacing={1}><Button size="small" onClick={() => { setTarget(request); setDecision('reject') }}>반려</Button><Button size="small" variant="contained" onClick={() => { setTarget(request); setDecision('approve') }}>승인</Button></Stack>}</TableCell></TableRow>)}</TableBody></Table></TableContainer>}</ContentCard><Dialog open={Boolean(target)} onClose={() => setTarget(null)} maxWidth="sm"><DialogTitle>{decision === 'approve' ? '요청 승인' : '요청 반려'}</DialogTitle><DialogContent><Typography sx={{ mb: 2 }}>요청 {target && shortId(target.id)}에 결정을 기록합니다.</Typography><TextField label="검토 의견" multiline minRows={3} value={note} onChange={(e) => setNote(e.target.value)} />{decide.error && <Box sx={{ mt: 2 }}><ErrorAlert error={decide.error} /></Box>}</DialogContent><DialogActions><Button onClick={() => setTarget(null)}>취소</Button><Button color={decision === 'approve' ? 'primary' : 'error'} variant="contained" onClick={() => decide.mutate()} disabled={decide.isPending}>{decision === 'approve' ? '승인' : '반려'}</Button></DialogActions></Dialog></>
}
