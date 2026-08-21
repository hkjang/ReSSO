import { useState } from 'react'
import { Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, jsonBody } from '../lib/api'
import type { ApprovalRequest } from '../types'
import { formatDate, shortId } from '../lib/format'
import { ContentCard, PageHeader } from '../components/Page'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'
import { ApprovalRequester, ApprovalTarget } from '../components/ApprovalSummary'
import { approvalKindLabel } from '../lib/approvals'

export function ApprovalsPage() {
  const queryClient = useQueryClient()
  const [target, setTarget] = useState<ApprovalRequest | null>(null)
  const [decision, setDecision] = useState<'approve' | 'reject'>('approve')
  const [note, setNote] = useState('')
  const requests = useQuery({ queryKey: ['approvals'], queryFn: () => api<{ items: ApprovalRequest[] }>('/api/admin/v1/approvals'), refetchInterval: 20_000 })
  const decide = useMutation({ mutationFn: () => api<ApprovalRequest>(`/api/admin/v1/approvals/${target!.id}/decision`, { method: 'POST', ...jsonBody({ decision, note }) }), onSuccess: async () => { setTarget(null); setNote(''); await queryClient.invalidateQueries({ queryKey: ['approvals'] }) } })
  if (requests.isLoading) return <PageLoading />
  if (requests.error) return <ErrorAlert error={requests.error} />
  return <><PageHeader title="검토 · 승인" description="승인 프로세스를 활성화한 Realm의 접근 요청을 검토합니다." badge={`${requests.data?.items.filter((item) => item.status === 'PENDING').length ?? 0} 대기`} /><Alert severity="info" sx={{ mb: 2 }}>Realm 설정에서 승인 프로세스를 끄면 관련 사용자 메뉴와 이 탐색 메뉴가 자동으로 제외됩니다.</Alert><ContentCard noPadding>{!requests.data?.items.length ? <EmptyState title="승인 요청이 없습니다" /> : <TableContainer><Table><TableHead><TableRow><TableCell>요청</TableCell><TableCell>요청자</TableCell><TableCell>부여 대상</TableCell><TableCell>사유</TableCell><TableCell>상태</TableCell><TableCell>요청일</TableCell><TableCell align="right">작업</TableCell></TableRow></TableHead><TableBody>{requests.data.items.map((request) => <TableRow key={request.id}><TableCell><Typography fontWeight={650}>{approvalKindLabel(request.kind)}</Typography><Typography variant="caption" color="text.secondary">{request.realm_name}</Typography></TableCell><TableCell><ApprovalRequester request={request} /></TableCell><TableCell><ApprovalTarget request={request} /></TableCell><TableCell sx={{ maxWidth: 320 }}>{request.reason || '—'}</TableCell><TableCell><Chip size="small" label={request.status} color={request.status === 'PENDING' ? 'warning' : request.status === 'APPROVED' ? 'success' : 'default'} /></TableCell><TableCell>{formatDate(request.created_at)}</TableCell><TableCell align="right">{request.status === 'PENDING' && <Stack direction="row" justifyContent="flex-end" spacing={1}><Button size="small" onClick={() => { setTarget(request); setDecision('reject') }}>반려</Button><Button size="small" variant="contained" onClick={() => { setTarget(request); setDecision('approve') }}>승인</Button></Stack>}</TableCell></TableRow>)}</TableBody></Table></TableContainer>}</ContentCard><Dialog open={Boolean(target)} onClose={() => setTarget(null)} maxWidth="sm"><DialogTitle>{decision === 'approve' ? '요청 승인' : '요청 반려'}</DialogTitle><DialogContent>{target && <Stack spacing={1.2} sx={{ mb: 2.5 }}>
        <Alert severity={decision === 'approve' ? 'warning' : 'info'}>
          {decision === 'approve'
            ? <>승인하면 <strong>{target.requester_display_name || target.requester_username}</strong> 계정에 {target.kind === 'ROLE_ASSIGNMENT' ? <>Role <strong className="mono">{target.target_role_name || '(확인 불가)'}</strong>이(가)</> : <>요청한 권한이</>} 즉시 부여됩니다.</>
            : <>반려하면 요청은 종료되고 권한은 부여되지 않습니다.</>}
        </Alert>
        <DecisionRow label="Realm" value={target.realm_name} />
        <DecisionRow label="요청자" value={`${target.requester_display_name || target.requester_username} (${target.requester_username || '삭제된 사용자'})`} />
        <DecisionRow label="요청 사유" value={target.reason || '—'} />
        <DecisionRow label="요청일" value={formatDate(target.created_at)} />
        <DecisionRow label="요청 ID" value={shortId(target.id)} mono />
      </Stack>}<TextField label="검토 의견" multiline minRows={3} value={note} onChange={(e) => setNote(e.target.value)} helperText="결정 근거는 감사 이벤트에 함께 기록됩니다." />{decide.error && <Box sx={{ mt: 2 }}><ErrorAlert error={decide.error} /></Box>}</DialogContent><DialogActions><Button onClick={() => setTarget(null)}>취소</Button><Button color={decision === 'approve' ? 'primary' : 'error'} variant="contained" onClick={() => decide.mutate()} disabled={decide.isPending}>{decision === 'approve' ? '승인' : '반려'}</Button></DialogActions></Dialog></>
}

function DecisionRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <Stack direction="row" spacing={1.5}><Typography variant="body2" color="text.secondary" sx={{ width: 76, flex: '0 0 auto' }}>{label}</Typography><Typography variant="body2" className={mono ? 'mono' : undefined} sx={{ overflowWrap: 'anywhere' }}>{value}</Typography></Stack>
}
