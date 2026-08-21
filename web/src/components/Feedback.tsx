import ErrorOutlineRoundedIcon from '@mui/icons-material/ErrorOutlineRounded'
import InboxRoundedIcon from '@mui/icons-material/InboxRounded'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import { Alert, AlertTitle, Box, Button, CircularProgress, Stack, Typography } from '@mui/material'
import { APIError } from '../lib/api'
import { CopyButton } from './CopyField'

export function PageLoading({ label = '불러오는 중' }: { label?: string }) {
  return (
    <Stack alignItems="center" justifyContent="center" spacing={1.5} sx={{ minHeight: 260 }} role="status">
      <CircularProgress size={30} />
      <Typography color="text.secondary">{label}</Typography>
    </Stack>
  )
}

/**
 * What went wrong and what to do about it.
 *
 * The alert used to show the raw message and a trace identifier. That leaves
 * an operator with no next step for the failures they actually hit — an
 * unreachable service during a restart, a permission they do not have, or a
 * record someone else changed first — so each of those now carries its own
 * guidance, and the trace identifier can be copied for a support request.
 */
export function ErrorAlert({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const apiError = error instanceof APIError ? error : undefined
  const message = error instanceof Error ? error.message : '데이터를 불러오지 못했습니다.'
  const guidance = guidanceFor(apiError)
  const retryable = onRetry && isRetryable(apiError)
  return (
    <Alert
      severity={apiError?.status === 403 ? 'warning' : 'error'}
      icon={<ErrorOutlineRoundedIcon />}
      action={retryable ? <Button color="inherit" size="small" startIcon={<RefreshRoundedIcon />} onClick={onRetry}>다시 시도</Button> : undefined}
    >
      <AlertTitle sx={{ mb: guidance || apiError?.traceId ? .5 : 0 }}>{message}</AlertTitle>
      {guidance && <Typography variant="body2">{guidance}</Typography>}
      {apiError?.traceId && (
        <Stack direction="row" alignItems="center" spacing={.4} sx={{ mt: .5 }}>
          <Typography component="span" className="mono" sx={{ fontSize: 12 }}>trace: {apiError.traceId}</Typography>
          <CopyButton value={apiError.traceId} label="Trace ID 복사" />
        </Stack>
      )}
    </Alert>
  )
}

function guidanceFor(error?: APIError): string {
  if (!error) return ''
  if (error.status === 0) return '서비스가 재시작 중이거나 네트워크가 끊겼을 수 있습니다.'
  if (error.status === 403) return '필요한 권한이 없습니다. 서비스 관리자에게 권한을 요청하세요.'
  if (error.status === 404) return '이미 삭제되었거나 접근할 수 없는 항목입니다. 목록을 새로 고쳐 확인하세요.'
  if (error.status === 409) return '다른 곳에서 먼저 변경되었습니다. 최신 상태를 불러온 뒤 다시 시도하세요.'
  if (error.status === 429) return '요청이 제한되었습니다. 잠시 기다린 뒤 다시 시도하세요.'
  if (error.status >= 500) return '서버가 요청을 처리하지 못했습니다. 잠시 후 다시 시도하고, 계속되면 아래 Trace ID와 함께 문의하세요.'
  return ''
}

// Retrying only helps where the cause can clear on its own.
function isRetryable(error?: APIError): boolean {
  if (!error) return true
  return error.status === 0 || error.status === 429 || error.status >= 500
}

export function EmptyState({ title, description }: { title: string; description?: string }) {
  return (
    <Box sx={{ py: 8, px: 3, textAlign: 'center', color: 'text.secondary' }}>
      <InboxRoundedIcon sx={{ fontSize: 42, color: '#98a2b3', mb: 1 }} />
      <Typography variant="h3" color="text.primary">{title}</Typography>
      {description && <Typography variant="body2" sx={{ mt: .75 }}>{description}</Typography>}
    </Box>
  )
}
