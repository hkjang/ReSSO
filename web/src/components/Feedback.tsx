import ErrorOutlineRoundedIcon from '@mui/icons-material/ErrorOutlineRounded'
import InboxRoundedIcon from '@mui/icons-material/InboxRounded'
import { Alert, Box, CircularProgress, Stack, Typography } from '@mui/material'
import { APIError } from '../lib/api'

export function PageLoading({ label = '불러오는 중' }: { label?: string }) {
  return (
    <Stack alignItems="center" justifyContent="center" spacing={1.5} sx={{ minHeight: 260 }} role="status">
      <CircularProgress size={30} />
      <Typography color="text.secondary">{label}</Typography>
    </Stack>
  )
}

export function ErrorAlert({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : '데이터를 불러오지 못했습니다.'
  const trace = error instanceof APIError ? error.traceId : undefined
  return (
    <Alert severity="error" icon={<ErrorOutlineRoundedIcon />}>
      {message}{trace && <Typography component="span" className="mono" sx={{ ml: 1, fontSize: 12 }}>trace: {trace}</Typography>}
    </Alert>
  )
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
