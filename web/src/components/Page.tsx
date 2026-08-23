import type { ReactNode } from 'react'
import { Box, Button, Chip, Stack, Typography } from '@mui/material'
import AddRoundedIcon from '@mui/icons-material/AddRounded'
import { useDocumentTitle } from '../lib/documentTitle'

export function PageHeader({ title, description, action, badge }: {
  title: string
  description?: string
  action?: { label: string; onClick: () => void }
  badge?: string
}) {
  useDocumentTitle(title)
  return (
    <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ xs: 'stretch', sm: 'flex-start' }} spacing={2} sx={{ mb: 3 }}>
      <Box>
        <Stack direction="row" spacing={1} alignItems="center">
          <Typography component="h1" variant="h1">{title}</Typography>
          {badge && <Chip size="small" label={badge} color="primary" variant="outlined" />}
        </Stack>
        {description && <Typography color="text.secondary" sx={{ mt: .6, maxWidth: 760 }}>{description}</Typography>}
      </Box>
      {action && <Button startIcon={<AddRoundedIcon />} variant="contained" onClick={action.onClick}>{action.label}</Button>}
    </Stack>
  )
}

export function ContentCard({ children, noPadding = false }: { children: ReactNode; noPadding?: boolean }) {
  return (
    <Box sx={{ bgcolor: 'background.paper', border: '1px solid', borderColor: 'divider', borderRadius: 2, overflow: 'hidden', p: noPadding ? 0 : { xs: 2, md: 3 } }}>
      {children}
    </Box>
  )
}

export function StatusChip({ active, activeLabel = '활성', inactiveLabel = '비활성' }: { active: boolean; activeLabel?: string; inactiveLabel?: string }) {
  return <Chip size="small" label={active ? activeLabel : inactiveLabel} color={active ? 'success' : 'default'} variant={active ? 'filled' : 'outlined'} />
}
