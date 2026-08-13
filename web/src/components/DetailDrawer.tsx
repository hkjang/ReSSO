import CloseRoundedIcon from '@mui/icons-material/CloseRounded'
import { Box, Divider, Drawer, IconButton, Stack, Typography } from '@mui/material'
import type { ReactNode } from 'react'

export function DetailDrawer({ open, title, subtitle, onClose, children, width = 560 }: {
  open: boolean
  title: string
  subtitle?: string
  onClose: () => void
  children: ReactNode
  width?: number
}) {
  return (
    <Drawer anchor="right" open={open} onClose={onClose} PaperProps={{ sx: { width: { xs: '100%', sm: width }, maxWidth: '100vw', height: '100%', overflow: 'hidden' } }}>
      <Stack direction="row" alignItems="flex-start" justifyContent="space-between" sx={{ p: 2.5, flex: '0 0 auto' }}>
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="h2" component="h2" noWrap>{title}</Typography>
          {subtitle && <Typography color="text.secondary" variant="body2" sx={{ mt: .5 }}>{subtitle}</Typography>}
        </Box>
        <IconButton onClick={onClose} aria-label="상세 패널 닫기"><CloseRoundedIcon /></IconButton>
      </Stack>
      <Divider />
      <Box sx={{ flex: '1 1 auto', minHeight: 0, overflowY: 'auto', overscrollBehavior: 'contain', p: 2.5 }}>
        {children}
      </Box>
    </Drawer>
  )
}
