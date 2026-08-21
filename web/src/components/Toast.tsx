import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { Alert, Snackbar } from '@mui/material'
import { ToastContext, type ToastSeverity } from './toast-context'

interface ToastMessage {
  key: number
  text: string
  severity: ToastSeverity
}

/**
 * Transient confirmation for actions that already changed something on screen.
 *
 * Pages previously kept a persistent `<Alert>` for every success, so "저장했습니다"
 * stayed visible while the user carried on editing and eventually stopped
 * meaning anything. A toast disappears on its own and keeps confirmations in
 * one predictable place.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState<ToastMessage | null>(null)
  const notify = useCallback((text: string, severity: ToastSeverity = 'success') => {
    setMessage({ key: Date.now(), text, severity })
  }, [])
  const value = useMemo(() => ({ notify }), [notify])
  return (
    <ToastContext.Provider value={value}>
      {children}
      <Snackbar
        key={message?.key}
        open={Boolean(message)}
        autoHideDuration={message?.severity === 'error' ? 8000 : 4000}
        onClose={(_, reason) => { if (reason !== 'clickaway') setMessage(null) }}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity={message?.severity ?? 'success'} variant="filled" onClose={() => setMessage(null)} sx={{ boxShadow: 3 }}>
          {message?.text}
        </Alert>
      </Snackbar>
    </ToastContext.Provider>
  )
}
