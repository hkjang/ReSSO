import { useCallback, useEffect, useRef, useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import LockPersonRoundedIcon from '@mui/icons-material/LockPersonRounded'
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, Stack, TextField } from '@mui/material'
import { api } from '../lib/api'
import { setReauthenticationPrompt } from '../lib/reauthentication'
import { ErrorAlert } from './Feedback'

/**
 * Asks for the password when a protected action needs one, and gets out of the
 * way.
 *
 * Mounted once, above the routes. The API layer raises the question and
 * repeats the request afterwards, so this knows nothing about which action was
 * interrupted and no screen has to be written twice — once for the ordinary
 * path and once for the interrupted one.
 *
 * Cancelling resolves false rather than leaving the caller waiting: the action
 * then fails the way any refused action does, with the message the server
 * gave, which is what the operator needs to see if they meant to cancel.
 */
export function ReauthenticationGate({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const [password, setPassword] = useState('')
  const [error, setError] = useState<unknown>(null)
  const [checking, setChecking] = useState(false)
  const settle = useRef<((confirmed: boolean) => void) | null>(null)

  const finish = useCallback((confirmed: boolean) => {
    setOpen(false)
    setPassword('')
    setError(null)
    setChecking(false)
    const resolve = settle.current
    settle.current = null
    resolve?.(confirmed)
  }, [])

  useEffect(() => {
    setReauthenticationPrompt(() => new Promise<boolean>((resolve) => {
      settle.current = resolve
      setOpen(true)
    }))
    return () => {
      setReauthenticationPrompt(null)
      // Unmounting with a question outstanding would leave whatever asked it
      // waiting on a promise nothing will ever settle.
      settle.current?.(false)
      settle.current = null
    }
  }, [])

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setChecking(true)
    setError(null)
    try {
      await api('/api/v1/auth/reauthenticate', { method: 'POST', body: JSON.stringify({ password }) })
      finish(true)
    } catch (failure) {
      // Left open on a wrong password: closing would fail the action the
      // operator is in the middle of because they mistyped.
      setError(failure)
      setChecking(false)
      setPassword('')
    }
  }

  return (
    <>
      {children}
      <Dialog open={open} onClose={() => finish(false)} maxWidth="xs" fullWidth>
        <Stack component="form" onSubmit={submit}>
          <DialogTitle>비밀번호를 다시 확인합니다</DialogTitle>
          <DialogContent>
            <Stack spacing={2}>
              <DialogContentText>
                방금 요청한 작업은 접근 권한을 내주는 작업이라, 브라우저 세션만으로는 진행하지 않습니다.
                비밀번호를 확인하면 <strong>요청한 작업이 그대로 이어집니다.</strong> 이후 5분 동안은 다시 묻지 않습니다.
              </DialogContentText>
              {error ? <ErrorAlert error={error} /> : null}
              <TextField
                autoFocus type="password" label="비밀번호" value={password} autoComplete="current-password"
                onChange={(event) => setPassword(event.target.value)}
                InputProps={{ startAdornment: <LockPersonRoundedIcon sx={{ mr: 1, color: 'text.secondary' }} /> }}
              />
            </Stack>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => finish(false)}>취소</Button>
            <Button type="submit" variant="contained" disabled={!password || checking}>
              {checking ? '확인하는 중…' : '확인하고 계속'}
            </Button>
          </DialogActions>
        </Stack>
      </Dialog>
    </>
  )
}
