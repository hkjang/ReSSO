import { useState } from 'react'
import CheckRoundedIcon from '@mui/icons-material/CheckRounded'
import ContentCopyRoundedIcon from '@mui/icons-material/ContentCopyRounded'
import { IconButton, Tooltip } from '@mui/material'
import { copyText } from '../lib/clipboard'
import { useToast } from './toast-context'

/**
 * Copy button for identifiers and secrets.
 *
 * Administrators copy Realm, user and client identifiers constantly, and a
 * one-time secret is unrecoverable if the copy silently fails — which is what
 * happened on the plain-HTTP origins ReSSO usually runs on. This reports the
 * outcome either way.
 */
export function CopyButton({ value, label = '복사', size = 'small' }: {
  value?: string
  label?: string
  size?: 'small' | 'medium'
}) {
  const { notify } = useToast()
  const [copied, setCopied] = useState(false)
  if (!value) return null
  const copy = async () => {
    if (await copyText(value)) {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
      notify('클립보드에 복사했습니다.')
      return
    }
    notify('클립보드에 복사하지 못했습니다. 값을 직접 선택해 복사하세요.', 'warning')
  }
  return (
    <Tooltip title={copied ? '복사함' : label}>
      <IconButton size={size} onClick={(event) => { event.stopPropagation(); void copy() }} aria-label={label}>
        {copied ? <CheckRoundedIcon fontSize="inherit" color="success" /> : <ContentCopyRoundedIcon fontSize="inherit" />}
      </IconButton>
    </Tooltip>
  )
}
