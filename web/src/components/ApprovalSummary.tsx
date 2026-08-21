import { Chip, Stack, Typography } from '@mui/material'
import type { ApprovalRequest } from '../types'

/**
 * What approving this request would actually do.
 *
 * The reviewer used to see only the request kind, so granting a role meant
 * agreeing to "ROLE_ASSIGNMENT" without being told which role.
 */
export function ApprovalTarget({ request }: { request: ApprovalRequest }) {
  if (request.kind === 'ROLE_ASSIGNMENT') {
    if (!request.target_role_name) {
      return <Typography variant="body2" color="warning.main">요청한 Role을 찾을 수 없습니다 (삭제되었을 수 있음)</Typography>
    }
    return <Chip size="small" className="mono" label={request.target_role_name} color="primary" variant="outlined" />
  }
  return <Typography variant="body2" color="text.secondary">—</Typography>
}

/** The requester, by name rather than by identifier. */
export function ApprovalRequester({ request }: { request: ApprovalRequest }) {
  if (!request.requester_username) {
    return <Typography variant="body2" color="text.secondary">삭제된 사용자</Typography>
  }
  return (
    <Stack>
      <Typography variant="body2" fontWeight={650}>{request.requester_display_name || request.requester_username}</Typography>
      <Typography variant="caption" color="text.secondary" className="mono">{request.requester_username}</Typography>
    </Stack>
  )
}
