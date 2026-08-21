import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { ErrorAlert } from './Feedback'
import { APIError } from '../lib/api'

test('an unreachable service explains itself in the operator\'s language', () => {
  // fetch rejects with "Failed to fetch"; the API layer replaces it.
  render(<ErrorAlert error={new APIError(0, 'network_unreachable', '서버에 연결하지 못했습니다. 네트워크와 ReSSO 서비스 상태를 확인한 뒤 다시 시도하세요.')} />)
  expect(screen.getByText(/서버에 연결하지 못했습니다/)).toBeInTheDocument()
  expect(screen.getByText(/서비스가 재시작 중이거나/)).toBeInTheDocument()
})

test('failures that can clear on their own offer a retry', async () => {
  const user = userEvent.setup()
  const onRetry = vi.fn()
  render(<ErrorAlert error={new APIError(503, 'unavailable', '요청을 처리하지 못했습니다.', 'trace-1')} onRetry={onRetry} />)
  await user.click(screen.getByRole('button', { name: /다시 시도/ }))
  expect(onRetry).toHaveBeenCalledOnce()
  expect(screen.getByText(/trace: trace-1/)).toBeInTheDocument()
})

test('a permission failure guides instead of inviting a pointless retry', () => {
  render(<ErrorAlert error={new APIError(403, 'insufficient_permission', '관리자 권한이 필요합니다.')} onRetry={vi.fn()} />)
  expect(screen.getByText(/필요한 권한이 없습니다/)).toBeInTheDocument()
  // Retrying the same request would fail identically.
  expect(screen.queryByRole('button', { name: /다시 시도/ })).not.toBeInTheDocument()
})

test('a conflict tells the user to reload first', () => {
  render(<ErrorAlert error={new APIError(409, 'conflict', '동일한 항목이 이미 존재합니다.')} onRetry={vi.fn()} />)
  expect(screen.getByText(/다른 곳에서 먼저 변경되었습니다/)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /다시 시도/ })).not.toBeInTheDocument()
})
