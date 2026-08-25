import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, expect, test, vi } from 'vitest'
import { ApprovalsPage } from './ApprovalsPage'

const mocks = vi.hoisted(() => ({ api: vi.fn() }))

vi.mock('../lib/api', () => ({
  api: (...args: unknown[]) => mocks.api(...args),
  jsonBody: (value: unknown) => ({ body: JSON.stringify(value) }),
}))

const request = {
  id: '00000000-0000-0000-0000-0000000000aa',
  realm_id: '00000000-0000-0000-0000-0000000000bb',
  requester_id: '00000000-0000-0000-0000-0000000000cc',
  kind: 'ROLE_ASSIGNMENT',
  payload: { role_id: '00000000-0000-0000-0000-0000000000dd' },
  reason: '야간 출고 담당',
  status: 'PENDING',
  decision_note: '',
  created_at: '2026-08-21T00:00:00Z',
  realm_name: 'master',
  requester_username: 'requester',
  requester_display_name: 'Req Uester',
  reviewer_username: 'team-lead',
  target_role_name: 'warehouse-operator',
}

beforeEach(() => {
  mocks.api.mockReset()
  mocks.api.mockResolvedValue({ items: [request] })
})

function renderApprovals() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}><MemoryRouter><ApprovalsPage /></MemoryRouter></QueryClientProvider>)
}

test('the queue names the requester and the role instead of identifiers', async () => {
  renderApprovals()
  // A reviewer used to see a truncated UUID and the word ROLE_ASSIGNMENT.
  expect(await screen.findByText('Req Uester')).toBeInTheDocument()
  expect(screen.getByText('requester')).toBeInTheDocument()
  expect(screen.getByText('warehouse-operator')).toBeInTheDocument()
  expect(screen.getByText('Role 할당')).toBeInTheDocument()
  expect(screen.queryByText('ROLE_ASSIGNMENT')).not.toBeInTheDocument()
})

test('the approval dialog states exactly what approving grants', async () => {
  const user = userEvent.setup()
  renderApprovals()
  await user.click(await screen.findByRole('button', { name: '승인' }))

  const dialog = await screen.findByRole('dialog')
  expect(dialog).toHaveTextContent('Req Uester')
  expect(dialog).toHaveTextContent('warehouse-operator')
  expect(dialog).toHaveTextContent(/즉시 부여됩니다/)
  expect(dialog).toHaveTextContent('야간 출고 담당')
})

test('a request whose role no longer exists is flagged rather than shown blank', async () => {
  mocks.api.mockResolvedValue({ items: [{ ...request, target_role_name: '' }] })
  renderApprovals()
  expect(await screen.findByText(/요청한 Role을 찾을 수 없습니다/)).toBeInTheDocument()
})

// The listing is capped at 500 and waiting requests come first, so what it
// drops is the oldest decided ones. A cut list that says nothing looks like the
// whole history. The decisions it cannot show are in the audit trail, which
// keeps a year of them — and the link has to arrive there already narrowed to
// approval decisions, or the reader is left to find them again.
test('a listing that hits the cap says so and points at the decisions it dropped', async () => {
  mocks.api.mockResolvedValue({ items: [{ ...request, status: 'APPROVED' }], truncated: true })
  renderApprovals()

  expect(await screen.findByText(/500건만 표시합니다/)).toBeInTheDocument()
  expect(screen.getByRole('link', { name: '감사 이벤트에서 보기' }))
    .toHaveAttribute('href', '/admin/audit?event_type=APPROVAL_DECISION')
})

test('a listing that fits says nothing about a cap', async () => {
  mocks.api.mockResolvedValue({ items: [request], truncated: false })
  renderApprovals()

  expect(await screen.findByText('Role 할당')).toBeInTheDocument()
  expect(screen.queryByText(/500건만 표시합니다/)).not.toBeInTheDocument()
})
