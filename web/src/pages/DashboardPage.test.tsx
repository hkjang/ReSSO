import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, expect, test, vi } from 'vitest'
import { DashboardPage } from './DashboardPage'

const mocks = vi.hoisted(() => ({ api: vi.fn() }))

vi.mock('../lib/api', () => ({ api: (...args: unknown[]) => mocks.api(...args) }))

const dashboard = (readiness: Record<string, unknown>) => ({
  realms: 1, users: 4, clients: 2, active_sessions: 1, pending_approvals: 0,
  readiness: {
    issuer_https: true, signing_keys_ready: true, federation_failures: 0,
    locked_users: 0, expiring_api_keys: 0, aging_signing_keys: 0,
    signing_key_advisory_days: 180, clock_skew_seconds: 0,
    clock_skew_round_trip_ms: 3, clock_skew_advisory_seconds: 30,
    ...readiness,
  },
})

beforeEach(() => {
  mocks.api.mockReset()
})

function renderDashboard() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <MemoryRouter><DashboardPage /></MemoryRouter>
  </QueryClientProvider>)
}

// Every readiness row that names a problem offers the screen that can fix it.
// The two below are the ones that used to point somewhere that could not.
test('the locked accounts and expiring keys link to screens that show them', async () => {
  mocks.api.mockResolvedValue(dashboard({ locked_users: 3, expiring_api_keys: 2 }))
  renderDashboard()

  expect(await screen.findByRole('link', { name: /잠긴 사용자 보기/ }))
    .toHaveAttribute('href', '/admin/users?status=locked')
  expect(screen.getByRole('link', { name: /만료 예정 키 보기/ }))
    .toHaveAttribute('href', '/admin/api-keys?expiring=true')
})

// The clock difference is settled on the hosts, not in the console. It used to
// offer "시각 동기화 확인" pointing at the audit log, which cannot check time
// synchronisation: a button that looks like the others and leads somewhere that
// does not help is worse than no button.
test('the clock difference says what to do rather than offering a screen', async () => {
  mocks.api.mockResolvedValue(dashboard({ clock_skew_seconds: 92.4 }))
  renderDashboard()

  expect(await screen.findByText(/92\.4초/)).toBeInTheDocument()
  expect(screen.getByText('두 호스트가 같은 시각 소스를 쓰도록 맞추세요')).toBeInTheDocument()
  expect(screen.queryByRole('link', { name: /시각 동기화/ })).not.toBeInTheDocument()
  expect(screen.queryByText('시각 동기화 확인')).not.toBeInTheDocument()
})

// A row that is fine offers nothing at all: the console does not send anyone to
// a screen for something that is not a problem.
test('a healthy row offers neither a link nor advice', async () => {
  mocks.api.mockResolvedValue(dashboard({}))
  renderDashboard()

  expect(await screen.findByText('서버·데이터베이스 시각 차이')).toBeInTheDocument()
  expect(screen.queryByText('두 호스트가 같은 시각 소스를 쓰도록 맞추세요')).not.toBeInTheDocument()
  expect(screen.queryByRole('link', { name: /잠긴 사용자 보기/ })).not.toBeInTheDocument()
})
