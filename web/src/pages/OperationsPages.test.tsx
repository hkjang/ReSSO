import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, expect, test, vi } from 'vitest'
import { AuditPage, LogsPage } from './OperationsPages'

const mocks = vi.hoisted(() => ({ api: vi.fn() }))

vi.mock('../lib/api', () => ({ api: (...args: unknown[]) => mocks.api(...args) }))

beforeEach(() => {
  mocks.api.mockReset()
  mocks.api.mockResolvedValue({ items: [] })
})

function renderLogs(entry = '/admin/logs') {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={[entry]}><LogsPage /></MemoryRouter></QueryClientProvider>)
}

test('typing a trace identifier issues one request, not one per keystroke', async () => {
  const user = userEvent.setup()
  renderLogs()
  await waitFor(() => expect(mocks.api).toHaveBeenCalled())
  const before = mocks.api.mock.calls.length

  await user.type(screen.getByLabelText('로그 검색'), 'abcdef123456')
  // The search is debounced; without it each of the twelve characters was a
  // separate request.
  await waitFor(() => {
    const queried = mocks.api.mock.calls.filter(([path]) => String(path).includes('q=abcdef123456'))
    expect(queried.length).toBeGreaterThan(0)
  })
  const issued = mocks.api.mock.calls.length - before
  expect(issued).toBeLessThan(5)
})

// A trace is an exact identifier. Sent as free text it becomes a leading
// wildcard over a mirror holding thirty days of every request — a full scan for
// something one index lookup answers — and it also matches lines that merely
// mention the identifier rather than carrying it.
test('a trace handed over from the audit screen is looked up as a trace, not searched as text', async () => {
  renderLogs('/admin/logs?trace=handed-over-trace')
  await waitFor(() => {
    expect(mocks.api.mock.calls.some(([path]) => String(path).includes('trace=handed-over-trace'))).toBe(true)
  })
  expect(mocks.api.mock.calls.every(([path]) => !String(path).includes('q=handed-over-trace'))).toBe(true)
  expect(screen.getByLabelText('로그 검색')).toHaveValue('handed-over-trace')
})

// Once the term is edited it is no longer the trace that was handed over, and
// the free-text search is what the person is asking for.
test('editing the handed-over trace goes back to searching text', async () => {
  const user = userEvent.setup()
  renderLogs('/admin/logs?trace=handed-over-trace')
  await waitFor(() => expect(mocks.api).toHaveBeenCalled())

  const field = screen.getByLabelText('로그 검색')
  await user.clear(field)
  await user.type(field, 'refused')

  await waitFor(() => {
    expect(mocks.api.mock.calls.some(([path]) => String(path).includes('q=refused'))).toBe(true)
  })
})

// A table with no accessible name is announced as just "table". The console
// puts several on a page — audit events beside server logs, API keys beside
// sessions — so someone navigating by table had a list of anonymous ones to
// guess between. MUI adds no name of its own; it has to be given.
test('the log table says what it lists', async () => {
  mocks.api.mockResolvedValue({ items: [{ id: 1, occurred_at: '2026-01-01T00:00:00Z', level: 'INFO',
    component: 'resso', message: 'started', trace_id: '', attributes: {} }] })
  renderLogs()
  const table = await screen.findByRole('table', { name: '서버 로그 목록' })
  expect(table).toBeInTheDocument()
})

// Another screen links here to show the approval decisions its own listing had
// to cut. A link that arrives unfiltered leaves the reader to find them again,
// so the event type is read from the URL rather than kept as local state.
test('the audit screen opens on the event type a link names', async () => {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={queryClient}>
    <MemoryRouter initialEntries={['/admin/audit?event_type=APPROVAL_DECISION']}><AuditPage /></MemoryRouter>
  </QueryClientProvider>)

  await waitFor(() => {
    const asked = mocks.api.mock.calls.map(([path]) => String(path))
    expect(asked.some((path) => path.includes('/audit?') && path.includes('event_type=APPROVAL_DECISION'))).toBe(true)
  })
})
