import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, expect, test, vi } from 'vitest'
import { LogsPage } from './OperationsPages'

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

test('a trace handed over from the audit screen seeds the search', async () => {
  renderLogs('/admin/logs?trace=handed-over-trace')
  await waitFor(() => {
    expect(mocks.api.mock.calls.some(([path]) => String(path).includes('q=handed-over-trace'))).toBe(true)
  })
  expect(screen.getByLabelText('로그 검색')).toHaveValue('handed-over-trace')
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
