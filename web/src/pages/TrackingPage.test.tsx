import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, expect, test, vi } from 'vitest'
import { TrackingPage } from './TrackingPage'

const mocks = vi.hoisted(() => ({ api: vi.fn() }))
vi.mock('../lib/api', () => ({
  api: (...args: unknown[]) => mocks.api(...args),
  jsonBody: (value: unknown) => ({ body: JSON.stringify(value) }),
}))

const off = {
  enabled: false, provider: 'none', momento_url: '', momento_site_id: '', momento_proxy: true,
  measurement_id: '', matomo_url: '', matomo_site_id: '', custom_snippet: '', allowed_hosts: '',
  include_admin: false, placement: 'head',
}
const basePolicy = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

beforeEach(() => {
  // The stand-in server remembers what was saved, as the real one does.
  let current = { config: off, policy: basePolicy, proxy_path: '/momento' }
  mocks.api.mockReset()
  mocks.api.mockImplementation((path: string, init?: RequestInit) => {
    if (path === '/api/admin/v1/tracking' && init?.method === 'PUT') {
      const config = JSON.parse(String(init.body))
      current = { config, policy: "default-src 'self'; script-src 'self' 'nonce-…'; report-uri /api/v1/tracking/csp-report", proxy_path: '/momento' }
      return Promise.resolve(current)
    }
    if (path === '/api/admin/v1/tracking/allowed-hosts') {
      return Promise.resolve({ config: { ...off, allowed_hosts: 'https://pixel.corp.example' }, policy: basePolicy, proxy_path: '/momento' })
    }
    if (path === '/api/admin/v1/tracking/violations') {
      return Promise.resolve({ items: [
        { origin: 'https://pixel.corp.example', directive: 'img-src', page: 'https://sso.example/login', count: 12, first_seen: '2026-09-12T01:00:00Z', last_seen: '2026-09-12T01:05:00Z', allowed: false },
        { origin: 'inline', directive: 'script-src-elem', page: 'https://sso.example/login', count: 3, first_seen: '2026-09-12T01:00:00Z', last_seen: '2026-09-12T01:04:00Z', allowed: false },
      ] })
    }
    return Promise.resolve(current)
  })
})

function renderPage() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <TrackingPage />
  </QueryClientProvider>)
}

// The default is off, and the screen has to say so plainly: the switch is
// off, and the policy shown is the narrow one the service ships with.
test('a fresh install shows tracking off and the base policy', async () => {
  renderPage()
  const toggle = await screen.findByLabelText('방문 추적 사용')
  expect(toggle).not.toBeChecked()
  expect(screen.getByText(basePolicy)).toBeInTheDocument()
  expect(screen.queryByText(/unsafe-eval/)).not.toBeInTheDocument()
})

// Turning Momento on through the proxy is the recommended setup, so the form
// has to send exactly that — and say that no external origin is involved.
test('turning Momento on through the proxy saves the configuration', async () => {
  const user = userEvent.setup()
  renderPage()
  await user.click(await screen.findByLabelText('방문 추적 사용'))
  await user.click(screen.getByRole('combobox', { name: '수집 도구' }))
  await user.click(await screen.findByRole('option', { name: 'Momento (사내 수집기)' }))
  await user.type(screen.getByRole('textbox', { name: /Momento 수집기 주소/ }), 'https://momento.corp.example')
  await user.type(screen.getByRole('textbox', { name: /사이트 ID/ }), 'SITE_1')
  expect(screen.getByText(/정책에 외부 출처가 등장하지 않습니다/)).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: '저장' }))

  await vi.waitFor(() => {
    const put = mocks.api.mock.calls.find(([path, init]) => path === '/api/admin/v1/tracking' && (init as RequestInit)?.method === 'PUT')
    expect(put).toBeDefined()
    const sent = JSON.parse(String((put![1] as RequestInit).body))
    expect(sent).toMatchObject({ enabled: true, provider: 'momento', momento_url: 'https://momento.corp.example', momento_site_id: 'SITE_1', momento_proxy: true })
  })
  expect(await screen.findByText(/script-src 'self' 'nonce-/)).toBeInTheDocument()
})

// A pasted snippet over the limit is refused here, before the server has to.
test('a snippet over 8KB cannot be saved', async () => {
  const user = userEvent.setup()
  renderPage()
  await user.click(await screen.findByRole('combobox', { name: '수집 도구' }))
  await user.click(await screen.findByRole('option', { name: '직접 붙여넣기' }))
  const snippet = screen.getByRole('textbox', { name: /추적 코드/ })
  await user.click(snippet)
  await user.paste('<script>' + 'x'.repeat(8 * 1024) + '</script>')
  expect(screen.getByRole('button', { name: '저장' })).toBeDisabled()
})

// What the browser refused is the whole point of the screen: an origin is
// one click from allowed, and an inline script without a nonce is named as
// such rather than offered a button that could not help.
test('a blocked origin is allowed with one click and the inline report is explained', async () => {
  const user = userEvent.setup()
  renderPage()
  expect(await screen.findByText('https://pixel.corp.example')).toBeInTheDocument()
  expect(screen.getByText(/nonce 없는 인라인 코드/)).toBeInTheDocument()
  expect(screen.getAllByRole('button', { name: '허용' })).toHaveLength(1)
  await user.click(screen.getByRole('button', { name: '허용' }))
  await vi.waitFor(() => {
    const post = mocks.api.mock.calls.find(([path]) => path === '/api/admin/v1/tracking/allowed-hosts')
    expect(post).toBeDefined()
    expect(JSON.parse(String((post![1] as RequestInit).body))).toEqual({ origin: 'https://pixel.corp.example' })
  })
  // The allow list in the form follows, so a later save keeps it.
  expect(await screen.findByDisplayValue('https://pixel.corp.example')).toBeInTheDocument()
})
