import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { AuthProvider } from './auth'
import { useAuth } from './auth-context'
import { api } from './api'

const me = {
  user: { id: 'u1', realm_id: 'r1', username: 'admin', email: '', email_verified: false, display_name: 'Admin', enabled: true, platform_admin: true, failed_attempts: 0, password_changed_at: '', created_at: '', updated_at: '' },
  roles: [],
  csrf_token: 'csrf',
  permissions: { platform_admin: true, realm_admin: false, admin: true },
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function Probe() {
  const { authenticated, sessionExpired, logout } = useAuth()
  return (
    <div>
      <span data-testid="authenticated">{String(authenticated)}</span>
      <span data-testid="expired">{String(sessionExpired)}</span>
      <button onClick={() => void logout()}>로그아웃</button>
      <button onClick={() => { void api('/api/admin/v1/realms').catch(() => undefined) }}>관리 요청</button>
    </div>
  )
}

function renderAuth() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}><AuthProvider><Probe /></AuthProvider></QueryClientProvider>)
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input)
    if (path.startsWith('/api/v1/meta')) return jsonResponse({ product: 'ReSSO', version: 'test' })
    if (path.startsWith('/api/v1/me')) return jsonResponse(me)
    return jsonResponse({}, 200)
  }))
})

afterEach(() => vi.unstubAllGlobals())

test('a rejected request while signed in ends the session and explains why', async () => {
  const user = userEvent.setup()
  renderAuth()
  await waitFor(() => expect(screen.getByTestId('authenticated')).toHaveTextContent('true'))

  // The server now rejects everything: the console used to keep rendering the
  // signed-in shell and fail inline on every panel.
  vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({ error: 'authentication_required' }, 401)))
  await user.click(screen.getByRole('button', { name: '관리 요청' }))

  await waitFor(() => expect(screen.getByTestId('authenticated')).toHaveTextContent('false'))
  expect(screen.getByTestId('expired')).toHaveTextContent('true')
})

test('signing out deliberately is not reported as an expiry', async () => {
  const user = userEvent.setup()
  renderAuth()
  await waitFor(() => expect(screen.getByTestId('authenticated')).toHaveTextContent('true'))

  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).includes('/auth/logout')) return new Response(null, { status: 204 })
    return jsonResponse({ error: 'authentication_required' }, 401)
  }))
  await user.click(screen.getByRole('button', { name: '로그아웃' }))

  await waitFor(() => expect(screen.getByTestId('authenticated')).toHaveTextContent('false'))
  expect(screen.getByTestId('expired')).toHaveTextContent('false')
})

test('a 401 before signing in is not an expiry', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).startsWith('/api/v1/meta')) return jsonResponse({ product: 'ReSSO', version: 'test' })
    return jsonResponse({ error: 'authentication_required' }, 401)
  }))
  renderAuth()
  await waitFor(() => expect(screen.getByTestId('authenticated')).toHaveTextContent('false'))
  // Someone who never signed in must not be told their session expired.
  expect(screen.getByTestId('expired')).toHaveTextContent('false')
})
