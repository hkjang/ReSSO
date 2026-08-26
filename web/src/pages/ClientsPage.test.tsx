import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { beforeEach, expect, test, vi } from 'vitest'
import { ClientsPage } from './ClientsPage'
import { ToastProvider } from '../components/Toast'

const mocks = vi.hoisted(() => ({ api: vi.fn() }))

vi.mock('../lib/realms', () => ({
  useRealms: () => ({ isLoading: false, error: null, data: { items: [{ id: 'realm-1', name: 'master', display_name: 'Master' }] } }),
  useRealmSelection: () => ({ realmID: 'realm-1', setRealmID: vi.fn() }),
}))

vi.mock('../lib/api', () => ({
  api: (...args: unknown[]) => mocks.api(...args),
  jsonBody: (value: unknown) => ({ body: JSON.stringify(value) }),
}))

const client = (clientID: string, name: string) => ({
  id: `id-${clientID}`, realm_id: 'realm-1', client_id: clientID, name, type: 'public',
  redirect_uris: [], post_logout_redirect_uris: [], web_origins: [],
  grant_types: ['authorization_code'], default_scopes: ['openid'], require_pkce: true,
  backchannel_logout_uri: '', created_at: '2026-08-21T00:00:00Z', updated_at: '2026-08-21T00:00:00Z',
})

beforeEach(() => {
  mocks.api.mockReset()
  mocks.api.mockImplementation((path: string) => {
    if (path.includes('/clients')) {
      return Promise.resolve({ items: [client('billing-web', 'Billing'), client('payroll-api', 'Payroll')] })
    }
    return Promise.resolve({ items: [] })
  })
})

function renderAt(entry: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  function HandOver() {
    const navigate = useNavigate()
    return <button onClick={() => navigate('/admin/clients?q=payroll-api')}>hand over payroll</button>
  }
  function Address() {
    return <div data-testid="address">{useLocation().search}</div>
  }
  return render(<QueryClientProvider client={queryClient}><ToastProvider>
    <MemoryRouter initialEntries={[entry]}>
      <HandOver />
      <Address />
      <Routes><Route path="/admin/clients" element={<ClientsPage />} /></Routes>
    </MemoryRouter>
  </ToastProvider></QueryClientProvider>)
}

test('the term the palette hands over filters the list it opens', async () => {
  renderAt('/admin/clients?q=billing-web')
  expect(await screen.findByText('billing-web')).toBeInTheDocument()
  expect(screen.queryByText('payroll-api')).not.toBeInTheDocument()
})

// The palette opens over this screen too, and landing on the route the browser
// is already on remounts nothing. A term read once at mount is applied to the
// first hand-over only: the second leaves the list filtered by the first while
// the address bar names the second.
test('a second hand-over refilters the list already open', async () => {
  const user = userEvent.setup()
  renderAt('/admin/clients?q=billing-web')
  expect(await screen.findByText('billing-web')).toBeInTheDocument()

  await user.click(screen.getByRole('button', { name: 'hand over payroll' }))

  expect(await screen.findByText('payroll-api')).toBeInTheDocument()
  expect(screen.queryByText('billing-web')).not.toBeInTheDocument()
})

// Typing puts the term in the URL too, which is what closes the last gap in the
// hand-over: type over the term you arrived with and the address bar follows,
// so being handed that same term again is a change the list acts on. While the
// URL only ever held what the palette put there, this case looked like no
// change at all and left what was typed in place.
test('a hand-over of the term already typed over still refilters', async () => {
  const user = userEvent.setup()
  renderAt('/admin/clients?q=payroll-api')
  expect(await screen.findByText('payroll-api')).toBeInTheDocument()

  const field = screen.getByPlaceholderText('Client ID, 이름 검색')
  await user.clear(field)
  await user.paste('billing')
  expect(await screen.findByText('billing-web')).toBeInTheDocument()
  // The typed term reaches the address bar, which is what makes the filtered
  // list something to link to — and what makes the hand-over below a change.
  await vi.waitFor(() => expect(screen.getByTestId('address')).toHaveTextContent('?q=billing'))

  await user.click(screen.getByRole('button', { name: 'hand over payroll' }))

  expect(await screen.findByText('payroll-api')).toBeInTheDocument()
  expect(screen.queryByText('billing-web')).not.toBeInTheDocument()
})
