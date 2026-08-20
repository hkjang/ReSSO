import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { expect, test, vi } from 'vitest'
import { UserFederationPage } from './UserFederationPage'

vi.mock('../lib/realms', () => ({
  useRealms: () => ({ isLoading: false, error: null, data: { items: [{ id: 'realm-1', name: 'master', display_name: 'Master' }] } }),
  useRealmSelection: () => ({ realmID: 'realm-1', setRealmID: vi.fn() }),
}))

vi.mock('../lib/api', () => ({
  api: vi.fn().mockResolvedValue({ items: [] }),
  jsonBody: (value: unknown) => ({ body: JSON.stringify(value) }),
}))

test('LDAP federation form keeps long connection inputs usable', async () => {
  const user = userEvent.setup()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={queryClient}><MemoryRouter><UserFederationPage /></MemoryRouter></QueryClientProvider>)

  await user.click(screen.getByRole('button', { name: 'LDAP 공급자 추가' }))
  const connectionURL = await screen.findByLabelText(/Connection URL/)
  const credential = await screen.findByLabelText(/Bind Credential/)
  const usersDN = await screen.findByLabelText(/Users DN/)
  await user.clear(connectionURL)
  await user.type(connectionURL, 'ldaps://directory.internal.company:636')
  await user.type(credential, 'correct horse battery staple')
  await user.clear(usersDN)
  await user.type(usersDN, 'ou=People,dc=internal,dc=company')

  expect(connectionURL).toHaveValue('ldaps://directory.internal.company:636')
  expect(credential).toHaveValue('correct horse battery staple')
  expect(usersDN).toHaveValue('ou=People,dc=internal,dc=company')
  expect(screen.getByRole('button', { name: '공급자 생성' })).toBeEnabled()
}, 15_000)
