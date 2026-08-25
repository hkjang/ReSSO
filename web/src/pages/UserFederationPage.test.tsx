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

const provider = {
  id: 'fed-1', realm_id: 'realm-1', name: 'corp', vendor: 'OTHER',
  connection_url: 'ldap://ldap.example.test', bind_dn: 'cn=admin,dc=example,dc=test',
  users_dn: 'ou=people,dc=example,dc=test', username_ldap_attribute: 'uid',
  rdn_ldap_attribute: 'uid', uuid_ldap_attribute: 'entryUUID',
  user_object_classes: ['inetOrgPerson'], user_ldap_filter: '', search_scope: 'SUBTREE',
  email_ldap_attribute: 'mail', first_name_ldap_attribute: '', last_name_ldap_attribute: '',
  display_name_ldap_attribute: 'cn', member_of_ldap_attribute: '', group_role_mappings: {},
  import_enabled: true, sync_registrations: false, missing_user_action: 'DISABLE',
  edit_mode: 'READ_ONLY', batch_size: 100, sync_period_seconds: 0, enabled: true,
  last_sync_at: '2026-08-25T00:00:00Z', last_sync_status: 'SUCCESS', last_sync_error: '',
  last_sync_added: 2, last_sync_updated: 1, last_sync_failed: 0, last_sync_disabled: 3,
  sync_running: false, created_at: '2026-08-01T00:00:00Z', updated_at: '2026-08-25T00:00:00Z',
}

// Under the DISABLE policy a sync deactivates the accounts that left the
// directory and ends their sessions. That is the consequential outcome of a
// run, and the screen an administrator is sent to afterwards listed added,
// updated and failed — everything except the one that logged people out.
test('the sync outcome says how many accounts it disabled', async () => {
  const user = userEvent.setup()
  const { api } = await import('../lib/api')
  vi.mocked(api).mockResolvedValue({ items: [provider] })
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={queryClient}><MemoryRouter><UserFederationPage /></MemoryRouter></QueryClientProvider>)

  await user.click(await screen.findByText('corp'))

  // The whole line, so the counts stay in one place and in this order.
  expect(await screen.findByText(/추가 2 · 갱신 1 · 실패 0 · 비활성화 3/)).toBeInTheDocument()
})
