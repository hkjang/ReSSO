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
  // Pasted rather than typed a character at a time. The property under test is
  // that a long value is accepted and kept, not that a hundred keystrokes each
  // re-render: typing them took fifteen seconds on a loaded runner, which is
  // this suite's own timeout, and pasting is what anyone does with a connection
  // URL or a DN anyway.
  const fill = async (field: HTMLElement, value: string) => {
    await user.clear(field)
    await user.click(field)
    await user.paste(value)
  }
  await fill(connectionURL, 'ldaps://directory.internal.company:636')
  await fill(credential, 'correct horse battery staple')
  await fill(usersDN, 'ou=People,dc=internal,dc=company')

  expect(connectionURL).toHaveValue('ldaps://directory.internal.company:636')
  expect(credential).toHaveValue('correct horse battery staple')
  expect(usersDN).toHaveValue('ou=People,dc=internal,dc=company')
  expect(screen.getByRole('button', { name: '공급자 생성' })).toBeEnabled()
  // The body runs in well under a second now. The margin is for a loaded
  // runner: this file renders the largest form in the console, and CPU
  // starvation stretches it past the five-second default without anything
  // being wrong with it.
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
  last_sync_unknown_roles: [] as string[],
  last_sync_group_memberships: 4,
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

// A mapping naming a Role this Realm does not have grants nothing, and the run
// still ends in SUCCESS — so it never appears in the error line. Without this
// the rule sits in the configuration forever and the people in that group
// quietly go without.
test('a group mapping that resolves to nothing is called out, not left to the error line', async () => {
  const user = userEvent.setup()
  const { api } = await import('../lib/api')
  vi.mocked(api).mockResolvedValue({ items: [{ ...provider, last_sync_unknown_roles: ['warehosue'] }] })
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={queryClient}><MemoryRouter><UserFederationPage /></MemoryRouter></QueryClientProvider>)

  await user.click(await screen.findByText('corp'))

  expect(await screen.findByText(/warehosue/)).toBeInTheDocument()
  expect(screen.getByText(/오류로 표시되지 않습니다/)).toBeInTheDocument()
})

test('a configuration whose mappings all resolve says nothing about them', async () => {
  const user = userEvent.setup()
  const { api } = await import('../lib/api')
  vi.mocked(api).mockResolvedValue({ items: [provider] })
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={queryClient}><MemoryRouter><UserFederationPage /></MemoryRouter></QueryClientProvider>)

  await user.click(await screen.findByText('corp'))

  expect(await screen.findByText(/비활성화 3/)).toBeInTheDocument()
  expect(screen.queryByText(/Role이 이 Realm에 없습니다/)).not.toBeInTheDocument()
})

// A mapping can name a Role this Realm really has and still grant nothing,
// because the directory returned no group membership at all — the attribute is
// named wrong, or the overlay producing it is off, which is the default in
// OpenLDAP. The run succeeds either way, so the screen has to tell the two
// apart rather than leave an administrator checking the Role names again.
test('mappings with nothing to match against are distinguished from wrong ones', async () => {
  const user = userEvent.setup()
  const { api } = await import('../lib/api')
  vi.mocked(api).mockResolvedValue({ items: [{
    ...provider,
    group_role_mappings: { 'cn=warehouse,ou=groups,dc=example,dc=test': 'warehouse' },
    last_sync_group_memberships: 0,
  }] })
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={queryClient}><MemoryRouter><UserFederationPage /></MemoryRouter></QueryClientProvider>)

  await user.click(await screen.findByText('corp'))

  expect(await screen.findByText(/그룹 소속을 가진 사용자가 한 명도 없었습니다/)).toBeInTheDocument()
  expect(screen.getByText(/overlay가 켜져 있는지/)).toBeInTheDocument()
})

test('a run that saw memberships says nothing about them', async () => {
  const user = userEvent.setup()
  const { api } = await import('../lib/api')
  vi.mocked(api).mockResolvedValue({ items: [{
    ...provider,
    group_role_mappings: { 'cn=warehouse,ou=groups,dc=example,dc=test': 'warehouse' },
  }] })
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={queryClient}><MemoryRouter><UserFederationPage /></MemoryRouter></QueryClientProvider>)

  await user.click(await screen.findByText('corp'))

  expect(await screen.findByText(/비활성화 3/)).toBeInTheDocument()
  expect(screen.queryByText(/그룹 소속을 가진 사용자가/)).not.toBeInTheDocument()
})
