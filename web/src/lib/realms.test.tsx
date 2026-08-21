import { QueryClientProvider, QueryClient } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { expect, test, vi } from 'vitest'
import { useRealmSelection } from './realms'
import type { Realm } from '../types'

vi.mock('./api', () => ({ api: vi.fn() }))

const realms = [
  { id: 'id-master', name: 'master', display_name: 'Master' },
  { id: 'id-partners', name: 'partners', display_name: 'Partners' },
] as Realm[]

function Probe() {
  const selection = useRealmSelection(realms)
  const location = useLocation()
  return (
    <div>
      <span data-testid="realm-id">{selection.realmID}</span>
      <span data-testid="search">{location.search}</span>
      <button onClick={() => selection.setRealmID('id-partners')}>partners로 전환</button>
    </div>
  )
}

function renderProbe(initialEntry: string) {
  localStorage.clear()
  const queryClient = new QueryClient()
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]}><Probe /></MemoryRouter>
    </QueryClientProvider>,
  )
}

test('a shared link opens the Realm it names', async () => {
  renderProbe('/admin/users?realm=partners')
  expect(await screen.findByTestId('realm-id')).toHaveTextContent('id-partners')
})

test('the Realm is written back into the URL so the screen can be shared', async () => {
  renderProbe('/admin/users')
  // With no parameter the first Realm is selected and the URL is corrected,
  // which is what previously made these pages impossible to link to.
  expect(await screen.findByTestId('search')).toHaveTextContent('realm=master')
  expect(screen.getByTestId('realm-id')).toHaveTextContent('id-master')
})

test('switching Realm updates the URL and is remembered for the next visit', async () => {
  const user = userEvent.setup()
  renderProbe('/admin/users')
  await user.click(screen.getByRole('button', { name: 'partners로 전환' }))
  expect(await screen.findByTestId('search')).toHaveTextContent('realm=partners')
  expect(localStorage.getItem('resso.admin.realm')).toBe('id-partners')
})

test('an unknown Realm name falls back instead of leaving the page blank', async () => {
  renderProbe('/admin/users?realm=does-not-exist')
  expect(await screen.findByTestId('realm-id')).toHaveTextContent('id-master')
})
