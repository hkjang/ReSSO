import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { expect, test, vi } from 'vitest'
import { LoginPage } from './LoginPage'

vi.mock('../lib/auth', () => ({
  useAuth: () => ({
    meta: { product: 'ReSSO', version: 'v9.9.9-test', commit: 'test', build_time: 'now', go_version: 'go-test' },
    refresh: vi.fn(),
  }),
}))

function renderLogin() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={['/login']}><LoginPage /></MemoryRouter></QueryClientProvider>)
}

test('login form remains usable and exposes the service version', async () => {
  const user = userEvent.setup()
  renderLogin()
  const username = screen.getByRole('textbox', { name: '아이디' })
  const password = screen.getByLabelText(/비밀번호/, { selector: 'input' })
  await user.type(username, 'admin')
  await user.type(password, 'correct horse battery staple')
  expect(username).toHaveValue('admin')
  expect(password).toHaveValue('correct horse battery staple')
  expect(screen.getByText('v9.9.9-test')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: /로그인/ })).toBeEnabled()
})
