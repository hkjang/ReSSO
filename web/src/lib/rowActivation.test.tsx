import { Table, TableBody, TableCell, TableRow } from '@mui/material'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { rowActivation } from './rowActivation'

function renderRow(onActivate: () => void) {
  return render(
    <Table><TableBody>
      <TableRow {...rowActivation(onActivate)}>
        <TableCell>행</TableCell>
        <TableCell><button type="button">내부 버튼</button></TableCell>
      </TableRow>
    </TableBody></Table>,
  )
}

test('a row opens from the keyboard, not only with a pointer', async () => {
  const user = userEvent.setup()
  const onActivate = vi.fn()
  renderRow(onActivate)

  // Tabbing must reach the row at all: it used to be pointer-only.
  await user.tab()
  const row = screen.getByRole('row')
  expect(row).toHaveFocus()

  await user.keyboard('{Enter}')
  expect(onActivate).toHaveBeenCalledTimes(1)
  await user.keyboard(' ')
  expect(onActivate).toHaveBeenCalledTimes(2)
})

test('a key press inside the row does not also open it', async () => {
  const user = userEvent.setup()
  const onActivate = vi.fn()
  renderRow(onActivate)

  await user.click(screen.getByRole('button', { name: '내부 버튼' }))
  await user.keyboard(' ')
  // Space on a control inside the row belongs to that control.
  expect(onActivate).not.toHaveBeenCalled()
})

test('clicking still opens the row', async () => {
  const user = userEvent.setup()
  const onActivate = vi.fn()
  renderRow(onActivate)
  await user.click(screen.getByText('행'))
  expect(onActivate).toHaveBeenCalledTimes(1)
})
