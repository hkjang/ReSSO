import { TableCell, TableSortLabel } from '@mui/material'
import type { TableCellProps } from '@mui/material'
import type { SortState } from '../lib/sort'

/**
 * A column header that can order the table.
 *
 * Every list was fixed to one ordering, so questions like "which accounts have
 * the oldest passwords" or "which client was registered last" could only be
 * answered by reading the whole page. TableSortLabel also gives the header the
 * aria-sort state a screen reader needs.
 */
export function SortableCell<K extends string>({ column, sort, onSort, children, align }: {
  column: K
  sort: SortState<K>
  onSort: (next: SortState<K>) => void
  children: React.ReactNode
  align?: TableCellProps['align']
}) {
  const active = sort.column === column
  return (
    <TableCell align={align} sortDirection={active ? (sort.descending ? 'desc' : 'asc') : false}>
      <TableSortLabel
        active={active}
        direction={active && sort.descending ? 'desc' : 'asc'}
        // Selecting the active column flips it; selecting another starts
        // ascending, which is what a first click on a name column should do.
        onClick={() => onSort({ column, descending: active ? !sort.descending : false })}
      >
        {children}
      </TableSortLabel>
    </TableCell>
  )
}
