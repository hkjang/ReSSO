export interface SortState<K extends string> {
  column: K
  descending: boolean
}

/** Order a fully loaded list in place. Undefined and empty values sort last. */
export function sortRows<T>(rows: T[], descending: boolean, key: (row: T) => string | number | undefined): T[] {
  return [...rows].sort((left, right) => {
    const a = key(left)
    const b = key(right)
    if (a === undefined || a === '') return b === undefined || b === '' ? 0 : 1
    if (b === undefined || b === '') return -1
    const compared = typeof a === 'number' && typeof b === 'number'
      ? a - b
      : String(a).localeCompare(String(b), 'ko')
    return descending ? -compared : compared
  })
}
