// @vitest-environment node
import { expect, test } from 'vitest'
import { sortRows } from './sort'

const rows = [
  { name: '나나', count: 3 },
  { name: '가가', count: 10 },
  { name: '다다', count: 1 },
]

test('orders text with Korean collation rather than code points', () => {
  expect(sortRows(rows, false, (row) => row.name).map((row) => row.name)).toEqual(['가가', '나나', '다다'])
  expect(sortRows(rows, true, (row) => row.name).map((row) => row.name)).toEqual(['다다', '나나', '가가'])
})

test('orders numbers numerically, not as strings', () => {
  // A string comparison would place 10 before 3.
  expect(sortRows(rows, false, (row) => row.count).map((row) => row.count)).toEqual([1, 3, 10])
  expect(sortRows(rows, true, (row) => row.count).map((row) => row.count)).toEqual([10, 3, 1])
})

test('missing values sort last in both directions', () => {
  const withGaps = [{ v: 'b' }, { v: undefined }, { v: '' }, { v: 'a' }]
  expect(sortRows(withGaps, false, (row) => row.v).map((row) => row.v ?? '·')).toEqual(['a', 'b', '·', ''])
  const descending = sortRows(withGaps, true, (row) => row.v).map((row) => row.v ?? '·')
  expect(descending.slice(0, 2)).toEqual(['b', 'a'])
})

test('the input array is not mutated', () => {
  const original = [...rows]
  sortRows(rows, true, (row) => row.name)
  expect(rows).toEqual(original)
})
